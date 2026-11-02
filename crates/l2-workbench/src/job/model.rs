use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::recovery_transition::{
    FunnelOmissionReason, MAX_FUNNEL_COHORTS, RecoveryCandidateSample, RecoveryFunnelEvent,
    RecoveryFunnelIdentity, RecoveryFunnelRegistration, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionStage, RecoveryTransitionSummary,
    cohort_capacity_charge,
};
use super::{MemoryBudget, MemoryClass, MemoryError, MemoryLease, MemorySnapshot};

#[path = "work.rs"]
mod work;

pub use work::WorkSnapshot;
use work::{WorkLedger, WorkOwner};

use super::cache_fallback::{
    CacheFallbackKind, CacheFallbackSummary, CacheStage, bounded_escaped_sample,
};

// Short samples swing too much to support a useful ETA
const MINIMUM_ETA_SAMPLE_MS: u64 = 1_000;

/// One named stage in the recovery pipeline
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Input checks and recovery setup
    Preparation,
    /// Input bytes and metadata are loaded
    Ingestion,
    /// Protocol and packet reconstruction runs
    Reconstruction,
    /// Native file formats are extracted
    NativeExtraction,
    /// Framing and record candidates are discovered
    FramingRecordDiscovery,
    /// Candidate transformations are discovered
    TransformDiscovery,
    /// Candidate results are assembled and validated
    AssemblyValidation,
    /// Validated containers are expanded
    Expansion,
    /// Reports are generated
    Reports,
    /// Results are committed to their destination
    Publication,
}

impl Phase {
    const ALL: [Self; 10] = [
        Self::Preparation,
        Self::Ingestion,
        Self::Reconstruction,
        Self::NativeExtraction,
        Self::FramingRecordDiscovery,
        Self::TransformDiscovery,
        Self::AssemblyValidation,
        Self::Expansion,
        Self::Reports,
        Self::Publication,
    ];

    /// Returns the short display name used by text renderers
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::Ingestion => "ingestion",
            Self::Reconstruction => "reconstruction",
            Self::NativeExtraction => "native extraction",
            Self::FramingRecordDiscovery => "framing and record discovery",
            Self::TransformDiscovery => "transform discovery",
            Self::AssemblyValidation => "assembly and validation",
            Self::Expansion => "expansion",
            Self::Reports => "reports",
            Self::Publication => "publication",
        }
    }
}

/// A measurable quantity collected while recovery runs
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum Counter {
    /// Input files examined
    Files,
    /// Bytes read or written
    Bytes,
    /// Source and manifest bytes actually returned by reads during this invocation
    SourceReadBytes,
    /// Source read bytes observed in earlier invocations of the restored job
    PriorSourceReadBytes,
    /// Packet records indexed during a fresh capture ingestion
    ///
    /// Reusing a cached index does not add packet work
    Packets,
    /// Flows reconstructed
    Flows,
    /// Cohorts grouped
    Cohorts,
    /// Candidate work items examined
    CandidatesExamined,
    /// Candidate work items rejected
    CandidatesRejected,
    /// Validated artifact objects committed by one Case recovery or source-analysis pass
    ///
    /// Objects are unique within that pass; separate passes may count the same bytes again
    ValidatedArtifacts,
    /// Archive member entries retained by one Case recovery or source-analysis pass
    ///
    /// Different entries count separately even when they contain the same bytes
    ExpandedMembers,
    /// Results reused from the persistent cache
    CacheHits,
    /// Results computed without a persistent cache entry
    CacheMisses,
    /// Strictly parsed records in committed record assemblies
    ///
    /// Failed or rolled-back assemblies do not add record work
    Records,
    /// Record input applications recorded by committed strict-parser receipts
    ///
    /// The same frame can count more than once when different schemas are tried
    RecordInputApplications,
    /// Transformations discovered
    Transforms,
    /// Reports written
    Reports,
}

impl Counter {
    const ALL: [Self; 17] = [
        Self::Files,
        Self::Bytes,
        Self::SourceReadBytes,
        Self::PriorSourceReadBytes,
        Self::Packets,
        Self::Flows,
        Self::Cohorts,
        Self::CandidatesExamined,
        Self::CandidatesRejected,
        Self::ValidatedArtifacts,
        Self::ExpandedMembers,
        Self::CacheHits,
        Self::CacheMisses,
        Self::Records,
        Self::RecordInputApplications,
        Self::Transforms,
        Self::Reports,
    ];

    /// Returns the short display name used by text renderers
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Bytes => "bytes",
            Self::SourceReadBytes => "source read bytes",
            Self::PriorSourceReadBytes => "prior source read bytes",
            Self::Packets => "packets",
            Self::Flows => "flows",
            Self::Cohorts => "cohorts",
            Self::CandidatesExamined => "candidates examined",
            Self::CandidatesRejected => "candidates rejected",
            Self::ValidatedArtifacts => "validated artifacts",
            Self::ExpandedMembers => "expanded members",
            Self::CacheHits => "cache hits",
            Self::CacheMisses => "cache misses",
            Self::Records => "records",
            Self::RecordInputApplications => "record input applications",
            Self::Transforms => "transforms",
            Self::Reports => "reports",
        }
    }
}

/// The current disposition of one recovery stage
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PhaseState {
    /// Stage has not started
    Pending,
    /// Stage is still processing work
    InProgress,
    /// Stage finished successfully
    Completed,
    /// Stage stopped after an error
    Failed,
    /// Stage stopped after a cancellation request
    Cancelled,
    /// Stage was intentionally omitted
    Skipped,
}

/// The outcome recorded when a stage stops running
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    /// Stage finished successfully
    Completed,
    /// Stage stopped after an error
    Failed,
    /// Stage stopped after a cancellation request
    Cancelled,
    /// Stage was intentionally omitted
    Skipped,
}

/// Serializable measurements for one recovery stage
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PhaseSnapshot {
    /// Stage represented by this entry
    pub phase: Phase,
    /// Current state of the stage
    pub state: PhaseState,
    /// Work items observed so far
    pub completed: u64,
    /// Known work item count, absent while discovery is open-ended
    pub total: Option<u64>,
    /// Most recent detail for the active stage
    pub message: Option<String>,
    /// Time spent in the stage, in milliseconds
    pub elapsed_ms: u64,
    /// Bounded progress as a whole percentage when the total is known
    pub progress_percent: Option<u8>,
    /// Measured work rate in units per second
    pub rate_per_second: Option<u64>,
    /// Estimated remaining time for bounded work after one second of measurement
    pub eta_seconds: Option<u64>,
}

impl PhaseSnapshot {
    const fn pending(phase: Phase) -> Self {
        Self {
            phase,
            state: PhaseState::Pending,
            completed: 0,
            total: None,
            message: None,
            elapsed_ms: 0,
            progress_percent: None,
            rate_per_second: None,
            eta_seconds: None,
        }
    }

    fn refresh_measurements(&mut self) {
        self.progress_percent = self.progress_percent();
        self.rate_per_second = self.rate_per_second();
        self.eta_seconds = self.eta_seconds();
    }

    fn progress_percent(&self) -> Option<u8> {
        let total = self.total?;
        if total == 0 {
            return Some(u8::from(self.state == PhaseState::Completed) * 100);
        }

        // Clamp the displayed percentage while preserving the exact observed count
        let completed = self.completed.min(total);
        let percent = u128::from(completed) * 100 / u128::from(total);
        Some(u8::try_from(percent).unwrap_or(100))
    }

    fn rate_per_second(&self) -> Option<u64> {
        if self.completed == 0 || self.elapsed_ms == 0 {
            return None;
        }

        // Use a wider intermediate so large jobs do not overflow during unit conversion
        let rate = u128::from(self.completed) * 1_000 / u128::from(self.elapsed_ms);
        Some(u64::try_from(rate).unwrap_or(u64::MAX))
    }

    fn eta_seconds(&self) -> Option<u64> {
        if self.state != PhaseState::InProgress {
            return None;
        }
        let total = self.total?;
        let remaining = total.saturating_sub(self.completed);

        // An ETA needs remaining work and a full second of measured progress
        if remaining == 0 || self.completed == 0 || self.elapsed_ms < MINIMUM_ETA_SAMPLE_MS {
            return None;
        }

        // Keep fractional units per second in the estimate instead of rounding the rate down
        let numerator = u128::from(remaining) * u128::from(self.elapsed_ms);
        let denominator = u128::from(self.completed) * 1_000;
        let eta = numerator.div_ceil(denominator);
        Some(u64::try_from(eta).unwrap_or(u64::MAX))
    }
}

/// Serializable view of all progress and counters for one job
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct JobSnapshot {
    /// Human-readable description of the work
    pub label: String,
    /// Wall-clock creation time as milliseconds since the Unix epoch
    pub created_at_unix_ms: u64,
    /// Monotonic elapsed job time in milliseconds
    pub elapsed_ms: u64,
    /// Most recently started stage
    pub current_phase: Option<Phase>,
    /// Ordered stage measurements
    pub phases: Vec<PhaseSnapshot>,
    /// Cumulative measurements collected by workers
    pub counters: BTreeMap<Counter, u64>,
    /// Bounded reasons cache-backed work continued without reusing an entry
    #[serde(default)]
    pub cache_fallbacks: CacheFallbackSummary,
    /// Bounded stage and outcome counts for observed recovery transitions
    #[serde(default)]
    pub recovery_transitions: RecoveryTransitionSummary,
    /// Current invocation's explicitly charged memory, excluding allocator overhead and RSS
    ///
    /// Serialized observations are never restored as live allocation state
    #[serde(default, skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub memory_admission: Option<MemorySnapshot>,
    /// Whether a cooperative cancellation request has been sent
    pub cancel_requested: bool,
}

impl JobSnapshot {
    fn snapshot_copy(&self, cohort_limit: usize, memory_limit: usize) -> Self {
        Self {
            label: self.label.clone(),
            created_at_unix_ms: self.created_at_unix_ms,
            elapsed_ms: self.elapsed_ms,
            current_phase: self.current_phase,
            phases: self.phases.clone(),
            counters: self.counters.clone(),
            cache_fallbacks: self.cache_fallbacks.clone(),
            recovery_transitions: self
                .recovery_transitions
                .snapshot_copy(cohort_limit, memory_limit),
            memory_admission: self.memory_admission,
            cancel_requested: self.cancel_requested,
        }
    }

    /// Check the phase topology and progress values required for a saved job snapshot
    #[must_use]
    pub fn is_valid_checkpoint(&self) -> bool {
        // Restoration needs exactly one entry for every known phase
        self.phases.len() == Phase::ALL.len()
            && Phase::ALL.iter().all(|phase| {
                self.phases
                    .iter()
                    .filter(|entry| entry.phase == *phase)
                    .count()
                    == 1
            })
            && self
                .phases
                .iter()
                .all(|phase| phase.progress_percent.is_none_or(|percent| percent <= 100))
    }

    /// Finds the recorded measurements for one stage
    #[must_use]
    pub fn phase(&self, phase: Phase) -> Option<&PhaseSnapshot> {
        self.phases.iter().find(|snapshot| snapshot.phase == phase)
    }
}

/// A cloneable handle to shared progress and cooperative cancellation state
#[derive(Clone, Debug)]
pub struct Job {
    inner: Arc<Inner>,
    work: Option<Arc<WorkOwner>>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    cancel_requested: AtomicBool,
    memory: Option<MemoryBudget>,
}

#[derive(Debug)]
struct State {
    snapshot: JobSnapshot,
    created_at: Instant,
    elapsed_base_ms: u64,
    phase_started_at: BTreeMap<Phase, Instant>,
    work: WorkLedger,
    funnel_memory: Option<MemoryLease>,
}

impl State {
    fn funnel_cohort_count(&self) -> usize {
        self.snapshot
            .recovery_transitions
            .funnel_cohort_count()
            .saturating_add(self.work.funnel_cohort_count(None))
    }

    fn ensure_funnel_slots(&mut self, memory: Option<&MemoryBudget>, requested: usize) -> usize {
        let requested = requested.min(MAX_FUNNEL_COHORTS);
        let Some(memory) = memory else {
            return requested;
        };
        let Ok(per_cohort) = u64::try_from(cohort_capacity_charge()) else {
            return 0;
        };
        let Some(bytes) = u64::try_from(requested)
            .ok()
            .and_then(|count| count.checked_mul(per_cohort))
        else {
            return 0;
        };
        if let Some(lease) = &mut self.funnel_memory {
            if lease.bytes() >= bytes || lease.try_resize(bytes).is_ok() {
                return requested;
            }
            return usize::try_from(lease.bytes() / per_cohort).unwrap_or(MAX_FUNNEL_COHORTS);
        }
        if requested == 0 {
            return 0;
        }
        match memory.try_reserve(MemoryClass::Executor, bytes) {
            Ok(lease) => {
                self.funnel_memory = Some(lease);
                requested
            }
            Err(_) => 0,
        }
    }

    fn release_funnel_slots(&mut self) {
        let desired = self.funnel_cohort_count();
        let Some(lease) = &mut self.funnel_memory else {
            return;
        };
        let Some(bytes) = u64::try_from(cohort_capacity_charge())
            .ok()
            .and_then(|unit| {
                u64::try_from(desired)
                    .ok()
                    .and_then(|count| count.checked_mul(unit))
            })
        else {
            return;
        };
        if bytes < lease.bytes() {
            let _ = lease.try_resize(bytes);
        }
    }
}

/// Errors returned when a progress update cannot be applied
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JobError {
    /// The shared memory observer could not read its live admission state
    Memory(MemoryError),
    /// Shared job state was poisoned by a panicking worker
    LockPoisoned,
    /// Requested phase has already started or finished
    PhaseAlreadyStarted(Phase),
    /// Requested phase is not currently running
    PhaseNotInProgress(Phase),
    /// A cumulative counter would overflow its stored value
    CounterOverflow(Counter),
    /// A phase work count would overflow its stored value
    PhaseOverflow(Phase),
    /// Checkpoint preparation conflicts with other pipeline or scoped work
    RestoreAfterStart,
    /// Saved phase topology or progress cannot form a valid checkpoint
    InvalidCheckpoint,
    /// A work scope must have a lowercase SHA-256 identity
    InvalidWorkIdentity,
    /// The same work identity is already owned by an active handle
    WorkAlreadyActive,
    /// The operation requires a scoped work handle
    WorkScopeRequired,
    /// A saved contribution has a different identity or an unsupported format
    InvalidWorkSnapshot,
    /// Cooperative cancellation was requested
    Cancelled,
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => write!(formatter, "job memory observation failed: {error}"),
            Self::LockPoisoned => formatter.write_str("job state lock is poisoned"),
            Self::PhaseAlreadyStarted(phase) => {
                write!(formatter, "{} phase has already started", phase.label())
            }
            Self::PhaseNotInProgress(phase) => {
                write!(formatter, "{} phase is not in progress", phase.label())
            }
            Self::CounterOverflow(counter) => {
                write!(formatter, "{} counter overflowed", counter.label())
            }
            Self::PhaseOverflow(phase) => {
                write!(formatter, "{} phase count overflowed", phase.label())
            }
            Self::RestoreAfterStart => formatter
                .write_str("job checkpoint cannot be prepared after other live work started"),
            Self::InvalidCheckpoint => {
                formatter.write_str("job checkpoint has invalid phase topology or progress")
            }
            Self::Cancelled => formatter.write_str("job cancellation was requested"),
            Self::InvalidWorkIdentity => {
                formatter.write_str("work identity must be a SHA-256 digest")
            }
            Self::WorkAlreadyActive => formatter.write_str("work identity is already active"),
            Self::WorkScopeRequired => formatter.write_str("a scoped work handle is required"),
            Self::InvalidWorkSnapshot => {
                formatter.write_str("work snapshot is incompatible with this scope")
            }
        }
    }
}

impl std::error::Error for JobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl Job {
    /// Creates a job with all pipeline stages pending
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self::from_parts(label.into(), None)
    }

    /// Creates a job whose snapshots observe the supplied shared admission budget
    ///
    /// Workers must use this same budget for the observations to describe their allocations
    #[must_use]
    pub fn with_memory_budget(label: impl Into<String>, memory: &MemoryBudget) -> Self {
        Self::from_parts(label.into(), Some(memory.clone()))
    }

    /// Returns the live budget shared by this job and its workers, when configured
    #[must_use]
    pub fn memory_budget(&self) -> Option<&MemoryBudget> {
        self.inner.memory.as_ref()
    }

    fn from_parts(label: String, memory: Option<MemoryBudget>) -> Self {
        let created_at = Instant::now();
        let snapshot = JobSnapshot {
            label,
            created_at_unix_ms: unix_time_millis(),
            elapsed_ms: 0,
            current_phase: None,
            phases: Phase::ALL.into_iter().map(PhaseSnapshot::pending).collect(),
            counters: Counter::ALL
                .into_iter()
                .map(|counter| (counter, 0))
                .collect(),
            cache_fallbacks: CacheFallbackSummary::default(),
            recovery_transitions: RecoveryTransitionSummary::default(),
            memory_admission: None,
            cancel_requested: false,
        };

        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    snapshot,
                    created_at,
                    elapsed_base_ms: 0,
                    phase_started_at: BTreeMap::new(),
                    work: WorkLedger::default(),
                    funnel_memory: None,
                }),
                cancel_requested: AtomicBool::new(false),
                memory,
            }),
            work: None,
        }
    }

    /// Starts a stage with an optional known work count
    ///
    /// Open-ended discovery stages should pass `None`, which keeps the estimate unknown
    /// instead of presenting a guessed completion time
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] when a worker previously panicked while holding
    /// the state lock, or [`JobError::PhaseAlreadyStarted`] when this stage is not pending
    pub fn start(&self, phase: Phase, total: Option<u64>) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
            .ok_or(JobError::PhaseAlreadyStarted(phase))?;
        if phase_snapshot.state != PhaseState::Pending {
            return Err(JobError::PhaseAlreadyStarted(phase));
        }

        phase_snapshot.state = PhaseState::InProgress;
        phase_snapshot.total = total;
        phase_snapshot.message = None;
        phase_snapshot.refresh_measurements();

        // Only one start instant is kept because each phase describes one pipeline pass
        state.phase_started_at.insert(phase, Instant::now());
        state.snapshot.current_phase = Some(phase);
        drop(state);
        Ok(())
    }

    /// Adds observed work to an active stage
    ///
    /// A known total bounds the displayed percentage, while `completed` retains the exact
    /// number observed if work expands during execution
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`], [`JobError::PhaseNotInProgress`], or
    /// [`JobError::PhaseOverflow`] when the update cannot be recorded
    pub fn advance(&self, phase: Phase, amount: u64) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.advance(&mut state, phase, amount);
        }
        state
            .work
            .check_phase(&state.snapshot, None, phase, amount)?;
        let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
            .ok_or(JobError::PhaseNotInProgress(phase))?;
        if phase_snapshot.state != PhaseState::InProgress {
            return Err(JobError::PhaseNotInProgress(phase));
        }

        phase_snapshot.completed = next_phase_value(phase_snapshot.completed, phase, amount)?;
        phase_snapshot.refresh_measurements();
        drop(state);
        Ok(())
    }

    /// Replaces the observed work count for an active stage with an absolute value
    ///
    /// Replayed cache work can report the same cumulative value again without incrementing it
    /// a second time
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] or [`JobError::PhaseNotInProgress`] when the stage
    /// is not active
    pub fn set_completed(&self, phase: Phase, completed: u64) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.set_completed(&mut state, phase, completed);
        }
        state.work.check_base_phase_replacement(phase, completed)?;
        let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
            .ok_or(JobError::PhaseNotInProgress(phase))?;
        if phase_snapshot.state != PhaseState::InProgress {
            return Err(JobError::PhaseNotInProgress(phase));
        }

        phase_snapshot.completed = completed;
        phase_snapshot.refresh_measurements();
        drop(state);
        Ok(())
    }

    /// Replaces the detail message for an active stage
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] or [`JobError::PhaseNotInProgress`] when the stage
    /// is not active
    pub fn set_current(&self, phase: Phase, message: impl Into<String>) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        {
            let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
                .ok_or(JobError::PhaseNotInProgress(phase))?;
            if phase_snapshot.state != PhaseState::InProgress {
                return Err(JobError::PhaseNotInProgress(phase));
            }

            phase_snapshot.message = Some(message.into());
        }

        // Overlapping work can make the most recently updated phase differ from the last one started
        state.snapshot.current_phase = Some(phase);
        drop(state);
        Ok(())
    }

    /// Adds work to a cumulative typed counter
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] or [`JobError::CounterOverflow`] when the value
    /// cannot be recorded
    pub fn increment(&self, counter: Counter, amount: u64) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.increment(&mut state, counter, amount);
        }
        state
            .work
            .check_counter(&state.snapshot, None, counter, amount)?;
        let current = state
            .snapshot
            .counters
            .get(&counter)
            .copied()
            .unwrap_or_default();
        let next = next_counter_value(current, counter, amount)?;
        state.snapshot.counters.insert(counter, next);
        drop(state);
        Ok(())
    }

    /// Records a typed cumulative counter and active phase work as one update
    ///
    /// The global counter always advances, while phase work changes only if the phase is active
    /// Standalone library work does not start or finish a phase
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`], [`JobError::CounterOverflow`], or
    /// [`JobError::PhaseOverflow`] when the update cannot be recorded without partial changes
    pub fn record_work(&self, phase: Phase, counter: Counter, amount: u64) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.record_work(&mut state, phase, counter, amount);
        }
        state
            .work
            .check_counter(&state.snapshot, None, counter, amount)?;
        if state
            .snapshot
            .phase(phase)
            .is_some_and(|entry| entry.state == PhaseState::InProgress)
        {
            state
                .work
                .check_phase(&state.snapshot, None, phase, amount)?;
        }
        let JobSnapshot {
            counters,
            current_phase,
            phases,
            ..
        } = &mut state.snapshot;
        let phase_snapshot = find_phase_mut(phases, phase);
        let next_completed = phase_snapshot
            .as_deref()
            .filter(|snapshot| snapshot.state == PhaseState::InProgress)
            .map(|snapshot| next_phase_value(snapshot.completed, phase, amount))
            .transpose()?;
        let current_counter = counters.get(&counter).copied().unwrap_or_default();
        let next_counter = next_counter_value(current_counter, counter, amount)?;

        // Validate both totals before mutating so overflow cannot split the measurements
        counters.insert(counter, next_counter);
        if let (Some(phase_snapshot), Some(next_completed)) = (phase_snapshot, next_completed) {
            phase_snapshot.completed = next_completed;
            phase_snapshot.refresh_measurements();

            // Overlapping work can make this the most recently visible phase
            *current_phase = Some(phase);
        }
        drop(state);
        Ok(())
    }

    /// Records a bounded cache fallback without retaining cache keys or recovered bytes
    ///
    /// The detail describes the failure without source names, cache keys, or recovered data
    ///
    /// The sample is escaped and truncated before the shared job lock is acquired. Repeated
    /// events are grouped by stage and kind, and the lexicographically smallest sample is kept
    /// so concurrent updates produce stable snapshots
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] when a worker panicked while holding the job state
    pub fn record_cache_fallback(
        &self,
        cache_stage: CacheStage,
        kind: CacheFallbackKind,
        sample_detail: fmt::Arguments<'_>,
    ) -> Result<(), JobError> {
        let sample_detail = bounded_escaped_sample(sample_detail);
        let mut state = self.lock_state()?;
        state
            .snapshot
            .cache_fallbacks
            .record(cache_stage, kind, sample_detail);
        drop(state);
        Ok(())
    }

    /// Records one bounded recovery transition without retaining candidate bytes
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] if shared state cannot be accessed
    pub fn record_recovery_transition(&self, event: RecoveryTransition) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.record_transition(&mut state, event);
        }
        state.snapshot.recovery_transitions.record(event);
        drop(state);
        Ok(())
    }

    /// Associates source-backed session inputs with one bounded cohort funnel
    ///
    /// # Errors
    /// Returns an error when shared job state cannot be accessed
    pub fn register_recovery_cohort(
        &self,
        registration: RecoveryFunnelRegistration<'_>,
    ) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.register_cohort(&mut state, registration);
        }
        if !state
            .snapshot
            .recovery_transitions
            .has_funnel_cohort(registration.identity)
        {
            let required = state.funnel_cohort_count().saturating_add(1);
            if state.ensure_funnel_slots(self.inner.memory.as_ref(), required) < required {
                let reason = if required > MAX_FUNNEL_COHORTS {
                    FunnelOmissionReason::CohortLimit
                } else {
                    FunnelOmissionReason::MemoryAdmission
                };
                state
                    .snapshot
                    .recovery_transitions
                    .omit_funnel_registration(reason);
                return Ok(());
            }
        }
        state
            .snapshot
            .recovery_transitions
            .register_cohort(registration);
        drop(state);
        Ok(())
    }

    /// Attributes a candidate outcome to its known source cohorts
    ///
    /// # Errors
    /// Returns an error when shared job state cannot be accessed
    pub fn record_recovery_funnel_candidate(
        &self,
        event: RecoveryFunnelEvent<'_>,
    ) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.record_funnel_candidate(&mut state, event);
        }
        state
            .snapshot
            .recovery_transitions
            .record_funnel_candidate(event);
        drop(state);
        Ok(())
    }

    /// Records a discovery outcome for the exact cohort whose report produced it
    ///
    /// # Errors
    /// Returns an error when shared job state cannot be accessed
    pub fn record_recovery_funnel_cohort_candidate(
        &self,
        identity: RecoveryFunnelIdentity,
        transition_stage: RecoveryTransitionStage,
        outcome: RecoveryTransitionOutcome,
        candidate: RecoveryCandidateSample,
    ) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        if let Some(work) = &self.work {
            return work.record_funnel_cohort_candidate(
                &mut state,
                identity,
                transition_stage,
                outcome,
                candidate,
            );
        }
        state
            .snapshot
            .recovery_transitions
            .record_funnel_cohort_candidate(identity, transition_stage, outcome, candidate);
        drop(state);
        Ok(())
    }

    /// Records the final outcome for a stage
    ///
    /// A skipped stage may finish while pending; other outcomes require a running stage
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`] or [`JobError::PhaseNotInProgress`] when the
    /// outcome cannot be applied
    pub fn finish(&self, phase: Phase, outcome: PhaseOutcome) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        let current_state = state
            .snapshot
            .phase(phase)
            .map(|phase_snapshot| phase_snapshot.state)
            .ok_or(JobError::PhaseNotInProgress(phase))?;
        let can_finish = current_state == PhaseState::InProgress
            || (outcome == PhaseOutcome::Skipped && current_state == PhaseState::Pending);
        if !can_finish {
            return Err(JobError::PhaseNotInProgress(phase));
        }

        // Remove the runtime clock before borrowing the public snapshot for mutation
        let elapsed_ms = state
            .phase_started_at
            .remove(&phase)
            .map(|started_at| duration_millis(started_at.elapsed()));
        let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
            .ok_or(JobError::PhaseNotInProgress(phase))?;
        phase_snapshot.state = match outcome {
            PhaseOutcome::Completed => PhaseState::Completed,
            PhaseOutcome::Failed => PhaseState::Failed,
            PhaseOutcome::Cancelled => PhaseState::Cancelled,
            PhaseOutcome::Skipped => PhaseState::Skipped,
        };

        // A skipped stage has no clock entry, and completed stages freeze their elapsed time
        if let Some(elapsed_ms) = elapsed_ms {
            phase_snapshot.elapsed_ms = phase_snapshot.elapsed_ms.saturating_add(elapsed_ms);
        }
        phase_snapshot.refresh_measurements();
        drop(state);
        Ok(())
    }

    /// Returns a serializable point-in-time view of the shared job state
    ///
    /// # Errors
    /// Returns an error when job state or the live memory observer is unavailable
    pub fn snapshot(&self) -> Result<JobSnapshot, JobError> {
        self.snapshot_with_result_projection(None)
    }

    /// Returns live progress with bounded recovery details for a result receipt
    ///
    /// Cohort stage counts are retained when `retain_cohorts` is true. Otherwise,
    /// omitted cohort and transition details are reported in the snapshot
    ///
    /// # Errors
    /// Returns an error when job state or the live memory observer is unavailable
    pub fn result_snapshot(&self, retain_cohorts: bool) -> Result<JobSnapshot, JobError> {
        self.snapshot_with_result_projection(Some(retain_cohorts))
    }

    fn snapshot_with_result_projection(
        &self,
        retain_cohorts: Option<bool>,
    ) -> Result<JobSnapshot, JobError> {
        let state = self.lock_state()?;
        let admission =
            reserve_funnel_snapshot(self.inner.memory.as_ref(), state.funnel_cohort_count());
        let memory_limit = admission.cohort_limit;
        let mut snapshot = timed_snapshot(&state, self.is_cancelled(), memory_limit);
        state.work.apply_to(&mut snapshot, memory_limit)?;
        if let Some(retain_cohorts) = retain_cohorts {
            snapshot.recovery_transitions.project_result(retain_cohorts);
        }
        snapshot
            .recovery_transitions
            .freeze_funnel(admission.memory);
        drop(state);
        self.with_memory_observation(snapshot)
    }

    /// Returns progress whose durable state belongs to the job rather than a Case
    ///
    /// Scoped measurements belong to their own committed generations. Leaving them out
    /// prevents a background display checkpoint from duplicating restored Case work.
    ///
    /// # Errors
    /// Returns an error when job state or the live memory observer is unavailable
    pub fn checkpoint_snapshot(&self) -> Result<JobSnapshot, JobError> {
        let state = self.lock_state()?;
        let count = state.snapshot.recovery_transitions.funnel_cohort_count();
        let admission = reserve_funnel_snapshot(self.inner.memory.as_ref(), count);
        let memory_limit = admission.cohort_limit;
        let mut snapshot = timed_snapshot(&state, self.is_cancelled(), memory_limit);
        snapshot.recovery_transitions.limit_checkpoint();
        snapshot
            .recovery_transitions
            .freeze_funnel(admission.memory);
        drop(state);
        self.with_memory_observation(snapshot)
    }

    /// Restores a saved snapshot into this shared job handle
    ///
    /// Interrupted stages return to pending while their completed counts and elapsed times
    /// remain available. A live preparation stage keeps its clock, work and message. Counters
    /// collected during the current invocation are added to saved totals, and the live
    /// cancellation flag remains owned by this handle. Source reads from earlier invocations
    /// remain separate from reads performed during this invocation
    ///
    /// # Errors
    /// Returns an error for invalid saved phases or progress, unavailable shared state,
    /// overflowing measurements, or other live pipeline or scoped work
    pub fn restore(&self, mut snapshot: JobSnapshot) -> Result<(), JobError> {
        // Refuse malformed phases before reserving memory or changing live state
        if !snapshot.is_valid_checkpoint() {
            return Err(JobError::InvalidCheckpoint);
        }
        let mut state = self.lock_state()?;
        live_preparation(&state)?;
        let existing = state.snapshot.recovery_transitions.funnel_cohort_count();
        let cohort_limit = MAX_FUNNEL_COHORTS.saturating_sub(existing);
        let required = existing.saturating_add(
            snapshot
                .recovery_transitions
                .funnel_cohort_count()
                .min(cohort_limit),
        );
        let allowed = state
            .ensure_funnel_slots(self.inner.memory.as_ref(), required)
            .saturating_sub(existing);
        snapshot
            .recovery_transitions
            .thaw_funnel(cohort_limit, allowed);
        let snapshot =
            match restored_snapshot(&state, snapshot, self.is_cancelled(), MAX_FUNNEL_COHORTS) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    state.release_funnel_slots();
                    return Err(error);
                }
            };
        state.elapsed_base_ms = snapshot.elapsed_ms;
        state.snapshot = snapshot;
        state.release_funnel_slots();
        // Preparation retains its original runtime clock through the restore
        state
            .phase_started_at
            .retain(|phase, _| *phase == Phase::Preparation);
        drop(state);
        Ok(())
    }

    /// Computes a safe checkpoint before an optional restore without changing the live job
    ///
    /// Preparation elapsed time includes the current invocation. Both a fresh checkpoint and
    /// a restored checkpoint reject live discovery stages and scoped work
    ///
    /// # Errors
    /// Returns an error for invalid saved phases or progress, unavailable shared state,
    /// overflowing measurements, or other live pipeline or scoped work
    pub fn preview_checkpoint(&self, saved: Option<&JobSnapshot>) -> Result<JobSnapshot, JobError> {
        if saved.is_some_and(|snapshot| !snapshot.is_valid_checkpoint()) {
            return Err(JobError::InvalidCheckpoint);
        }
        let state = self.lock_state()?;
        let cancel_requested = self.is_cancelled();
        let live_count = state.snapshot.recovery_transitions.funnel_cohort_count();
        let saved_limit = MAX_FUNNEL_COHORTS.saturating_sub(live_count);
        let saved_count = saved.map_or(0, |snapshot| {
            snapshot.recovery_transitions.funnel_cohort_count()
        });
        let count = live_count.saturating_add(saved_count.min(saved_limit));
        let admission = reserve_funnel_snapshot(self.inner.memory.as_ref(), count);
        let memory_limit = admission.cohort_limit;
        let mut snapshot = if let Some(saved) = saved {
            let snapshot = saved.snapshot_copy(saved_limit, memory_limit);
            let mut snapshot = restored_snapshot(&state, snapshot, cancel_requested, memory_limit)?;
            let elapsed_base_ms = snapshot.elapsed_ms;
            apply_timing(&state, &mut snapshot, elapsed_base_ms);
            snapshot
        } else {
            live_preparation(&state)?;
            timed_snapshot(&state, cancel_requested, memory_limit)
        };
        snapshot.recovery_transitions.limit_checkpoint();
        snapshot
            .recovery_transitions
            .freeze_funnel(admission.memory);
        drop(state);
        self.with_memory_observation(snapshot)
    }

    /// Requests cooperative cancellation for every clone of this job handle
    pub fn request_cancel(&self) {
        self.inner.cancel_requested.store(true, Ordering::Release);
    }

    /// Reports whether cooperative cancellation has been requested
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel_requested.load(Ordering::Acquire)
    }

    /// Stops a worker at its next cancellation check when cancellation was requested
    ///
    /// # Errors
    /// Returns [`JobError::Cancelled`] when cancellation was requested
    pub fn check_cancelled(&self) -> Result<(), JobError> {
        if self.is_cancelled() {
            return Err(JobError::Cancelled);
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, State>, JobError> {
        self.inner.state.lock().map_err(|_| JobError::LockPoisoned)
    }

    fn with_memory_observation(&self, mut snapshot: JobSnapshot) -> Result<JobSnapshot, JobError> {
        // Read the budget after releasing the job lock so observation cannot block worker updates
        snapshot.memory_admission = self
            .inner
            .memory
            .as_ref()
            .map(MemoryBudget::snapshot)
            .transpose()
            .map_err(JobError::Memory)?;
        Ok(snapshot)
    }
}

fn live_preparation(state: &State) -> Result<Option<&PhaseSnapshot>, JobError> {
    let preparation = state
        .snapshot
        .phase(Phase::Preparation)
        .filter(|phase| phase.state == PhaseState::InProgress);
    let expected_current = preparation.map(|_| Phase::Preparation);
    let phases_are_restorable = state.snapshot.current_phase == expected_current
        && state.snapshot.phases.iter().all(|phase| {
            phase.state == PhaseState::Pending
                || (phase.phase == Phase::Preparation && phase.state == PhaseState::InProgress)
        })
        && state.work.is_empty();
    if phases_are_restorable {
        Ok(preparation)
    } else {
        Err(JobError::RestoreAfterStart)
    }
}

fn restored_snapshot(
    state: &State,
    mut snapshot: JobSnapshot,
    cancel_requested: bool,
    memory_limit: usize,
) -> Result<JobSnapshot, JobError> {
    let preparation = live_preparation(state)?;
    snapshot.memory_admission = None;

    // Saved source reads describe prior work, not I/O performed by this process
    let previous_reads = snapshot
        .counters
        .remove(&Counter::SourceReadBytes)
        .unwrap_or_default();
    let prior_reads = snapshot
        .counters
        .entry(Counter::PriorSourceReadBytes)
        .or_insert(0);
    *prior_reads = prior_reads
        .checked_add(previous_reads)
        .ok_or(JobError::CounterOverflow(Counter::PriorSourceReadBytes))?;

    // Cache lookups may have recorded work before restoration
    for (counter, value) in &state.snapshot.counters {
        let restored_value = snapshot.counters.entry(*counter).or_insert(0);
        *restored_value = restored_value
            .checked_add(*value)
            .ok_or(JobError::CounterOverflow(*counter))?;
    }
    snapshot
        .cache_fallbacks
        .merge(state.snapshot.cache_fallbacks.clone());
    snapshot.recovery_transitions.merge(
        state
            .snapshot
            .recovery_transitions
            .snapshot_copy(MAX_FUNNEL_COHORTS, memory_limit),
    );
    snapshot.cancel_requested = cancel_requested;
    for phase in &mut snapshot.phases {
        if phase.state == PhaseState::InProgress {
            phase.state = PhaseState::Pending;
            phase.refresh_measurements();
        }
    }

    if let Some(preparation) = preparation {
        let saved = find_phase_mut(&mut snapshot.phases, Phase::Preparation)
            .ok_or(JobError::RestoreAfterStart)?;
        let completed =
            next_phase_value(saved.completed, Phase::Preparation, preparation.completed)?;
        let elapsed_ms = saved.elapsed_ms.saturating_add(preparation.elapsed_ms);
        // Keep the live state and message while retaining previously observed work
        *saved = preparation.clone();
        saved.completed = completed;
        saved.elapsed_ms = elapsed_ms;
        saved.refresh_measurements();
        snapshot.current_phase = Some(Phase::Preparation);
    }
    Ok(snapshot)
}

fn timed_snapshot(state: &State, cancel_requested: bool, memory_limit: usize) -> JobSnapshot {
    let mut snapshot = state
        .snapshot
        .snapshot_copy(MAX_FUNNEL_COHORTS, memory_limit);
    snapshot.cancel_requested = cancel_requested;
    apply_timing(state, &mut snapshot, state.elapsed_base_ms);
    snapshot
}

struct FunnelSnapshotAdmission {
    memory: Option<MemoryLease>,
    cohort_limit: usize,
}

fn reserve_funnel_snapshot(memory: Option<&MemoryBudget>, count: usize) -> FunnelSnapshotAdmission {
    if count == 0 {
        return FunnelSnapshotAdmission {
            memory: None,
            cohort_limit: MAX_FUNNEL_COHORTS,
        };
    }
    let Some(memory) = memory else {
        return FunnelSnapshotAdmission {
            memory: None,
            cohort_limit: MAX_FUNNEL_COHORTS,
        };
    };
    let lease = u64::try_from(cohort_capacity_charge())
        .ok()
        .and_then(|unit| {
            u64::try_from(count)
                .ok()
                .and_then(|count| unit.checked_mul(count))
        })
        .and_then(|bytes| memory.try_reserve(MemoryClass::Executor, bytes).ok());
    let cohort_limit = if lease.is_some() {
        MAX_FUNNEL_COHORTS
    } else {
        0
    };
    FunnelSnapshotAdmission {
        memory: lease,
        cohort_limit,
    }
}

fn apply_timing(state: &State, snapshot: &mut JobSnapshot, elapsed_base_ms: u64) {
    snapshot.elapsed_ms =
        elapsed_base_ms.saturating_add(duration_millis(state.created_at.elapsed()));
    // Runtime clocks stay outside the serialized model and are applied only to this copy
    for phase in &mut snapshot.phases {
        if let Some(started_at) = state.phase_started_at.get(&phase.phase) {
            phase.elapsed_ms = phase
                .elapsed_ms
                .saturating_add(duration_millis(started_at.elapsed()));
            phase.refresh_measurements();
        }
    }
}

fn find_phase_mut(phases: &mut [PhaseSnapshot], phase: Phase) -> Option<&mut PhaseSnapshot> {
    phases.iter_mut().find(|snapshot| snapshot.phase == phase)
}

fn next_phase_value(current: u64, phase: Phase, amount: u64) -> Result<u64, JobError> {
    current
        .checked_add(amount)
        .ok_or(JobError::PhaseOverflow(phase))
}

fn next_counter_value(current: u64, counter: Counter, amount: u64) -> Result<u64, JobError> {
    current
        .checked_add(amount)
        .ok_or(JobError::CounterOverflow(counter))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_millis)
}
