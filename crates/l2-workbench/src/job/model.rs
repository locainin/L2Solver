use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::recovery_transition::{RecoveryTransition, RecoveryTransitionSummary};

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
    const ALL: [Self; 15] = [
        Self::Files,
        Self::Bytes,
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
    /// Whether a cooperative cancellation request has been sent
    pub cancel_requested: bool,
}

impl JobSnapshot {
    pub(super) fn is_valid_checkpoint(&self) -> bool {
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
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    cancel_requested: AtomicBool,
}

#[derive(Debug)]
struct State {
    snapshot: JobSnapshot,
    created_at: Instant,
    elapsed_base_ms: u64,
    phase_started_at: BTreeMap<Phase, Instant>,
}

/// Errors returned when a progress update cannot be applied
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JobError {
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
    /// Snapshot restoration was requested after live work started
    RestoreAfterStart,
    /// Cooperative cancellation was requested
    Cancelled,
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::RestoreAfterStart => {
                formatter.write_str("job snapshot cannot be restored after live work started")
            }
            Self::Cancelled => formatter.write_str("job cancellation was requested"),
        }
    }
}

impl std::error::Error for JobError {}

impl Job {
    /// Creates a job with all pipeline stages pending
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        let created_at = Instant::now();
        let snapshot = JobSnapshot {
            label: label.into(),
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
            cancel_requested: false,
        };

        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    snapshot,
                    created_at,
                    elapsed_base_ms: 0,
                    phase_started_at: BTreeMap::new(),
                }),
                cancel_requested: AtomicBool::new(false),
            }),
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
        state.snapshot.recovery_transitions.record(event);
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
    /// Returns [`JobError::LockPoisoned`] when a worker previously panicked while holding
    /// the state lock
    pub fn snapshot(&self) -> Result<JobSnapshot, JobError> {
        let state = self.lock_state()?;
        let mut snapshot = state.snapshot.clone();
        snapshot.elapsed_ms = state
            .elapsed_base_ms
            .saturating_add(duration_millis(state.created_at.elapsed()));
        snapshot.cancel_requested = self.is_cancelled();

        // Runtime clocks stay outside the serialized model and are applied only to this copy
        for phase in &mut snapshot.phases {
            if let Some(started_at) = state.phase_started_at.get(&phase.phase) {
                phase.elapsed_ms = phase
                    .elapsed_ms
                    .saturating_add(duration_millis(started_at.elapsed()));
                phase.refresh_measurements();
            }
        }
        Ok(snapshot)
    }

    /// Restores a saved snapshot into this shared job handle
    ///
    /// Interrupted stages return to pending while their completed counts and elapsed times
    /// remain available. Counters collected during the current invocation are added to saved
    /// totals, and the live cancellation flag remains owned by this handle
    ///
    /// # Errors
    /// Returns [`JobError::LockPoisoned`], [`JobError::CounterOverflow`], or
    /// [`JobError::RestoreAfterStart`] when the snapshot cannot be applied safely
    pub fn restore(&self, mut snapshot: JobSnapshot) -> Result<(), JobError> {
        let mut state = self.lock_state()?;
        let no_live_phase_started = state.snapshot.current_phase.is_none()
            && state
                .snapshot
                .phases
                .iter()
                .all(|phase| phase.state == PhaseState::Pending);
        if !no_live_phase_started {
            return Err(JobError::RestoreAfterStart);
        }

        // Cache lookups can happen before restoration, so their counters remain part of this run
        for (counter, value) in &state.snapshot.counters {
            let restored_value = snapshot.counters.entry(*counter).or_insert(0);
            *restored_value = restored_value
                .checked_add(*value)
                .ok_or(JobError::CounterOverflow(*counter))?;
        }

        // Cache fallback counts are cumulative, just like the counters above
        let current_cache_fallbacks = std::mem::take(&mut state.snapshot.cache_fallbacks);
        snapshot.cache_fallbacks.merge(current_cache_fallbacks);
        let transitions = std::mem::take(&mut state.snapshot.recovery_transitions);
        snapshot.recovery_transitions.merge(transitions);

        // A prior process cancellation does not cancel this run, but a signal during lookup does
        snapshot.cancel_requested = self.is_cancelled();
        for phase in &mut snapshot.phases {
            if phase.state == PhaseState::InProgress {
                phase.state = PhaseState::Pending;
                phase.refresh_measurements();
            }
        }

        state.elapsed_base_ms = snapshot.elapsed_ms;
        state.snapshot = snapshot;
        state.phase_started_at.clear();
        drop(state);
        Ok(())
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
