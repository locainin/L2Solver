use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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
    /// Packets processed
    Packets,
    /// Flows reconstructed
    Flows,
    /// Cohorts grouped
    Cohorts,
    /// Candidate work items examined
    CandidatesExamined,
    /// Candidate work items rejected
    CandidatesRejected,
    /// Artifacts that passed validation
    ValidatedArtifacts,
    /// Members found while expanding containers
    ExpandedMembers,
    /// Results reused from the persistent cache
    CacheHits,
    /// Results computed without a persistent cache entry
    CacheMisses,
    /// Records discovered
    Records,
    /// Transformations discovered
    Transforms,
    /// Reports written
    Reports,
}

impl Counter {
    const ALL: [Self; 14] = [
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
    /// Estimated remaining time when a known total and measured rate exist
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

        // No completed work or elapsed time means there is no measured pace to extrapolate
        if remaining == 0 || self.completed == 0 || self.elapsed_ms == 0 {
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
    /// Whether a cooperative cancellation request has been sent
    pub cancel_requested: bool,
}

impl JobSnapshot {
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

        phase_snapshot.completed = phase_snapshot
            .completed
            .checked_add(amount)
            .ok_or(JobError::PhaseOverflow(phase))?;
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
        let phase_snapshot = find_phase_mut(&mut state.snapshot.phases, phase)
            .ok_or(JobError::PhaseNotInProgress(phase))?;
        if phase_snapshot.state != PhaseState::InProgress {
            return Err(JobError::PhaseNotInProgress(phase));
        }

        phase_snapshot.message = Some(message.into());
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
        let value = state.snapshot.counters.entry(counter).or_insert(0);
        *value = value
            .checked_add(amount)
            .ok_or(JobError::CounterOverflow(counter))?;
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

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_millis)
}
