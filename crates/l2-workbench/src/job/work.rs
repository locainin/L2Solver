//! Independently restorable progress for concurrent recovery work

use super::{
    Arc, BTreeMap, Counter, Inner, Job, JobError, JobSnapshot, Phase, PhaseState,
    RecoveryTransition, RecoveryTransitionSummary, State, find_phase_mut, next_counter_value,
    next_phase_value,
};
use serde::{Deserialize, Serialize};

const WORK_SNAPSHOT_VERSION: u32 = 1;

/// Measurements committed alongside one recovery execution generation
///
/// These values describe observed work, not the scheduler's resource allowances
/// A restore replaces this contribution and leaves other active workers unchanged
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSnapshot {
    schema_version: u32,
    scope_id: String,
    counts: WorkCounts,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkCounts {
    counters: BTreeMap<Counter, u64>,
    phase_work: BTreeMap<Phase, u64>,
    recovery_transitions: RecoveryTransitionSummary,
}

#[derive(Debug, Default)]
pub(super) struct WorkLedger {
    active: BTreeMap<String, WorkCounts>,
    // Finished contributions stay visible without retaining one map per completed Case
    finished: WorkCounts,
}

#[derive(Debug)]
pub(super) struct WorkOwner {
    inner: Arc<Inner>,
    id: String,
}

impl Job {
    /// Starts an independently checkpointed work contribution using a stage-key digest
    ///
    /// Clones share this contribution and the job's cancellation flag. The last handle
    /// retires its measurements into the displayed totals for this invocation. Durable
    /// restoration belongs to the Case generation rather than the background job snapshot.
    ///
    /// # Errors
    /// Returns an error for an invalid identity, an already active identity, or a poisoned lock
    pub fn work_scope(&self, identity: &str) -> Result<Self, JobError> {
        if !crate::hashing::is_sha256_digest(identity) {
            return Err(JobError::InvalidWorkIdentity);
        }
        let mut state = self.lock_state()?;
        if state.work.active.contains_key(identity) {
            return Err(JobError::WorkAlreadyActive);
        }
        state
            .work
            .active
            .insert(identity.to_owned(), WorkCounts::default());
        drop(state);
        Ok(Self {
            inner: Arc::clone(&self.inner),
            work: Some(Arc::new(WorkOwner {
                inner: Arc::clone(&self.inner),
                id: identity.to_owned(),
            })),
        })
    }

    /// Captures only this work contribution at a transaction-consistent scheduler boundary
    ///
    /// # Errors
    /// Returns an error when called on an unscoped handle or when shared state is unavailable
    pub fn work_snapshot(&self) -> Result<WorkSnapshot, JobError> {
        let owner = self.work.as_ref().ok_or(JobError::WorkScopeRequired)?;
        let state = self.lock_state()?;
        Ok(WorkSnapshot {
            schema_version: WORK_SNAPSHOT_VERSION,
            scope_id: owner.id.clone(),
            counts: owner.counts(&state)?.clone(),
        })
    }

    /// Replaces this work contribution with its committed generation's measurements
    ///
    /// A background display update may be ahead of the last committed generation. Replacing
    /// the contribution rolls it back without subtracting another worker's measurements.
    ///
    /// # Errors
    /// Returns an error for a wrong identity or format, an overflowing aggregate, or an
    /// unavailable work scope. All checks complete before any live measurement changes.
    pub fn restore_work(&self, snapshot: WorkSnapshot) -> Result<(), JobError> {
        let owner = self.work.as_ref().ok_or(JobError::WorkScopeRequired)?;
        if snapshot.schema_version != WORK_SNAPSHOT_VERSION || snapshot.scope_id != owner.id {
            return Err(JobError::InvalidWorkSnapshot);
        }
        let mut state = self.lock_state()?;
        owner.counts(&state)?;
        for (&counter, &amount) in &snapshot.counts.counters {
            state
                .work
                .check_counter(&state.snapshot, Some(&owner.id), counter, amount)?;
        }
        for (&phase, &amount) in &snapshot.counts.phase_work {
            state
                .work
                .check_phase(&state.snapshot, Some(&owner.id), phase, amount)?;
        }
        *owner.counts_mut(&mut state)? = snapshot.counts;
        drop(state);
        Ok(())
    }
}

impl WorkLedger {
    pub(super) fn is_empty(&self) -> bool {
        self.active.is_empty() && self.finished == WorkCounts::default()
    }

    fn contributions(&self, skip: Option<&str>) -> impl Iterator<Item = &WorkCounts> {
        std::iter::once(&self.finished).chain(
            self.active
                .iter()
                .filter_map(move |(id, counts)| (skip != Some(id.as_str())).then_some(counts)),
        )
    }

    pub(super) fn check_counter(
        &self,
        base: &JobSnapshot,
        skip: Option<&str>,
        counter: Counter,
        amount: u64,
    ) -> Result<(), JobError> {
        let mut total = base.counters.get(&counter).copied().unwrap_or_default();
        for counts in self.contributions(skip) {
            total = next_counter_value(total, counter, counts.counter(counter))?;
        }
        next_counter_value(total, counter, amount)?;
        Ok(())
    }

    pub(super) fn check_phase(
        &self,
        base: &JobSnapshot,
        skip: Option<&str>,
        phase: Phase,
        amount: u64,
    ) -> Result<(), JobError> {
        let mut total = base.phase(phase).map_or(0, |entry| entry.completed);
        for counts in self.contributions(skip) {
            total = next_phase_value(total, phase, counts.phase(phase))?;
        }
        next_phase_value(total, phase, amount)?;
        Ok(())
    }

    pub(super) fn check_base_phase_replacement(
        &self,
        phase: Phase,
        amount: u64,
    ) -> Result<(), JobError> {
        let mut total = amount;
        for counts in self.contributions(None) {
            total = next_phase_value(total, phase, counts.phase(phase))?;
        }
        Ok(())
    }

    pub(super) fn apply_to(&self, snapshot: &mut JobSnapshot) -> Result<(), JobError> {
        for counts in self.contributions(None) {
            for (&counter, &amount) in &counts.counters {
                let current = snapshot.counters.get(&counter).copied().unwrap_or_default();
                snapshot
                    .counters
                    .insert(counter, next_counter_value(current, counter, amount)?);
            }
            for (&phase, &amount) in &counts.phase_work {
                if let Some(entry) = find_phase_mut(&mut snapshot.phases, phase) {
                    entry.completed = next_phase_value(entry.completed, phase, amount)?;
                    entry.refresh_measurements();
                }
            }
            snapshot
                .recovery_transitions
                .merge(counts.recovery_transitions.clone());
        }
        Ok(())
    }
}

impl WorkOwner {
    fn counts<'state>(&self, state: &'state State) -> Result<&'state WorkCounts, JobError> {
        state
            .work
            .active
            .get(&self.id)
            .ok_or(JobError::InvalidWorkSnapshot)
    }

    fn counts_mut<'state>(
        &self,
        state: &'state mut State,
    ) -> Result<&'state mut WorkCounts, JobError> {
        state
            .work
            .active
            .get_mut(&self.id)
            .ok_or(JobError::InvalidWorkSnapshot)
    }

    pub(super) fn increment(
        &self,
        state: &mut State,
        counter: Counter,
        amount: u64,
    ) -> Result<(), JobError> {
        state
            .work
            .check_counter(&state.snapshot, None, counter, amount)?;
        let counts = self.counts_mut(state)?;
        let next = next_counter_value(counts.counter(counter), counter, amount)?;
        counts.counters.insert(counter, next);
        Ok(())
    }

    pub(super) fn advance(
        &self,
        state: &mut State,
        phase: Phase,
        amount: u64,
    ) -> Result<(), JobError> {
        ensure_active_phase(state, phase)?;
        state
            .work
            .check_phase(&state.snapshot, None, phase, amount)?;
        let counts = self.counts_mut(state)?;
        let next = next_phase_value(counts.phase(phase), phase, amount)?;
        counts.phase_work.insert(phase, next);
        Ok(())
    }

    pub(super) fn set_completed(
        &self,
        state: &mut State,
        phase: Phase,
        amount: u64,
    ) -> Result<(), JobError> {
        ensure_active_phase(state, phase)?;
        state
            .work
            .check_phase(&state.snapshot, Some(&self.id), phase, amount)?;
        self.counts_mut(state)?.phase_work.insert(phase, amount);
        Ok(())
    }

    pub(super) fn record_work(
        &self,
        state: &mut State,
        phase: Phase,
        counter: Counter,
        amount: u64,
    ) -> Result<(), JobError> {
        let phase_active = state
            .snapshot
            .phase(phase)
            .is_some_and(|entry| entry.state == PhaseState::InProgress);
        state
            .work
            .check_counter(&state.snapshot, None, counter, amount)?;
        if phase_active {
            state
                .work
                .check_phase(&state.snapshot, None, phase, amount)?;
        }
        let counts = self.counts_mut(state)?;
        let next_counter = next_counter_value(counts.counter(counter), counter, amount)?;
        let next_phase = phase_active
            .then(|| next_phase_value(counts.phase(phase), phase, amount))
            .transpose()?;
        // Both checks complete before updating either measurement
        counts.counters.insert(counter, next_counter);
        if let Some(next) = next_phase {
            counts.phase_work.insert(phase, next);
            state.snapshot.current_phase = Some(phase);
        }
        Ok(())
    }

    pub(super) fn record_transition(
        &self,
        state: &mut State,
        event: RecoveryTransition,
    ) -> Result<(), JobError> {
        self.counts_mut(state)?.recovery_transitions.record(event);
        Ok(())
    }
}

impl WorkCounts {
    fn counter(&self, counter: Counter) -> u64 {
        self.counters.get(&counter).copied().unwrap_or_default()
    }

    fn phase(&self, phase: Phase) -> u64 {
        self.phase_work.get(&phase).copied().unwrap_or_default()
    }

    fn retire(&mut self, other: Self) {
        // Updates and restores already checked the combined totals while holding this lock
        for (counter, amount) in other.counters {
            let current = self.counters.entry(counter).or_default();
            *current += amount;
        }
        for (phase, amount) in other.phase_work {
            let current = self.phase_work.entry(phase).or_default();
            *current += amount;
        }
        self.recovery_transitions.merge(other.recovery_transitions);
    }
}

impl Drop for WorkOwner {
    fn drop(&mut self) {
        // A poisoned job already rejects progress updates; teardown must not panic again
        if let Ok(mut state) = self.inner.state.lock()
            && let Some(counts) = state.work.active.remove(&self.id)
        {
            state.work.finished.retire(counts);
        }
    }
}

fn ensure_active_phase(state: &State, phase: Phase) -> Result<(), JobError> {
    if state
        .snapshot
        .phase(phase)
        .is_some_and(|entry| entry.state == PhaseState::InProgress)
    {
        Ok(())
    } else {
        Err(JobError::PhaseNotInProgress(phase))
    }
}
