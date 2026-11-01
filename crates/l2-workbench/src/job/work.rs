//! Independently restorable progress for concurrent recovery work

use super::super::recovery_transition::{FunnelOmissionReason, MAX_FUNNEL_COHORTS};
use super::{
    Arc, BTreeMap, Counter, Inner, Job, JobError, JobSnapshot, Phase, PhaseState,
    RecoveryTransition, RecoveryTransitionSummary, State, find_phase_mut, next_counter_value,
    next_phase_value, reserve_funnel_snapshot,
};
use super::{
    RecoveryCandidateSample, RecoveryFunnelEvent, RecoveryFunnelIdentity,
    RecoveryFunnelRegistration, RecoveryTransitionOutcome, RecoveryTransitionStage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const WORK_SNAPSHOT_VERSION: u32 = 1;

#[path = "work/checkpoint.rs"]
mod checkpoint;

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

impl WorkSnapshot {
    /// Returns a bounded, serializable view for durable checkpoint metadata
    ///
    /// The allowance covers optional recovery diagnostics. Work counters and the small
    /// omission marker remain present even when the allowance is zero. Values above the
    /// policy ceiling are capped. The returned view borrows this immutable snapshot.
    #[must_use]
    pub fn checkpoint_view(&self, max_diagnostic_bytes: usize) -> impl Serialize + '_ {
        checkpoint::View::new(self, max_diagnostic_bytes)
    }

    /// Returns this contribution's observed count for one measurement
    #[must_use]
    pub fn counter(&self, counter: Counter) -> u64 {
        self.counts.counter(counter)
    }

    /// Returns work observed while the selected phase was active
    #[must_use]
    pub fn phase_work(&self, phase: Phase) -> u64 {
        self.counts.phase(phase)
    }
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
        let counts = owner.counts(&state)?;
        let admission = reserve_funnel_snapshot(
            self.inner.memory.as_ref(),
            counts.recovery_transitions.funnel_cohort_count(),
        );
        let memory_limit = admission.cohort_limit;
        let mut recovery_transitions = counts
            .recovery_transitions
            .snapshot_copy(MAX_FUNNEL_COHORTS, memory_limit);
        recovery_transitions.freeze_funnel(admission.memory);
        let snapshot = WorkSnapshot {
            schema_version: WORK_SNAPSHOT_VERSION,
            scope_id: owner.id.clone(),
            counts: WorkCounts {
                counters: counts.counters.clone(),
                phase_work: counts.phase_work.clone(),
                recovery_transitions,
            },
        };
        drop(state);
        Ok(snapshot)
    }

    /// Replaces this work contribution with its committed generation's measurements
    ///
    /// A background display update may be ahead of the last committed generation. Replacing
    /// the contribution rolls it back without subtracting another worker's measurements.
    ///
    /// # Errors
    /// Returns an error for a wrong identity or format, an overflowing aggregate, or an
    /// unavailable work scope. All checks complete before any live measurement changes.
    pub fn restore_work(&self, mut snapshot: WorkSnapshot) -> Result<(), JobError> {
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
        let other_cohorts = state
            .snapshot
            .recovery_transitions
            .funnel_cohort_count()
            .saturating_add(state.work.funnel_cohort_count(Some(&owner.id)));
        let required = other_cohorts
            .saturating_add(snapshot.counts.recovery_transitions.funnel_cohort_count());
        let allowed = state
            .ensure_funnel_slots(self.inner.memory.as_ref(), required)
            .saturating_sub(other_cohorts);
        let max_scope = MAX_FUNNEL_COHORTS.saturating_sub(other_cohorts);
        snapshot
            .counts
            .recovery_transitions
            .thaw_funnel(max_scope, allowed);
        *owner.counts_mut(&mut state)? = snapshot.counts;
        state.release_funnel_slots();
        drop(state);
        Ok(())
    }
}

impl WorkLedger {
    pub(super) fn funnel_cohort_count(&self, skip: Option<&str>) -> usize {
        self.contributions(skip).fold(0_usize, |total, counts| {
            total.saturating_add(counts.recovery_transitions.funnel_cohort_count())
        })
    }
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

    pub(super) fn apply_to(
        &self,
        snapshot: &mut JobSnapshot,
        memory_limit: usize,
    ) -> Result<(), JobError> {
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
            snapshot.recovery_transitions.merge(
                counts
                    .recovery_transitions
                    .snapshot_copy(MAX_FUNNEL_COHORTS, memory_limit),
            );
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

    pub(super) fn register_cohort(
        &self,
        state: &mut State,
        mut registration: RecoveryFunnelRegistration<'_>,
    ) -> Result<(), JobError> {
        registration.identity = self.scoped_funnel_identity(registration.identity);
        if !self
            .counts(state)?
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
                self.counts_mut(state)?
                    .recovery_transitions
                    .omit_funnel_registration(reason);
                return Ok(());
            }
        }
        self.counts_mut(state)?
            .recovery_transitions
            .register_cohort(registration);
        Ok(())
    }

    pub(super) fn record_funnel_candidate(
        &self,
        state: &mut State,
        event: RecoveryFunnelEvent<'_>,
    ) -> Result<(), JobError> {
        self.counts_mut(state)?
            .recovery_transitions
            .record_funnel_candidate(event);
        Ok(())
    }

    pub(super) fn record_funnel_cohort_candidate(
        &self,
        state: &mut State,
        identity: RecoveryFunnelIdentity,
        transition_stage: RecoveryTransitionStage,
        outcome: RecoveryTransitionOutcome,
        candidate: RecoveryCandidateSample,
    ) -> Result<(), JobError> {
        let identity = self.scoped_funnel_identity(identity);
        self.counts_mut(state)?
            .recovery_transitions
            .record_funnel_cohort_candidate(identity, transition_stage, outcome, candidate);
        Ok(())
    }

    fn scoped_funnel_identity(
        &self,
        mut identity: RecoveryFunnelIdentity,
    ) -> RecoveryFunnelIdentity {
        // Case node IDs are local to this independently checkpointed work scope
        let mut digest = Sha256::new();
        digest.update(b"l2-recovery-funnel-work-scope-v1\0");
        digest.update(self.id.as_bytes());
        digest.update(identity.cohort_sha256);
        identity.cohort_sha256 = digest.finalize().into();
        identity
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
            state.release_funnel_slots();
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
