//! Keep scheduler phase and source position at operation boundaries

use super::{
    Executor, RecoveryError, RecoveryExecutionError, evidence, record_candidate_progress,
    relational::RelationalLane,
};

#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SchedulerCursor {
    pub(super) phase: SchedulerPhase,
    record_discovery_barrier_reached: bool,
    evidence_stop: Option<evidence::CaseEvidenceStop>,
    evidence_stop_reported: bool,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) enum SchedulerPhase {
    #[default]
    Start,
    Seeding {
        roots: Vec<(u64, String)>,
        next: usize,
    },
    Running,
    Finished,
}

impl SchedulerCursor {
    pub(super) fn validate(&self, executor: &Executor<'_>) -> Result<(), RecoveryError> {
        if self.evidence_stop_reported && self.evidence_stop.is_none() {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        match &self.phase {
            SchedulerPhase::Start => {
                if executor.coordinator.candidate_count() != 0
                    || executor.case_index.node_count != 0
                    || executor.case_index.edge_count != 0
                {
                    return Err(RecoveryError::InvalidCheckpoint);
                }
            }
            SchedulerPhase::Seeding { roots, next } => {
                if *next > roots.len() || roots.len() > executor.case.nodes().len() {
                    return Err(RecoveryError::InvalidCheckpoint);
                }
                let mut unique = std::collections::HashSet::new();
                unique
                    .try_reserve(roots.len())
                    .map_err(|_| RecoveryError::AllocationFailed)?;
                for (id, kind) in roots {
                    if executor
                        .case
                        .node(*id)
                        .is_none_or(|node| node.kind != *kind)
                        || !unique.insert(*id)
                    {
                        return Err(RecoveryError::InvalidCheckpoint);
                    }
                }
            }
            SchedulerPhase::Finished => {
                if executor.coordinator.peek_next_id().is_some()
                    || (self.evidence_stop.is_none()
                        && (!executor.pending_record_assemblies.is_empty()
                            || !executor.pending_record_suffixes.is_empty()
                            || executor.deferred_record_discovery_plan.is_some()))
                {
                    return Err(RecoveryError::InvalidCheckpoint);
                }
            }
            SchedulerPhase::Running => {}
        }
        Ok(())
    }
}

pub(super) fn step(
    executor: &mut Executor<'_>,
    cursor: &mut SchedulerCursor,
) -> Result<bool, RecoveryExecutionError> {
    match &mut cursor.phase {
        SchedulerPhase::Start => {
            executor.check_cancelled()?;
            executor.enqueue_framing_discovery_if_enabled()?;
            let roots = executor.initialize_case_index()?;
            cursor.phase = if roots.is_empty() {
                SchedulerPhase::Running
            } else {
                SchedulerPhase::Seeding { roots, next: 0 }
            };
            return Ok(true);
        }
        SchedulerPhase::Seeding { roots, next } => {
            executor.check_cancelled()?;
            if *next == roots.len() {
                cursor.phase = SchedulerPhase::Running;
                return Ok(true);
            }
            let (node_id, kind) = roots.get(*next).ok_or(RecoveryError::InvariantFailure)?;
            // The saved source descriptor must still identify the same Case node
            if executor
                .case
                .node(*node_id)
                .is_none_or(|node| node.kind != *kind)
            {
                return Err(RecoveryError::InvariantFailure.into());
            }
            executor.enqueue_root(*node_id, kind)?;
            *next += 1;
            return Ok(true);
        }
        SchedulerPhase::Running => {}
        SchedulerPhase::Finished => return Ok(false),
    }
    if frontier_step(
        executor,
        &mut cursor.evidence_stop,
        &mut cursor.evidence_stop_reported,
    )? {
        return Ok(true);
    }
    // Deferred cohort work can mutate the Case even when the frontier is empty
    executor.check_cancelled()?;
    if cursor.evidence_stop.is_some() {
        executor.report_incremental_metadata_omission()?;
        executor.omit_unsearched_incremental_cohorts()?;
        cursor.phase = SchedulerPhase::Finished;
        return Ok(false);
    }
    if executor.flush_transform_cohorts()? || executor.flush_derived_discovery()? {
        return Ok(true);
    }
    if !cursor.record_discovery_barrier_reached && executor.plan.discover_records {
        cursor.record_discovery_barrier_reached = true;
        executor.enqueue_record_discovery_if_enabled()?;
        if executor.coordinator.peek_next_id().is_some() {
            return Ok(true);
        }
    }
    if executor.flush_relational_cohorts(RelationalLane::Normal)?
        || executor.flush_pending_record_assemblies()?
        || executor.enqueue_deferred_record_discovery()?
    {
        return Ok(true);
    }
    // Deep work runs after normal recovery and its derived artifacts have drained
    executor.report_incremental_metadata_omission()?;
    if executor.flush_relational_cohorts(RelationalLane::Incremental)?
        || executor.enqueue_next_record_suffix()?
    {
        return Ok(true);
    }
    cursor.phase = SchedulerPhase::Finished;
    Ok(false)
}

pub(super) fn frontier_step(
    executor: &mut Executor<'_>,
    evidence_stop: &mut Option<evidence::CaseEvidenceStop>,
    evidence_stop_reported: &mut bool,
) -> Result<bool, RecoveryExecutionError> {
    // Check before admitting deferred work or removing the next candidate
    executor.check_cancelled()?;
    if evidence_stop.is_none()
        && !executor.pending_record_assemblies.is_empty()
        && !executor.next_candidate_precedes_deferred_assembly()
    {
        executor.flush_pending_record_assemblies()?;
    }
    let Some(candidate_id) = executor.coordinator.peek_next_id() else {
        return Ok(false);
    };
    if evidence_stop.is_none() {
        let task = executor
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
            .task();
        *evidence_stop = evidence::saturated_case_evidence(executor.case, task);
    }
    // Keep the candidate queued when cancellation arrives during progress setup
    if evidence_stop.is_none() {
        let candidate_task = executor
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
            .task();
        if let Some(progress) = &executor.job {
            progress.begin_candidate(candidate_task)?;
        }
    } else {
        executor.check_cancelled()?;
    }
    if executor.coordinator.pop_next()? != Some(candidate_id) {
        return Err(RecoveryError::InvariantFailure.into());
    }
    if let Some(stop) = *evidence_stop {
        executor.stop_candidate_for_case_evidence(candidate_id, stop, !*evidence_stop_reported)?;
        *evidence_stop_reported = true;
        record_candidate_progress(executor, candidate_id, executor.omissions.len())?;
        return Ok(true);
    }
    let omission_start = executor.omissions.len();
    if let Err(error) = executor.execute_candidate(candidate_id) {
        *evidence_stop = Some(executor.stop_after_case_evidence_error(candidate_id, error)?);
        *evidence_stop_reported = true;
        record_candidate_progress(executor, candidate_id, executor.omissions.len())?;
        return Ok(true);
    }
    record_candidate_progress(executor, candidate_id, omission_start)?;
    if let Some(stop) = evidence::recent_case_evidence_stop(
        executor
            .omissions
            .get(omission_start..)
            .ok_or(RecoveryError::InvariantFailure)?,
    ) {
        *evidence_stop = Some(stop);
        *evidence_stop_reported = true;
    }
    Ok(true)
}
