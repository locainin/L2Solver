//! Reject inconsistent saved references before any resumed operation runs

use super::super::{Executor, RecoveryCandidateId, RecoveryError, RecoveryTask};

pub(super) fn executor(executor: &Executor<'_>) -> Result<(), RecoveryError> {
    let coordinator = &executor.coordinator;
    if (executor.snapshot_candidates
        && executor.candidate_ids.len() != coordinator.candidate_count())
        || (!executor.snapshot_candidates && !executor.candidate_ids.is_empty())
        || executor.record_phase_work_charged > executor.policy.record_phase_work_limit
        || executor.record_schema_associations_charged
            > executor.policy.resources.max_pending_origin_links
        || executor
            .validated_artifacts
            .iter()
            .any(|id| executor.case.blob(id).is_none())
        || executor
            .record_discovery_context_by_report
            .keys()
            .any(|id| executor.case.node(*id).is_none())
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    let task_matches = |id: &RecoveryCandidateId, check: fn(&RecoveryTask) -> bool| {
        coordinator
            .candidate(*id)
            .is_some_and(|candidate| check(candidate.task()))
    };
    if !executor
        .transform_discoveries
        .keys()
        .all(|id| task_matches(id, |task| matches!(task, RecoveryTask::TransformDiscovery)))
        || !executor.framing_selection_bases.keys().all(|id| {
            task_matches(id, |task| {
                matches!(task, RecoveryTask::MaterializeFraming(_))
            })
        })
        || !executor
            .framing_discoveries
            .keys()
            .all(|id| task_matches(id, |task| matches!(task, RecoveryTask::FramingDiscovery)))
        || !executor
            .record_discoveries
            .keys()
            .all(|id| task_matches(id, |task| matches!(task, RecoveryTask::RecordDiscovery)))
        || !executor
            .record_schema_report_links
            .keys()
            .all(|id| task_matches(id, |task| matches!(task, RecoveryTask::AssembleRecords(_))))
        || !executor.relational_discoveries.keys().all(|id| {
            task_matches(id, |task| {
                matches!(
                    task,
                    RecoveryTask::RelationalTransformDiscovery
                        | RecoveryTask::RelationalTransformDiscoveryIncremental
                )
            })
        })
        || !executor
            .transform_proposal_receipts
            .keys()
            .all(|id| task_matches(id, |task| matches!(task, RecoveryTask::Transform(_))))
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    for suffix in &executor.pending_record_suffixes {
        if executor
            .record_discoveries
            .get(&suffix.candidate_id)
            .is_none_or(|contexts| suffix.context_index >= contexts.len())
        {
            return Err(RecoveryError::InvalidCheckpoint);
        }
    }
    Ok(())
}
