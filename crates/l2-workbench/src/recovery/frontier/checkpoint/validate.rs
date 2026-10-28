//! Rebuild derived indexes after validating restored evidence and resource state

use super::super::super::{
    RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState, RecoveryInput, RecoveryResult,
};
use super::super::{
    RecoveryCoordinator, RecoveryError, case_refs,
    identity::{candidate_identity, same_task_identity, task_has_origin_context},
    queue::result_allowed_at,
};
use super::format::{Candidate, Checkpoint, Input};
use super::secrets;
use crate::evidence::{Case, EvidenceStatus};
use std::collections::HashSet;

pub(super) fn restore(
    case: &Case,
    checkpoint: Checkpoint,
) -> Result<RecoveryCoordinator, RecoveryError> {
    let mut coordinator = RecoveryCoordinator::new(checkpoint.resources);
    coordinator.work_bytes = checkpoint.work_bytes;
    coordinator.lineage_work = checkpoint.lineage_work;
    coordinator
        .candidates
        .try_reserve_exact(checkpoint.candidates.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    coordinator
        .identity_index
        .try_reserve(checkpoint.candidates.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    for saved in checkpoint.candidates {
        restore_candidate(case, &mut coordinator, saved)?;
    }
    validate_parents(case, &coordinator)?;
    let mut queued = HashSet::new();
    queued
        .try_reserve(checkpoint.frontier.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    coordinator
        .frontier
        .try_reserve(checkpoint.frontier.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    for id in checkpoint.frontier {
        let candidate = coordinator
            .candidate(id)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        if candidate.state != RecoveryCandidateState::Queued || !queued.insert(id) {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        coordinator.frontier.push_back(id);
    }
    if coordinator
        .candidates
        .iter()
        .enumerate()
        .any(|(index, candidate)| {
            (candidate.state == RecoveryCandidateState::Queued)
                != queued.contains(&RecoveryCandidateId(index))
        })
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    coordinator
        .transform_proposal_associations
        .try_reserve(checkpoint.associations.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    for association in checkpoint.associations {
        if case.node(association.report_node_id).is_none() {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        let identity = association.identity.get().as_bytes();
        secrets::validate_association(identity)?;
        coordinator.transform_proposal_identity_bytes_retained = add_bounded(
            coordinator.transform_proposal_identity_bytes_retained,
            identity.len(),
            coordinator.resources.max_transform_proposal_identity_bytes,
        )?;
        let mut retained_identity = Vec::new();
        retained_identity
            .try_reserve_exact(identity.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        retained_identity.extend_from_slice(identity);
        if !coordinator
            .transform_proposal_associations
            .insert((association.report_node_id, retained_identity))
        {
            return Err(RecoveryError::InvalidCheckpoint);
        }
    }
    if !coordinator.candidates.is_empty() {
        coordinator.case_identity = Some(case.identity());
    }
    Ok(coordinator)
}

fn restore_candidate(
    case: &Case,
    coordinator: &mut RecoveryCoordinator,
    saved: Candidate,
) -> Result<(), RecoveryError> {
    secrets::validate_task(&saved.task)?;
    if saved.inputs.is_empty()
        || saved.inputs.len() > coordinator.resources.max_inputs_per_candidate
        || saved.depth > coordinator.resources.max_depth
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    let (inputs, origins) = restore_inputs(case, coordinator, saved.inputs)?;
    let parent_set = unique_set(&saved.parent_ids)?;
    coordinator.parent_links_retained = add_bounded(
        coordinator.parent_links_retained,
        saved.parent_ids.len(),
        coordinator.resources.max_parent_links,
    )?;
    let pending_set = unique_set(&saved.pending_origin_node_ids)?;
    if !pending_set.is_subset(&origins) {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    coordinator.pending_origin_links_retained = add_bounded(
        coordinator.pending_origin_links_retained,
        pending_set.len(),
        coordinator.resources.max_pending_origin_links,
    )?;
    let candidate = RecoveryCandidate {
        inputs,
        task: saved.task,
        depth: saved.depth,
        parent_ids: saved.parent_ids,
        parent_id_set: parent_set,
        origin_node_ids: origins,
        pending_origin_node_ids: saved.pending_origin_node_ids,
        completion_priority: saved.completion_priority,
        state: saved.state,
    };
    validate_state(case, &candidate, &pending_set)?;
    retain_candidate(case, coordinator, candidate)
}

fn restore_inputs(
    case: &Case,
    coordinator: &mut RecoveryCoordinator,
    saved_inputs: Vec<Input>,
) -> Result<(Vec<RecoveryInput>, HashSet<u64>), RecoveryError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(saved_inputs.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    let mut origins = HashSet::new();
    let mut total_input_bytes = 0_usize;
    for saved in saved_inputs {
        let origin_set = unique_set(&saved.origin_node_ids)?;
        if origin_set.is_empty() {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        let input = RecoveryInput {
            blob_id: saved.blob_id,
            origin_node_ids: saved.origin_node_ids,
            origin_node_id_set: origin_set,
        };
        let blob =
            case_refs::input_blob(case, &input).map_err(|_| RecoveryError::InvalidCheckpoint)?;
        if blob.bytes.len() > coordinator.resources.max_input_bytes_per_item {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        total_input_bytes = add_bounded(
            total_input_bytes,
            blob.bytes.len(),
            coordinator.resources.max_total_input_bytes_per_candidate,
        )?;
        coordinator.context_aliases_retained = add_bounded(
            coordinator.context_aliases_retained,
            input.origin_node_ids.len(),
            coordinator.resources.max_context_aliases,
        )?;
        origins
            .try_reserve(input.origin_node_ids.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        origins.extend(input.origin_node_ids.iter().copied());
        inputs.push(input);
    }
    if origins.len() > coordinator.resources.max_origins_per_candidate {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    Ok((inputs, origins))
}

fn unique_set<T: Copy + Eq + std::hash::Hash>(entries: &[T]) -> Result<HashSet<T>, RecoveryError> {
    let mut values = HashSet::new();
    values
        .try_reserve(entries.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    values.extend(entries.iter().copied());
    if values.len() != entries.len() {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    Ok(values)
}

fn retain_candidate(
    case: &Case,
    coordinator: &mut RecoveryCoordinator,
    candidate: RecoveryCandidate,
) -> Result<(), RecoveryError> {
    let identity = candidate_identity(&candidate.inputs, &candidate.task, candidate.depth)
        .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    coordinator.candidate_task_identity_bytes_retained = add_bounded(
        coordinator.candidate_task_identity_bytes_retained,
        identity.task_identity_bytes,
        coordinator.resources.max_candidate_task_identity_bytes,
    )?;
    if let Some(ids) = coordinator.identity_index.get(&identity.key) {
        let mut blobs = Vec::new();
        blobs
            .try_reserve_exact(candidate.inputs.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for input in &candidate.inputs {
            blobs.push(
                case_refs::input_blob(case, input).map_err(|_| RecoveryError::InvalidCheckpoint)?,
            );
        }
        for id in ids {
            let previous = coordinator
                .candidate(*id)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
            if same_task_identity(&previous.task, &candidate.task)
                && (!task_has_origin_context(&candidate.task)
                    || case_refs::same_origin_context(&previous.inputs, &candidate.inputs))
                && case_refs::same_input_bytes(case, &previous.inputs, &blobs)
            {
                return Err(RecoveryError::InvalidCheckpoint);
            }
        }
    }
    let id = RecoveryCandidateId(coordinator.candidates.len());
    let ids = coordinator.identity_index.entry(identity.key).or_default();
    ids.try_reserve(1)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    ids.push(id);
    coordinator.candidates.push(candidate);
    Ok(())
}

fn validate_state(
    case: &Case,
    candidate: &RecoveryCandidate,
    pending: &HashSet<u64>,
) -> Result<(), RecoveryError> {
    let (stage, result, is_pending) = match &candidate.state {
        RecoveryCandidateState::Queued => {
            if !pending.is_empty() {
                return Err(RecoveryError::InvalidCheckpoint);
            }
            return Ok(());
        }
        RecoveryCandidateState::Running(_) => {
            return Err(RecoveryError::CheckpointRunningCandidate);
        }
        RecoveryCandidateState::Finished { stage, result } => (*stage, result, false),
        RecoveryCandidateState::ContextPending { stage, result } => (*stage, result, true),
    };
    if stage != candidate.task.stage()
        || !result_allowed_at(stage, &candidate.task, result)
        || (is_pending && (pending.is_empty() || result.evidence_link_contract().is_none()))
        || (!is_pending && !pending.is_empty())
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    let missing = case_refs::missing_result_origins(case, &candidate.inputs, result)
        .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    // Links may have appeared after the pending list was last refreshed
    if missing.iter().any(|origin| !pending.contains(origin)) {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    Ok(())
}

fn validate_parents(case: &Case, coordinator: &RecoveryCoordinator) -> Result<(), RecoveryError> {
    for candidate in &coordinator.candidates {
        for parent_id in &candidate.parent_ids {
            let parent = coordinator
                .candidate(*parent_id)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
            let result = match &parent.state {
                RecoveryCandidateState::Finished { result, .. }
                | RecoveryCandidateState::ContextPending { result, .. } => result,
                RecoveryCandidateState::Queued | RecoveryCandidateState::Running(_) => {
                    return Err(RecoveryError::InvalidCheckpoint);
                }
            };
            let (node, relation, depth) = match result {
                RecoveryResult::Derived { evidence_node_id } => (
                    *evidence_node_id,
                    "derived_from",
                    parent.depth.checked_add(1),
                ),
                RecoveryResult::ObservedValidation { node_id } => {
                    (*node_id, "validated_range", Some(parent.depth))
                }
                RecoveryResult::Hypothesis { .. }
                | RecoveryResult::Rejected { .. }
                | RecoveryResult::Unsupported
                | RecoveryResult::Omitted
                | RecoveryResult::ResourceExhausted { .. } => {
                    return Err(RecoveryError::InvalidCheckpoint);
                }
            };
            if depth != Some(candidate.depth)
                || !candidate
                    .origin_node_ids
                    .iter()
                    .any(|origin| case.has_edge(*origin, node, relation, EvidenceStatus::Observed))
            {
                return Err(RecoveryError::InvalidCheckpoint);
            }
        }
    }
    Ok(())
}

fn add_bounded(used: usize, amount: usize, limit: usize) -> Result<usize, RecoveryError> {
    used.checked_add(amount)
        .filter(|total| *total <= limit)
        .ok_or(RecoveryError::InvalidCheckpoint)
}
