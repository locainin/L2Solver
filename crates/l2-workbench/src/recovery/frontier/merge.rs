//! Prepare and commit candidate context merges within declared resource limits

use super::super::case_refs;
use super::super::{
    EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState, RecoveryInput,
    RecoveryResource, RecoveryResult, RecoveryStage,
};
use super::resources::added_context_alias_count;
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;

pub(super) enum CandidateMergeOutcome {
    Merged(bool),
    Exhausted(EnqueueOutcome),
}

struct TerminalMerge {
    stage: RecoveryStage,
    result: RecoveryResult,
    new_missing_origins: Vec<u64>,
}

struct PreparedCandidateMerge {
    terminal: Option<TerminalMerge>,
    new_parent_links: usize,
}

impl RecoveryCoordinator {
    pub(super) fn merge_candidate(
        &mut self,
        id: RecoveryCandidateId,
        inputs: &[RecoveryInput],
        case: &Case,
        derivation_parents: &[RecoveryCandidateId],
    ) -> Result<CandidateMergeOutcome, RecoveryError> {
        let candidate = self.candidate(id).ok_or(RecoveryError::InvariantFailure)?;
        let prepared = prepare_candidate_merge(candidate, inputs, derivation_parents, case)?;
        let requested_aliases = added_context_alias_count(candidate.inputs(), inputs)?;
        let remaining_aliases = self
            .resources
            .max_context_aliases
            .checked_sub(self.context_aliases_retained)
            .ok_or(RecoveryError::InvariantFailure)?;
        if requested_aliases > remaining_aliases {
            return Ok(CandidateMergeOutcome::Exhausted(
                EnqueueOutcome::ResourceExhausted {
                    resource: RecoveryResource::ContextAliases,
                    limit: self.resources.max_context_aliases,
                    used: self.context_aliases_retained,
                    requested: requested_aliases,
                },
            ));
        }
        let pending_before = candidate.pending_origin_node_ids.len();
        let new_pending_origins = prepared
            .terminal
            .as_ref()
            .map_or(0, |terminal| terminal.new_missing_origins.len());
        let pending_after = pending_before
            .checked_add(new_pending_origins)
            .ok_or(RecoveryError::AllocationFailed)?;
        let remaining_pending = self
            .resources
            .max_pending_origin_links
            .checked_sub(self.pending_origin_links_retained)
            .ok_or(RecoveryError::InvariantFailure)?;
        if new_pending_origins > remaining_pending {
            return Ok(CandidateMergeOutcome::Exhausted(
                EnqueueOutcome::ResourceExhausted {
                    resource: RecoveryResource::PendingOriginLinks,
                    limit: self.resources.max_pending_origin_links,
                    used: self.pending_origin_links_retained,
                    requested: new_pending_origins,
                },
            ));
        }
        let pending_retained_after = self
            .pending_origin_links_retained
            .checked_sub(pending_before)
            .and_then(|used| used.checked_add(pending_after))
            .ok_or(RecoveryError::InvariantFailure)?;

        let (requires_context, inserted_parent_links) = {
            let candidate = self
                .candidates
                .get_mut(id.index())
                .ok_or(RecoveryError::InvariantFailure)?;
            reserve_candidate_merge(
                candidate,
                inputs,
                prepared.new_parent_links,
                new_pending_origins,
            )?;
            commit_candidate_merge(candidate, inputs, derivation_parents, prepared)
        };
        self.context_aliases_retained += requested_aliases;
        self.pending_origin_links_retained = pending_retained_after;
        self.parent_links_retained += inserted_parent_links;
        Ok(CandidateMergeOutcome::Merged(requires_context))
    }
}

fn prepare_candidate_merge(
    candidate: &RecoveryCandidate,
    inputs: &[RecoveryInput],
    derivation_parents: &[RecoveryCandidateId],
    case: &Case,
) -> Result<PreparedCandidateMerge, RecoveryError> {
    if candidate.inputs.len() != inputs.len() {
        return Err(RecoveryError::InvariantFailure);
    }
    let terminal = match &candidate.state {
        RecoveryCandidateState::Finished { stage, result }
        | RecoveryCandidateState::ContextPending { stage, result } => {
            let new_missing_origins = case_refs::missing_result_origins_after_merge(
                case,
                &candidate.origin_node_ids,
                inputs,
                result,
            )?;
            Some(TerminalMerge {
                stage: *stage,
                result: result.clone(),
                new_missing_origins,
            })
        }
        RecoveryCandidateState::Queued | RecoveryCandidateState::Running(_) => None,
    };
    let new_parent_links = derivation_parents
        .iter()
        .filter(|parent_id| !candidate.parent_id_set.contains(parent_id))
        .count();
    Ok(PreparedCandidateMerge {
        terminal,
        new_parent_links,
    })
}

fn reserve_candidate_merge(
    candidate: &mut RecoveryCandidate,
    inputs: &[RecoveryInput],
    new_parent_links: usize,
    new_pending_origins: usize,
) -> Result<(), RecoveryError> {
    let incoming_origin_count = inputs
        .iter()
        .try_fold(0_usize, |total, input| {
            total.checked_add(input.origin_node_ids.len())
        })
        .ok_or(RecoveryError::AllocationFailed)?;
    candidate
        .origin_node_ids
        .try_reserve(incoming_origin_count)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    candidate
        .parent_ids
        .try_reserve(new_parent_links)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    candidate
        .parent_id_set
        .try_reserve(new_parent_links)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    candidate
        .pending_origin_node_ids
        .try_reserve(new_pending_origins)
        .map_err(|_| RecoveryError::AllocationFailed)?;

    for (existing, incoming) in candidate.inputs.iter_mut().zip(inputs) {
        let new_origins = incoming
            .origin_node_ids
            .iter()
            .filter(|origin| !existing.origin_node_id_set.contains(origin))
            .count();
        existing
            .origin_node_ids
            .try_reserve(new_origins)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        existing
            .origin_node_id_set
            .try_reserve(new_origins)
            .map_err(|_| RecoveryError::AllocationFailed)?;
    }
    Ok(())
}

fn commit_candidate_merge(
    candidate: &mut RecoveryCandidate,
    inputs: &[RecoveryInput],
    derivation_parents: &[RecoveryCandidateId],
    prepared: PreparedCandidateMerge,
) -> (bool, usize) {
    for (existing, incoming) in candidate.inputs.iter_mut().zip(inputs) {
        for origin in &incoming.origin_node_ids {
            if existing.origin_node_id_set.insert(*origin) {
                existing.origin_node_ids.push(*origin);
            }
            candidate.origin_node_ids.insert(*origin);
        }
    }
    let mut inserted_parent_links = 0;
    for parent_id in derivation_parents {
        if candidate.parent_id_set.insert(*parent_id) {
            candidate.parent_ids.push(*parent_id);
            inserted_parent_links += 1;
        }
    }
    let Some(terminal) = prepared.terminal else {
        return (false, inserted_parent_links);
    };
    candidate
        .pending_origin_node_ids
        .extend(terminal.new_missing_origins);
    let requires_context = !candidate.pending_origin_node_ids.is_empty();
    candidate.state = if requires_context {
        RecoveryCandidateState::ContextPending {
            stage: terminal.stage,
            result: terminal.result,
        }
    } else {
        RecoveryCandidateState::Finished {
            stage: terminal.stage,
            result: terminal.result,
        }
    };
    (requires_context, inserted_parent_links)
}
