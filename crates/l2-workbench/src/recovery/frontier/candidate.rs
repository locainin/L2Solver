//! Retain candidate results and reuse compatible evidence contexts

use super::super::case_refs;
use super::super::{
    EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState, RecoveryInput,
    RecoveryResource, RecoveryTask,
};
use super::identity::{CandidateIdentity, same_task_identity, task_has_origin_context};
use super::lineage::LineageSearchOutcome;
use super::merge::CandidateMergeOutcome;
use super::resources::{context_alias_count, distinct_origin_count};
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;
use std::collections::HashSet;

impl RecoveryCoordinator {
    pub(super) fn reuse_or_skip(
        &mut self,
        case: &Case,
        identity: &CandidateIdentity,
        prepared: &case_refs::PreparedInputs<'_>,
        task: &RecoveryTask,
        derivation_parents: &[RecoveryCandidateId],
    ) -> Result<Option<EnqueueOutcome>, RecoveryError> {
        let work_identity = (identity.key.0.clone(), identity.key.1.clone());
        let existing =
            self.find_candidate(case, &identity.key, task, &prepared.inputs, &prepared.blobs)?;
        if let Some(id) = existing {
            if let Some(exhausted) = self.origin_exhaustion(id, &prepared.inputs)? {
                return Ok(Some(exhausted));
            }
            if let Some(exhausted) = self.parent_link_exhaustion(id, derivation_parents)? {
                return Ok(Some(exhausted));
            }
            return Ok(Some(
                match self.merge_candidate(id, &prepared.inputs, case, derivation_parents)? {
                    CandidateMergeOutcome::Merged(true) => EnqueueOutcome::MergedNeedsContext(id),
                    CandidateMergeOutcome::Merged(false) => EnqueueOutcome::Merged(id),
                    CandidateMergeOutcome::Exhausted(outcome) => outcome,
                },
            ));
        }
        // Exact reuse above may need to retain late evidence context even at capacity
        if self.candidates.len() >= self.resources.max_candidates {
            return Ok(Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::CandidateCount,
                limit: self.resources.max_candidates,
                used: self.candidates.len(),
                requested: 1,
            }));
        }
        if let Some(exhausted) =
            self.candidate_task_identity_exhaustion(identity.task_identity_bytes)
        {
            return Ok(Some(exhausted));
        }
        let ancestor = match self.cycle_ancestor(
            case,
            derivation_parents,
            &work_identity,
            task,
            &prepared.inputs,
            &prepared.blobs,
        )? {
            LineageSearchOutcome::NoAncestor => None,
            LineageSearchOutcome::Ancestor(id) => Some(id),
            LineageSearchOutcome::Exhausted(outcome) => return Ok(Some(outcome)),
        };
        if let Some(ancestor_id) = ancestor {
            if let Some(exhausted) = self.origin_exhaustion(ancestor_id, &prepared.inputs)? {
                return Ok(Some(exhausted));
            }
            return Ok(Some(
                match self.merge_candidate(ancestor_id, &prepared.inputs, case, &[])? {
                    CandidateMergeOutcome::Merged(_) => EnqueueOutcome::CycleSkipped {
                        candidate_id: ancestor_id,
                    },
                    CandidateMergeOutcome::Exhausted(outcome) => outcome,
                },
            ));
        }
        Ok(None)
    }

    pub(super) fn enqueue_new(
        &mut self,
        prepared: case_refs::PreparedInputs<'_>,
        task: RecoveryTask,
        identity: CandidateIdentity,
        derivation_parents: &[RecoveryCandidateId],
    ) -> Result<EnqueueOutcome, RecoveryError> {
        let requested_origins = distinct_origin_count(&prepared.inputs);
        if let Some(exhausted) = self.candidate_retention_exhaustion(
            &prepared.inputs,
            requested_origins,
            identity.task_identity_bytes,
            derivation_parents.len(),
        )? {
            return Ok(exhausted);
        }
        let requested_aliases = context_alias_count(&prepared.inputs)?;
        let charged_task_identity_bytes = self
            .candidate_task_identity_bytes_retained
            .checked_add(identity.task_identity_bytes)
            .ok_or(RecoveryError::InvariantFailure)?;
        let charged_parent_links = self
            .parent_links_retained
            .checked_add(derivation_parents.len())
            .ok_or(RecoveryError::InvariantFailure)?;
        let charged_context_aliases = self
            .context_aliases_retained
            .checked_add(requested_aliases)
            .ok_or(RecoveryError::InvariantFailure)?;
        let id = RecoveryCandidateId(self.candidates.len());
        let candidate = prepare_candidate(
            prepared.inputs,
            task,
            identity.key.2,
            derivation_parents,
            requested_origins,
        )?;
        let new_identity_ids = self.reserve_candidate_storage(&identity.key)?;
        self.retain_candidate(id, identity.key, candidate, new_identity_ids)?;
        self.parent_links_retained = charged_parent_links;
        self.context_aliases_retained = charged_context_aliases;
        self.candidate_task_identity_bytes_retained = charged_task_identity_bytes;
        Ok(EnqueueOutcome::Queued(id))
    }

    fn reserve_candidate_storage(
        &mut self,
        identity: &(String, String, usize),
    ) -> Result<Option<Vec<RecoveryCandidateId>>, RecoveryError> {
        self.candidates
            .try_reserve(1)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        self.frontier
            .try_reserve(1)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        self.identity_index
            .try_reserve(1)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        if let Some(existing) = self.identity_index.get_mut(identity) {
            existing
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            return Ok(None);
        }
        let mut new_ids = Vec::new();
        new_ids
            .try_reserve_exact(1)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        Ok(Some(new_ids))
    }

    fn retain_candidate(
        &mut self,
        id: RecoveryCandidateId,
        identity: (String, String, usize),
        candidate: RecoveryCandidate,
        new_identity_ids: Option<Vec<RecoveryCandidateId>>,
    ) -> Result<(), RecoveryError> {
        if let Some(mut ids) = new_identity_ids {
            ids.push(id);
            self.identity_index.insert(identity, ids);
        } else if let Some(ids) = self.identity_index.get_mut(&identity) {
            ids.push(id);
        } else {
            return Err(RecoveryError::InvariantFailure);
        }
        self.candidates.push(candidate);
        self.frontier.push_back(id);
        Ok(())
    }

    fn find_candidate(
        &self,
        case: &Case,
        identity: &(String, String, usize),
        task: &RecoveryTask,
        inputs: &[RecoveryInput],
        blobs: &[&crate::evidence::Blob],
    ) -> Result<Option<RecoveryCandidateId>, RecoveryError> {
        let Some(matches) = self.identity_index.get(identity) else {
            return Ok(None);
        };
        for id in matches {
            let candidate = self.candidate(*id).ok_or(RecoveryError::InvariantFailure)?;
            if same_task_identity(candidate.task(), task)
                && (!task_has_origin_context(task)
                    || case_refs::same_origin_context(candidate.inputs(), inputs))
                && case_refs::same_input_bytes(case, candidate.inputs(), blobs)
            {
                return Ok(Some(*id));
            }
        }
        Ok(None)
    }
}

fn prepare_candidate(
    inputs: Vec<RecoveryInput>,
    task: RecoveryTask,
    depth: usize,
    derivation_parents: &[RecoveryCandidateId],
    requested_origins: usize,
) -> Result<RecoveryCandidate, RecoveryError> {
    let mut parent_ids = Vec::new();
    parent_ids
        .try_reserve_exact(derivation_parents.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    parent_ids.extend_from_slice(derivation_parents);

    let mut parent_id_set = HashSet::new();
    parent_id_set
        .try_reserve(derivation_parents.len())
        .map_err(|_| RecoveryError::AllocationFailed)?;
    parent_id_set.extend(parent_ids.iter().copied());

    let mut origin_node_ids = HashSet::new();
    origin_node_ids
        .try_reserve(requested_origins)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    origin_node_ids.extend(
        inputs
            .iter()
            .flat_map(|input| input.origin_node_ids.iter().copied()),
    );

    Ok(RecoveryCandidate {
        inputs,
        task,
        depth,
        parent_ids,
        parent_id_set,
        origin_node_ids,
        pending_origin_node_ids: Vec::new(),
        state: RecoveryCandidateState::Queued,
    })
}
