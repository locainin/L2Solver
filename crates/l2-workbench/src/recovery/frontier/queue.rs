//! Admit recovery work and dispatch candidates in deterministic order

use super::super::case_refs::{self, InputPreparation};
use super::super::{
    EnqueueOutcome, RecoveryCandidateId, RecoveryCandidateState, RecoveryResource, RecoveryResult,
    RecoveryStage, RecoveryTask,
};
use super::identity::candidate_identity;
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;
use std::collections::HashSet;

struct EnqueueAtDepth<'a> {
    case: &'a Case,
    node_ids: &'a [u64],
    task: RecoveryTask,
    depth: Option<usize>,
    parent_depth: Option<usize>,
    derivation_parents: &'a [RecoveryCandidateId],
    origin_aliases: &'a [Vec<u64>],
}

impl RecoveryCoordinator {
    /// Add one typed task from a retained evidence node at root depth
    ///
    /// # Errors
    /// Returns an error when the source node or its retained blob is invalid
    pub fn enqueue(
        &mut self,
        case: &Case,
        node_id: u64,
        task: RecoveryTask,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        self.enqueue_nodes(case, &[node_id], task)
    }

    /// Add one typed task from an ordered batch of retained nodes at root depth
    ///
    /// # Errors
    /// Returns an error for an empty batch or an invalid source node
    pub fn enqueue_nodes(
        &mut self,
        case: &Case,
        node_ids: &[u64],
        task: RecoveryTask,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        self.enqueue_at_depth(case, node_ids, task, Some(0), None, &[])
    }

    /// Add one task from children linked to a parent's retained derivation receipt
    ///
    /// Work from a different depth keeps a separate candidate identity
    ///
    /// # Errors
    /// Returns an error when the parent, child evidence, or derivation links are invalid
    pub fn enqueue_derived(
        &mut self,
        parent_id: RecoveryCandidateId,
        case: &Case,
        node_ids: &[u64],
        task: RecoveryTask,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        self.ensure_case(case)?;
        let parent = self
            .candidate(parent_id)
            .ok_or(RecoveryError::UnknownCandidate { id: parent_id })?;
        let RecoveryCandidateState::Finished {
            result: RecoveryResult::Derived { evidence_node_id },
            ..
        } = parent.state()
        else {
            return Err(RecoveryError::ParentNotDerived { id: parent_id });
        };
        if let Some(outcome) = case_refs::input_count_exhaustion(node_ids.len(), self.resources) {
            return Ok(outcome);
        }
        let parent_result_node_id = *evidence_node_id;
        let parent_depth = parent.depth();
        let _ = case_refs::evidence_blob(case, parent_result_node_id)?;
        case_refs::validate_derived_inputs(case, parent_id, parent_result_node_id, node_ids)?;
        let depth = parent_depth.checked_add(1);
        self.enqueue_at_depth(
            case,
            node_ids,
            task,
            depth,
            Some(parent_depth),
            &[parent_id],
        )
    }

    /// Add one task from exact bytes established by a structural validation parent
    ///
    /// Validation keeps the artifact at its current depth; derivation and expansion advance it
    /// Equivalent same-blob origins remain context for that exact byte input
    ///
    /// # Errors
    /// Returns an error when the parent is not a completed validation or an exact-byte link is
    /// missing
    pub fn enqueue_validated(
        &mut self,
        parent_id: RecoveryCandidateId,
        case: &Case,
        node_ids: &[u64],
        task: RecoveryTask,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        self.ensure_case(case)?;
        let parent = self
            .candidate(parent_id)
            .ok_or(RecoveryError::UnknownCandidate { id: parent_id })?;
        let RecoveryCandidateState::Finished {
            result: RecoveryResult::ObservedValidation { node_id },
            ..
        } = parent.state()
        else {
            return Err(RecoveryError::ParentNotValidated { id: parent_id });
        };
        if let Some(outcome) = case_refs::input_count_exhaustion(node_ids.len(), self.resources) {
            return Ok(outcome);
        }
        let validation_node_id = *node_id;
        let parent_depth = parent.depth();
        case_refs::validate_validated_inputs(case, parent_id, validation_node_id, node_ids)?;
        let origin_aliases = case_refs::validated_origin_aliases(
            case,
            parent_id,
            parent.inputs(),
            validation_node_id,
            node_ids,
        )?;
        self.enqueue_at_depth_with_aliases(EnqueueAtDepth {
            case,
            node_ids,
            task,
            depth: Some(parent_depth),
            parent_depth: Some(parent_depth),
            derivation_parents: &[parent_id],
            origin_aliases: &origin_aliases,
        })
    }

    /// Add one task from ordered children of equally deep derivation candidates
    ///
    /// Every pair keeps its own immediate receipt while the input order is retained
    ///
    /// # Errors
    /// Returns an error when parents or child edges do not form one exact derivation batch
    pub fn enqueue_derived_many(
        &mut self,
        case: &Case,
        parent_child_pairs: &[(RecoveryCandidateId, u64)],
        task: RecoveryTask,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        if parent_child_pairs.is_empty() {
            return Err(RecoveryError::EmptyInputBatch);
        }
        self.ensure_case(case)?;
        if let Some(outcome) =
            case_refs::input_count_exhaustion(parent_child_pairs.len(), self.resources)
        {
            return Ok(outcome);
        }
        let mut parent_ids = Vec::new();
        parent_ids
            .try_reserve_exact(parent_child_pairs.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        let mut parent_id_set = HashSet::new();
        parent_id_set
            .try_reserve(parent_child_pairs.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        let mut child_node_ids = Vec::new();
        child_node_ids
            .try_reserve_exact(parent_child_pairs.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        let mut parent_depth = None;
        for (parent_id, child_node_id) in parent_child_pairs {
            let parent = self
                .candidate(*parent_id)
                .ok_or(RecoveryError::UnknownCandidate { id: *parent_id })?;
            let RecoveryCandidateState::Finished {
                result: RecoveryResult::Derived { evidence_node_id },
                ..
            } = parent.state()
            else {
                return Err(RecoveryError::ParentNotDerived { id: *parent_id });
            };
            match parent_depth {
                Some(first) if first != parent.depth() => {
                    return Err(RecoveryError::ParentDepthMismatch {
                        first,
                        second: parent.depth(),
                    });
                }
                None => parent_depth = Some(parent.depth()),
                Some(_) => {}
            }
            let _ = case_refs::evidence_blob(case, *evidence_node_id)?;
            case_refs::validate_derived_inputs(
                case,
                *parent_id,
                *evidence_node_id,
                &[*child_node_id],
            )?;
            child_node_ids.push(*child_node_id);
            if parent_id_set.insert(*parent_id) {
                parent_ids.push(*parent_id);
            }
        }
        let parent_depth = parent_depth.ok_or(RecoveryError::EmptyInputBatch)?;
        self.enqueue_at_depth(
            case,
            &child_node_ids,
            task,
            parent_depth.checked_add(1),
            Some(parent_depth),
            &parent_ids,
        )
    }

    fn enqueue_at_depth(
        &mut self,
        case: &Case,
        node_ids: &[u64],
        task: RecoveryTask,
        depth: Option<usize>,
        parent_depth: Option<usize>,
        derivation_parents: &[RecoveryCandidateId],
    ) -> Result<EnqueueOutcome, RecoveryError> {
        self.enqueue_at_depth_with_aliases(EnqueueAtDepth {
            case,
            node_ids,
            task,
            depth,
            parent_depth,
            derivation_parents,
            origin_aliases: &[],
        })
    }

    fn enqueue_at_depth_with_aliases(
        &mut self,
        request: EnqueueAtDepth<'_>,
    ) -> Result<EnqueueOutcome, RecoveryError> {
        let EnqueueAtDepth {
            case,
            node_ids,
            task,
            depth,
            parent_depth,
            derivation_parents,
            origin_aliases,
        } = request;
        let prepared = match case_refs::prepare_inputs(case, node_ids, self.resources)? {
            InputPreparation::Ready(prepared) => prepared,
            InputPreparation::Exhausted(outcome) => return Ok(outcome),
        };
        let mut prepared = prepared;
        if !origin_aliases.is_empty() {
            case_refs::append_input_origin_aliases(case, &mut prepared.inputs, origin_aliases)?;
        }
        let Some(depth) = depth.filter(|value| *value <= self.resources.max_depth) else {
            return Ok(self.depth_exhausted(parent_depth));
        };
        if self.case_identity.is_some() {
            self.ensure_case(case)?;
        }
        let identity = candidate_identity(&prepared.inputs, &task, depth)?;
        if let Some(outcome) =
            self.reuse_or_skip(case, &identity, &prepared, &task, derivation_parents)?
        {
            return Ok(outcome);
        }
        let outcome = self.enqueue_new(prepared, task, identity, derivation_parents)?;
        if matches!(outcome, EnqueueOutcome::Queued(_)) {
            self.bind_case(case)?;
        }
        Ok(outcome)
    }

    fn depth_exhausted(&self, parent_depth: Option<usize>) -> EnqueueOutcome {
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::RecursionDepth,
            limit: self.resources.max_depth,
            used: parent_depth.unwrap_or(0),
            requested: 1,
        }
    }

    /// Move the oldest queued candidate into its task stage
    ///
    /// # Errors
    /// Returns an error if the queued handle or its state violates an invariant
    pub fn pop_next(&mut self) -> Result<Option<RecoveryCandidateId>, RecoveryError> {
        let Some(id) = self.frontier.front().copied() else {
            return Ok(None);
        };
        let candidate = self
            .candidates
            .get_mut(id.index())
            .ok_or(RecoveryError::InvariantFailure)?;
        if candidate.state != RecoveryCandidateState::Queued {
            return Err(RecoveryError::InvariantFailure);
        }
        candidate.state = RecoveryCandidateState::Running(candidate.task.stage());
        self.frontier.pop_front();
        Ok(Some(id))
    }

    /// Finish a running candidate with an explicit evidence or execution result
    ///
    /// # Errors
    /// Returns an error when the candidate is not running, the stage is invalid, or
    /// result evidence is unlinked from any input origin
    pub fn finish(
        &mut self,
        case: &Case,
        id: RecoveryCandidateId,
        result: RecoveryResult,
    ) -> Result<(), RecoveryError> {
        self.ensure_case(case)?;
        let candidate = self
            .candidates
            .get(id.index())
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        let RecoveryCandidateState::Running(stage) = candidate.state else {
            return Err(RecoveryError::CandidateNotRunning { id });
        };
        if !result_allowed_at(stage, &result) {
            return Err(RecoveryError::InvalidResultStage);
        }
        let inputs = candidate.inputs.clone();
        case_refs::validate_result_node(case, id, &inputs, &result)?;
        let candidate = self
            .candidates
            .get_mut(id.index())
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        candidate.pending_origin_node_ids.clear();
        candidate.state = RecoveryCandidateState::Finished { stage, result };
        Ok(())
    }
}

fn result_allowed_at(stage: RecoveryStage, result: &RecoveryResult) -> bool {
    match result {
        RecoveryResult::ObservedValidation { .. } => stage == RecoveryStage::StructuralValidation,
        RecoveryResult::Derived { .. } => matches!(
            stage,
            RecoveryStage::Transform
                | RecoveryStage::MaterializeFraming
                | RecoveryStage::AssembleRecords
                | RecoveryStage::EmbeddedDiscovery
                | RecoveryStage::RecursiveExpansion
        ),
        RecoveryResult::Hypothesis { .. }
        | RecoveryResult::Rejected { .. }
        | RecoveryResult::Unsupported
        | RecoveryResult::Omitted
        | RecoveryResult::ResourceExhausted { .. } => true,
    }
}
