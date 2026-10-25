//! Check and charge shared recovery budgets before retaining work

use super::super::case_refs;
use super::super::{
    BudgetCheck, ContextRegistration, EnqueueOutcome, RecoveryCandidateId, RecoveryCandidateState,
    RecoveryInput, RecoveryResource, RecoveryResult, RecoveryStage,
};
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;
use std::collections::HashSet;

impl RecoveryCoordinator {
    pub(super) fn candidate_task_identity_exhaustion(
        &self,
        requested: usize,
    ) -> Option<EnqueueOutcome> {
        let used = self.candidate_task_identity_bytes_retained;
        let Some(charged) = used.checked_add(requested) else {
            return Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::CandidateTaskIdentityBytes,
                limit: self.resources.max_candidate_task_identity_bytes,
                used,
                requested,
            });
        };
        (charged > self.resources.max_candidate_task_identity_bytes).then_some(
            EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::CandidateTaskIdentityBytes,
                limit: self.resources.max_candidate_task_identity_bytes,
                used,
                requested,
            },
        )
    }

    pub(super) fn candidate_retention_exhaustion(
        &self,
        inputs: &[RecoveryInput],
        requested_origins: usize,
        task_identity_bytes: usize,
        requested_parent_links: usize,
    ) -> Result<Option<EnqueueOutcome>, RecoveryError> {
        if requested_origins > self.resources.max_origins_per_candidate {
            return Ok(Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::OriginCount,
                limit: self.resources.max_origins_per_candidate,
                used: 0,
                requested: requested_origins,
            }));
        }
        let requested_aliases = context_alias_count(inputs)?;
        let remaining_aliases = self
            .resources
            .max_context_aliases
            .checked_sub(self.context_aliases_retained)
            .ok_or(RecoveryError::InvariantFailure)?;
        if requested_aliases > remaining_aliases {
            return Ok(Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::ContextAliases,
                limit: self.resources.max_context_aliases,
                used: self.context_aliases_retained,
                requested: requested_aliases,
            }));
        }
        if self.frontier.len() >= self.resources.max_frontier {
            return Ok(Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::FrontierCount,
                limit: self.resources.max_frontier,
                used: self.frontier.len(),
                requested: 1,
            }));
        }
        if let Some(exhausted) = self.candidate_task_identity_exhaustion(task_identity_bytes) {
            return Ok(Some(exhausted));
        }
        Ok(self.parent_link_capacity_exhaustion(requested_parent_links))
    }

    pub(super) fn origin_exhaustion(
        &self,
        id: RecoveryCandidateId,
        inputs: &[RecoveryInput],
    ) -> Result<Option<EnqueueOutcome>, RecoveryError> {
        let candidate = self.candidate(id).ok_or(RecoveryError::InvariantFailure)?;
        let requested = inputs
            .iter()
            .flat_map(|input| input.origin_node_ids.iter())
            .filter(|origin| !candidate.origin_node_ids.contains(origin))
            .copied()
            .collect::<HashSet<_>>()
            .len();
        let used = candidate.origin_node_ids.len();
        if requested > self.resources.max_origins_per_candidate - used {
            Ok(Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::OriginCount,
                limit: self.resources.max_origins_per_candidate,
                used,
                requested,
            }))
        } else {
            Ok(None)
        }
    }

    pub(super) fn parent_link_exhaustion(
        &self,
        id: RecoveryCandidateId,
        parent_ids: &[RecoveryCandidateId],
    ) -> Result<Option<EnqueueOutcome>, RecoveryError> {
        let candidate = self.candidate(id).ok_or(RecoveryError::InvariantFailure)?;
        let requested = parent_ids
            .iter()
            .filter(|parent_id| !candidate.parent_id_set.contains(parent_id))
            .count();
        Ok(self.parent_link_capacity_exhaustion(requested))
    }

    pub(super) fn parent_link_capacity_exhaustion(
        &self,
        requested: usize,
    ) -> Option<EnqueueOutcome> {
        let remaining = self.resources.max_parent_links - self.parent_links_retained;
        (requested > remaining).then_some(EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::ParentLinks,
            limit: self.resources.max_parent_links,
            used: self.parent_links_retained,
            requested,
        })
    }

    /// Verify late origin links and complete a candidate's terminal context
    ///
    /// # Errors
    /// Returns an error when the candidate has no pending result context
    pub fn refresh_context(
        &mut self,
        case: &Case,
        id: RecoveryCandidateId,
    ) -> Result<ContextRegistration, RecoveryError> {
        self.ensure_case(case)?;
        let candidate = self
            .candidates
            .get(id.index())
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        let RecoveryCandidateState::ContextPending { stage, result } = &candidate.state else {
            return Err(RecoveryError::ContextNotPending { id });
        };
        let stage = *stage;
        let result = result.clone();
        let inputs = candidate.inputs.clone();
        let pending_before = candidate.pending_origin_node_ids.len();
        let missing = case_refs::missing_result_origins(case, &inputs, &result)?;
        let pending_after = missing.len();
        let requested = pending_after.saturating_sub(pending_before);
        let remaining = self
            .resources
            .max_pending_origin_links
            .checked_sub(self.pending_origin_links_retained)
            .ok_or(RecoveryError::InvariantFailure)?;
        if requested > remaining {
            return Ok(ContextRegistration::ResourceExhausted {
                resource: RecoveryResource::PendingOriginLinks,
                limit: self.resources.max_pending_origin_links,
                used: self.pending_origin_links_retained,
                requested,
            });
        }
        let pending_retained_after = self
            .pending_origin_links_retained
            .checked_sub(pending_before)
            .and_then(|used| used.checked_add(pending_after))
            .ok_or(RecoveryError::InvariantFailure)?;
        let candidate = self
            .candidates
            .get_mut(id.index())
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        candidate.pending_origin_node_ids = missing;
        self.pending_origin_links_retained = pending_retained_after;
        if candidate.pending_origin_node_ids.is_empty() {
            candidate.state = RecoveryCandidateState::Finished { stage, result };
            Ok(ContextRegistration::Complete)
        } else {
            Ok(ContextRegistration::Pending {
                origins: candidate.pending_origin_node_ids.len(),
            })
        }
    }

    /// Charge actual or planned work against the coordinator-wide work budget
    ///
    /// # Errors
    /// Returns an error when the candidate is not running or its handle is invalid
    pub fn charge_work(
        &mut self,
        id: RecoveryCandidateId,
        requested: usize,
    ) -> Result<BudgetCheck, RecoveryError> {
        let stage = self.running_stage(id)?;
        let remaining = self.remaining_work_bytes();
        if requested > remaining {
            self.finish_after_budget(
                id,
                stage,
                RecoveryResource::WorkBytes,
                self.resources.max_work_bytes,
                self.work_bytes,
                requested,
            )?;
            return Ok(BudgetCheck::Exhausted {
                resource: RecoveryResource::WorkBytes,
                limit: self.resources.max_work_bytes,
                used: self.work_bytes,
                requested,
            });
        }
        self.work_bytes += requested;
        Ok(BudgetCheck::WithinBudget)
    }

    /// Charge work that belongs to the Case scan rather than one candidate
    #[must_use]
    pub const fn charge_case_work(&mut self, requested: usize) -> BudgetCheck {
        let remaining = self.remaining_work_bytes();
        if requested > remaining {
            return BudgetCheck::Exhausted {
                resource: RecoveryResource::WorkBytes,
                limit: self.resources.max_work_bytes,
                used: self.work_bytes,
                requested,
            };
        }
        self.work_bytes += requested;
        BudgetCheck::WithinBudget
    }

    /// Check one output length against the same explicit policy used by executors
    ///
    /// # Errors
    /// Returns an error when the candidate is not running or its handle is invalid
    pub fn check_output(
        &mut self,
        id: RecoveryCandidateId,
        requested: usize,
    ) -> Result<BudgetCheck, RecoveryError> {
        let stage = self.running_stage(id)?;
        if requested > self.resources.max_output_bytes {
            self.finish_after_budget(
                id,
                stage,
                RecoveryResource::OutputBytes,
                self.resources.max_output_bytes,
                0,
                requested,
            )?;
            return Ok(BudgetCheck::Exhausted {
                resource: RecoveryResource::OutputBytes,
                limit: self.resources.max_output_bytes,
                used: 0,
                requested,
            });
        }
        Ok(BudgetCheck::WithinBudget)
    }

    fn running_stage(&self, id: RecoveryCandidateId) -> Result<RecoveryStage, RecoveryError> {
        let candidate = self
            .candidate(id)
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        match candidate.state() {
            RecoveryCandidateState::Running(stage) => Ok(*stage),
            RecoveryCandidateState::Queued
            | RecoveryCandidateState::Finished { .. }
            | RecoveryCandidateState::ContextPending { .. } => {
                Err(RecoveryError::CandidateNotRunning { id })
            }
        }
    }

    fn finish_after_budget(
        &mut self,
        id: RecoveryCandidateId,
        stage: RecoveryStage,
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    ) -> Result<(), RecoveryError> {
        let candidate = self
            .candidates
            .get_mut(id.index())
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        if candidate.state != RecoveryCandidateState::Running(stage) {
            return Err(RecoveryError::CandidateNotRunning { id });
        }
        candidate.state = RecoveryCandidateState::Finished {
            stage,
            result: RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            },
        };
        Ok(())
    }
}

pub(super) fn distinct_origin_count(inputs: &[RecoveryInput]) -> usize {
    inputs
        .iter()
        .flat_map(|input| input.origin_node_ids.iter().copied())
        .collect::<HashSet<_>>()
        .len()
}

pub(super) fn context_alias_count(inputs: &[RecoveryInput]) -> Result<usize, RecoveryError> {
    inputs
        .iter()
        .try_fold(0_usize, |total, input| {
            total.checked_add(input.origin_node_ids.len())
        })
        .ok_or(RecoveryError::AllocationFailed)
}

pub(super) fn added_context_alias_count(
    current_inputs: &[RecoveryInput],
    incoming_inputs: &[RecoveryInput],
) -> Result<usize, RecoveryError> {
    if current_inputs.len() != incoming_inputs.len() {
        return Err(RecoveryError::InvariantFailure);
    }
    current_inputs
        .iter()
        .zip(incoming_inputs)
        .try_fold(0_usize, |total, (current, incoming)| {
            let added = incoming
                .origin_node_ids
                .iter()
                .filter(|origin| !current.origin_node_id_set.contains(origin))
                .count();
            total.checked_add(added)
        })
        .ok_or(RecoveryError::AllocationFailed)
}
