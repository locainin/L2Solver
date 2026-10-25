//! Coordinate bounded recovery tasks and their retained evidence contexts

mod candidate;
mod error;
mod identity;
mod lineage;
mod merge;
mod queue;
mod resources;

pub use error::RecoveryError;

use super::{
    RecoveryCandidate, RecoveryCandidateId, RecoveryResource, RecoveryResourcePolicy, case_refs,
};
use crate::evidence::{Case, CaseIdentity};
use identity::canonical_recipe_identity_bytes;
use std::collections::{HashMap, HashSet, VecDeque};

/// Deterministic FIFO coordinator for typed work over one retained Case
///
/// The first accepted enqueue binds the coordinator to that Case identity
///
/// A `Case::transaction` rollback does not roll back this coordinator
/// Commit Case evidence before updating the coordinator, or discard the coordinator
/// if the evidence transaction rolls back
pub struct RecoveryCoordinator {
    resources: RecoveryResourcePolicy,
    candidates: Vec<RecoveryCandidate>,
    frontier: VecDeque<RecoveryCandidateId>,
    identity_index: HashMap<(String, String, usize), Vec<RecoveryCandidateId>>,
    case_identity: Option<CaseIdentity>,
    work_bytes: usize,
    parent_links_retained: usize,
    lineage_work: usize,
    context_aliases_retained: usize,
    pending_origin_links_retained: usize,
    candidate_task_identity_bytes_retained: usize,
    transform_proposal_identity_bytes_retained: usize,
    transform_proposal_associations: HashSet<(u64, Vec<u8>)>,
}

impl RecoveryCoordinator {
    /// Create a coordinator with the exact caller-resolved budgets
    #[must_use]
    pub fn new(resources: RecoveryResourcePolicy) -> Self {
        Self {
            resources,
            candidates: Vec::new(),
            frontier: VecDeque::new(),
            identity_index: HashMap::new(),
            case_identity: None,
            work_bytes: 0,
            parent_links_retained: 0,
            lineage_work: 0,
            context_aliases_retained: 0,
            pending_origin_links_retained: 0,
            candidate_task_identity_bytes_retained: 0,
            transform_proposal_identity_bytes_retained: 0,
            transform_proposal_associations: HashSet::new(),
        }
    }

    /// Return the exact resource policy applied by this coordinator
    #[must_use]
    pub const fn resources(&self) -> RecoveryResourcePolicy {
        self.resources
    }

    /// Return the number of distinct candidate tasks retained
    #[must_use]
    pub const fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Return bytes charged against the shared work budget
    #[must_use]
    pub const fn work_bytes_charged(&self) -> usize {
        self.work_bytes
    }

    /// Return the unspent portion of the shared work byte budget
    #[must_use]
    pub const fn remaining_work_bytes(&self) -> usize {
        self.resources.max_work_bytes - self.work_bytes
    }

    /// Return the number of unique report-node and recipe associations retained globally
    #[must_use]
    pub fn transform_proposal_associations_charged(&self) -> usize {
        self.transform_proposal_associations.len()
    }

    /// Return the unspent portion of the global transform-proposal association budget
    #[must_use]
    pub fn remaining_transform_proposal_associations(&self) -> usize {
        self.resources.max_transform_proposal_associations
            - self.transform_proposal_associations.len()
    }

    /// Return serialized task-identity bytes retained across candidates
    #[must_use]
    pub const fn candidate_task_identity_bytes_charged(&self) -> usize {
        self.candidate_task_identity_bytes_retained
    }

    /// Return the unspent serialized task-identity byte budget
    #[must_use]
    pub const fn remaining_candidate_task_identity_bytes(&self) -> usize {
        self.resources.max_candidate_task_identity_bytes
            - self.candidate_task_identity_bytes_retained
    }

    /// Return canonical recipe-identity bytes retained for transform proposals
    #[must_use]
    pub const fn transform_proposal_identity_bytes_charged(&self) -> usize {
        self.transform_proposal_identity_bytes_retained
    }

    /// Return the unspent transform-proposal identity byte budget
    #[must_use]
    pub const fn remaining_transform_proposal_identity_bytes(&self) -> usize {
        self.resources.max_transform_proposal_identity_bytes
            - self.transform_proposal_identity_bytes_retained
    }

    /// Admit one unique proposal report-node and canonical-recipe association
    ///
    /// The report-node identifier remains part of the association identity. This resource
    /// counts associations, not evidence edges
    ///
    /// # Errors
    /// Returns an error when the canonical recipe identity cannot be encoded or storage cannot grow
    pub fn admit_transform_proposal_association(
        &mut self,
        report_node_id: u64,
        recipe: &crate::derivation::Recipe,
    ) -> Result<super::TransformProposalAssociationOutcome, RecoveryError> {
        use super::TransformProposalAssociationOutcome;

        let identity = canonical_recipe_identity_bytes(recipe)?;
        let identity_bytes = identity.len();
        let association = (report_node_id, identity);
        if self.transform_proposal_associations.contains(&association) {
            return Ok(TransformProposalAssociationOutcome::AlreadyRetained);
        }

        let used = self.transform_proposal_associations.len();
        let Some(charged) = used.checked_add(1) else {
            return Ok(TransformProposalAssociationOutcome::ResourceExhausted {
                resource: RecoveryResource::TransformProposalAssociations,
                limit: self.resources.max_transform_proposal_associations,
                used,
                requested: 1,
            });
        };
        if charged > self.resources.max_transform_proposal_associations {
            return Ok(TransformProposalAssociationOutcome::ResourceExhausted {
                resource: RecoveryResource::TransformProposalAssociations,
                limit: self.resources.max_transform_proposal_associations,
                used,
                requested: 1,
            });
        }

        let used_identity_bytes = self.transform_proposal_identity_bytes_retained;
        let Some(charged_identity_bytes) = used_identity_bytes.checked_add(identity_bytes) else {
            return Ok(TransformProposalAssociationOutcome::ResourceExhausted {
                resource: RecoveryResource::TransformProposalIdentityBytes,
                limit: self.resources.max_transform_proposal_identity_bytes,
                used: used_identity_bytes,
                requested: identity_bytes,
            });
        };
        if charged_identity_bytes > self.resources.max_transform_proposal_identity_bytes {
            return Ok(TransformProposalAssociationOutcome::ResourceExhausted {
                resource: RecoveryResource::TransformProposalIdentityBytes,
                limit: self.resources.max_transform_proposal_identity_bytes,
                used: used_identity_bytes,
                requested: identity_bytes,
            });
        }

        self.transform_proposal_associations
            .try_reserve(1)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        self.transform_proposal_associations.insert(association);
        self.transform_proposal_identity_bytes_retained = charged_identity_bytes;
        Ok(TransformProposalAssociationOutcome::Admitted)
    }

    /// Return the number of distinct derivation parent links retained globally
    #[must_use]
    pub const fn parent_links_retained(&self) -> usize {
        self.parent_links_retained
    }

    /// Return the number of retained input-position and origin-node references
    #[must_use]
    pub const fn context_aliases_retained(&self) -> usize {
        self.context_aliases_retained
    }

    /// Return pending direct result links retained for late candidate origins
    #[must_use]
    pub const fn pending_origin_links_retained(&self) -> usize {
        self.pending_origin_links_retained
    }

    /// Return candidate visits and parent-edge examinations charged globally
    #[must_use]
    pub const fn lineage_work_charged(&self) -> usize {
        self.lineage_work
    }

    /// Return the unspent portion of the shared lineage-work budget
    #[must_use]
    pub const fn remaining_lineage_work(&self) -> usize {
        self.resources.max_lineage_work - self.lineage_work
    }

    fn bind_case(&mut self, case: &Case) -> Result<(), RecoveryError> {
        let identity = case.identity();
        match &self.case_identity {
            Some(bound) if bound.identifies(case) => Ok(()),
            Some(_) => Err(RecoveryError::DifferentCase),
            None => {
                self.case_identity = Some(identity);
                Ok(())
            }
        }
    }

    fn ensure_case(&self, case: &Case) -> Result<(), RecoveryError> {
        self.case_identity
            .as_ref()
            .filter(|bound| bound.identifies(case))
            .map_or(Err(RecoveryError::DifferentCase), |_| Ok(()))
    }

    /// Return a candidate by its stable coordinator-local handle
    #[must_use]
    pub fn candidate(&self, id: RecoveryCandidateId) -> Option<&RecoveryCandidate> {
        self.candidates.get(id.index())
    }

    /// Resolve every ordered candidate input from the current evidence case
    ///
    /// The coordinator keeps identifiers only, so Case remains the sole byte store
    ///
    /// # Errors
    /// Returns an error when a candidate origin or blob reference is invalid
    pub fn input_blobs<'case>(
        &self,
        case: &'case Case,
        id: RecoveryCandidateId,
    ) -> Result<Vec<&'case crate::evidence::Blob>, RecoveryError> {
        let candidate = self
            .candidate(id)
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        self.ensure_case(case)?;
        let mut blobs = Vec::with_capacity(candidate.inputs().len());
        for input in candidate.inputs() {
            blobs.push(case_refs::input_blob(case, input)?);
        }
        Ok(blobs)
    }

    /// Resolve the retained blob for a single-input candidate
    ///
    /// # Errors
    /// Returns an error when the candidate is invalid or does not contain one input
    pub fn input_blob<'case>(
        &self,
        case: &'case Case,
        id: RecoveryCandidateId,
    ) -> Result<&'case crate::evidence::Blob, RecoveryError> {
        let candidate = self
            .candidate(id)
            .ok_or(RecoveryError::UnknownCandidate { id })?;
        let [input] = candidate.inputs() else {
            return Err(RecoveryError::MultipleInputs {
                id,
                input_count: candidate.inputs().len(),
            });
        };
        self.ensure_case(case)?;
        case_refs::input_blob(case, input)
    }
}
