use super::evidence::{TransactionEdges, add_transaction_edge, case_evidence_quota};
use super::scheduler::enqueue_candidate_id;
use super::{
    Executor, PROPOSED_BY_REASON, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask, edge_identity,
};
use l2_workbench::{
    derivation::Recipe,
    evidence::{Case, Edge, EvidenceStatus},
    recovery::{
        RecoveryCandidateState, RecoveryError, RecoveryResource, RecoveryResult,
        TransformProposalAssociationOutcome,
        proposals::{
            TRANSFORM_PROPOSAL_FORMAT_VERSION, TRANSFORM_PROPOSAL_OPERATION_COUNT,
            TransformProposalBudget, TransformProposalReport, propose_transforms,
            transform_proposal_scan_work_bound,
        },
    },
};
use serde::Serialize;
use serde_json::json;
use std::{collections::HashSet, hash::Hash};

const REPORT_KIND: &str = "recovery_transform_proposal_report";
const REPORT_VERSION: u16 = TRANSFORM_PROPOSAL_FORMAT_VERSION;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_proposal_link_quota.rs"]
mod proposal_link_quota_tests;

pub(super) fn add_transform_proposal_edges(
    case: &mut Case,
    edge_identities: &mut TransactionEdges<'_>,
    transform_receipt: u64,
    proposal_receipts: &[u64],
) -> Result<(), RecoveryExecutionError> {
    for proposal_receipt in proposal_receipts {
        add_transaction_edge(
            case,
            edge_identities,
            Edge {
                from: transform_receipt,
                to: *proposal_receipt,
                relation: "proposed_by".to_owned(),
                status: EvidenceStatus::Unresolved,
                reason: PROPOSED_BY_REASON.to_owned(),
            },
        )?;
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct TransformDiscoveryState {
    contexts: OrderedUnique<TransformDiscoveryContext>,
    report_node: Option<u64>,
    recipes: Vec<Recipe>,
}

/// Keep first-seen values in order while using a hash set for membership checks
pub(super) struct OrderedUnique<T> {
    ordered: Vec<T>,
    membership: HashSet<T>,
}

impl<T> Default for OrderedUnique<T> {
    fn default() -> Self {
        Self {
            ordered: Vec::new(),
            membership: HashSet::new(),
        }
    }
}

impl<T: Eq + Hash + Clone> OrderedUnique<T> {
    pub(super) fn contains(&self, value: &T) -> bool {
        self.membership.contains(value)
    }

    pub(super) fn try_insert(
        &mut self,
        value: T,
    ) -> Result<bool, std::collections::TryReserveError> {
        if self.membership.contains(&value) {
            return Ok(false);
        }

        self.ordered.try_reserve(1)?;
        self.membership.try_reserve(1)?;
        if !self.membership.insert(value.clone()) {
            return Ok(false);
        }
        self.ordered.push(value);
        Ok(true)
    }

    pub(super) fn as_slice(&self) -> &[T] {
        &self.ordered
    }
}

/// Track the committed receipt prefix for one terminal transform receipt
#[derive(Default)]
pub(super) struct OrderedProposalReceipts {
    receipts: OrderedUnique<u64>,
    linked_transform_receipt: Option<u64>,
    linked_count: usize,
    blocked_link: Option<BlockedProposalLink>,
}

#[derive(Clone, Copy)]
struct BlockedProposalLink {
    transform_receipt: u64,
    omission_index: usize,
}

impl OrderedProposalReceipts {
    pub(super) fn try_insert(
        &mut self,
        receipt: u64,
    ) -> Result<bool, std::collections::TryReserveError> {
        self.receipts.try_insert(receipt)
    }

    pub(super) fn pending_for(&self, transform_receipt: u64) -> Option<&[u64]> {
        let linked_count = if self.linked_transform_receipt == Some(transform_receipt) {
            self.linked_count
        } else {
            0
        };
        self.receipts.as_slice().get(linked_count..)
    }

    pub(super) fn mark_linked(&mut self, transform_receipt: u64) {
        self.linked_transform_receipt = Some(transform_receipt);
        self.linked_count = self.receipts.as_slice().len();
    }

    fn blocked_omission_index(&self, transform_receipt: u64) -> Option<usize> {
        self.blocked_link
            .filter(|blocked| blocked.transform_receipt == transform_receipt)
            .map(|blocked| blocked.omission_index)
    }

    const fn mark_blocked(&mut self, transform_receipt: u64, omission_index: usize) {
        self.blocked_link = Some(BlockedProposalLink {
            transform_receipt,
            omission_index,
        });
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct TransformDiscoveryContext {
    byte_parent: Option<RecoveryCandidateId>,
    input_node: u64,
}

#[derive(Serialize)]
struct TransformProposalReceipt<'a> {
    version: u16,
    input: TransformProposalInput<'a>,
    scan: TransformProposalScan,
    proposal_budget: TransformProposalBudget,
    proposal_report: &'a TransformProposalReport,
}

#[derive(Serialize)]
struct TransformProposalInput<'a> {
    node_id: u64,
    blob_id: &'a str,
    byte_length: usize,
}

#[derive(Serialize)]
struct TransformProposalScan {
    operation_count: usize,
    work_bytes_charged: usize,
}

impl Executor<'_> {
    pub(super) fn register_transform_discovery_context(
        &mut self,
        candidate_id: RecoveryCandidateId,
        byte_parent: Option<RecoveryCandidateId>,
        input_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let context = TransformDiscoveryContext {
            byte_parent,
            input_node,
        };
        let completed = {
            if !self.transform_discoveries.contains_key(&candidate_id) {
                self.transform_discoveries
                    .try_reserve(1)
                    .map_err(|source| RecoveryExecutionError::Operational {
                        stage: RecoveryStage::TransformDiscovery,
                        source: Box::new(source),
                    })?;
            }
            let state = self.transform_discoveries.entry(candidate_id).or_default();
            let inserted = state.contexts.try_insert(context).map_err(|source| {
                RecoveryExecutionError::Operational {
                    stage: RecoveryStage::TransformDiscovery,
                    source: Box::new(source),
                }
            })?;
            if !inserted {
                return Ok(());
            }
            state
                .report_node
                .map(|report_node| (report_node, state.recipes.clone()))
        };
        if let Some((report_node, recipes)) = completed {
            self.enqueue_proposals_for_context(context, report_node, &recipes)?;
        }
        Ok(())
    }

    pub(super) fn run_transform_discovery(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        input_length: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let scan_work_bytes =
            transform_proposal_scan_work_bound(input_length).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "transform proposal scan work cannot be represented".to_owned(),
                )
            })?;
        let scan_limit = self
            .policy
            .transform_exploration
            .max_scan_work_bytes_per_input;
        if scan_work_bytes > scan_limit {
            return self.finish_scan_work_limit(
                candidate_id,
                input_node,
                scan_limit,
                scan_work_bytes,
            );
        }

        let task = RecoveryTask::TransformDiscovery;
        if !self.charge_work(candidate_id, &task, &[input_node], scan_work_bytes)? {
            return Ok(());
        }

        let (input_blob_id, proposal_report) =
            self.assess_transform_input(candidate_id, input_length)?;
        self.record_transform_discovery_omissions(input_node, &proposal_report);
        // An empty retained list is negative only when no eligible recipe was budgeted out
        if self.finish_complete_negative_transform_search(candidate_id, &proposal_report)? {
            return Ok(());
        }

        let report_bytes = serialize_transform_proposal_report(
            input_node,
            input_length,
            scan_work_bytes,
            &input_blob_id,
            &proposal_report,
            self.policy.transform_exploration.proposal_budget,
        )?;
        let proposal_count = proposal_report.proposals.len();
        let assessment_count = proposal_report.assessments.len();
        let Some(report_node) = self.retain_transform_proposal_report(
            candidate_id,
            input_node,
            &report_bytes,
            json!({
                "version":REPORT_VERSION,
                "input_node_id":input_node,
                "input_blob_id":input_blob_id,
                "assessment_count":assessment_count,
                "proposal_count":proposal_count,
                "candidate_omissions":proposal_report.omissions.candidates,
                "report_omissions":proposal_report.omissions.reports
            }),
        )?
        else {
            return Ok(());
        };
        let recipes = proposal_report
            .proposals
            .into_iter()
            .map(|proposal| proposal.recipe)
            .collect::<Vec<_>>();
        // The report order defines the retained prefix when the shared budget fills
        let recipes = self.admit_proposal_prefix(report_node, input_node, &recipes)?;
        let contexts = {
            let state = self
                .transform_discoveries
                .get_mut(&candidate_id)
                .ok_or(RecoveryError::InvariantFailure)?;
            if state.report_node.replace(report_node).is_some() {
                return Err(RecoveryError::InvariantFailure.into());
            }
            state.recipes.clone_from(&recipes);
            state.contexts.as_slice().to_vec()
        };
        for context in contexts {
            self.enqueue_proposals_for_context(context, report_node, &recipes)?;
        }
        Ok(())
    }

    fn record_transform_discovery_omissions(
        &mut self,
        input_node: u64,
        proposal_report: &TransformProposalReport,
    ) {
        if proposal_report.omissions.candidates != 0 || proposal_report.omissions.reports != 0 {
            self.omissions
                .push(RecoveryOmission::TransformDiscoveryAnalysis {
                    input_node_id: input_node,
                    omitted_candidates: proposal_report.omissions.candidates,
                    omitted_reports: proposal_report.omissions.reports,
                });
        }
    }

    fn finish_complete_negative_transform_search(
        &mut self,
        candidate_id: RecoveryCandidateId,
        proposal_report: &TransformProposalReport,
    ) -> Result<bool, RecoveryExecutionError> {
        if !proposal_report.proposals.is_empty() || proposal_report.omissions.candidates != 0 {
            return Ok(false);
        }
        self.complete_negative_transform_searches = self
            .complete_negative_transform_searches
            .checked_add(1)
            .ok_or(RecoveryError::InvariantFailure)?;
        self.finish(candidate_id, RecoveryResult::Unsupported)?;
        Ok(true)
    }

    fn retain_transform_proposal_report(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        report_bytes: &[u8],
        details: serde_json::Value,
    ) -> Result<Option<u64>, RecoveryExecutionError> {
        let requested_details_bytes = serde_json::to_vec(&details)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::TransformDiscovery,
                source: Box::new(source),
            })?
            .len();
        match self.receipt_node_bytes_and_finish(
            candidate_id,
            REPORT_KIND,
            report_bytes,
            details,
            |node_id| RecoveryResult::Hypothesis { node_id },
        ) {
            Ok(node_id) => Ok(Some(node_id)),
            Err(RecoveryExecutionError::Evidence(error)) => {
                let Some((resource, limit, used)) = case_evidence_quota(self.case, &error) else {
                    return Err(RecoveryExecutionError::Evidence(error));
                };
                let requested = match resource {
                    RecoveryResource::EvidenceEdges => self
                        .coordinator
                        .candidate(candidate_id)
                        .and_then(|candidate| candidate.inputs().first())
                        .ok_or(RecoveryError::InvariantFailure)?
                        .origin_node_ids()
                        .len(),
                    RecoveryResource::EvidenceBlobBytes => report_bytes.len(),
                    RecoveryResource::EvidenceTotalDetailsBytes => requested_details_bytes,
                    RecoveryResource::EvidenceBlobs | RecoveryResource::EvidenceNodes => 1,
                    RecoveryResource::EvidenceSourceRanges
                    | RecoveryResource::EvidenceLimitations => 0,
                    _ => return Err(RecoveryExecutionError::Evidence(error)),
                };
                self.finish_case_quota(candidate_id, input_node, resource, limit, used, requested)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn assess_transform_input(
        &self,
        candidate_id: RecoveryCandidateId,
        input_length: usize,
    ) -> Result<(String, TransformProposalReport), RecoveryExecutionError> {
        let input = self.coordinator.input_blob(self.case, candidate_id)?;
        if input.bytes.len() != input_length {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let report = propose_transforms(
            &input.bytes,
            self.policy.transform_exploration.proposal_budget,
        );
        Ok((input.id.clone(), report))
    }

    pub(super) fn link_transform_proposals(
        &mut self,
        candidate_id: RecoveryCandidateId,
        transform_receipt: u64,
    ) -> Result<(), RecoveryExecutionError> {
        if self
            .transform_proposal_receipts
            .get(&candidate_id)
            .is_some_and(|receipts| receipts.blocked_omission_index(transform_receipt).is_some())
        {
            return Ok(());
        }

        let Some(receipts) = self.unlinked_proposal_receipts(candidate_id, transform_receipt)?
        else {
            return Ok(());
        };
        if receipts.is_empty() {
            self.transform_proposal_receipts
                .get_mut(&candidate_id)
                .ok_or(RecoveryError::InvariantFailure)?
                .mark_linked(transform_receipt);
            return Ok(());
        }

        let requested = receipts.len();
        match self.case_transaction(|case, identities| {
            add_transform_proposal_edges(case, identities, transform_receipt, &receipts)
        }) {
            Ok(()) => {
                self.transform_proposal_receipts
                    .get_mut(&candidate_id)
                    .ok_or(RecoveryError::InvariantFailure)?
                    .mark_linked(transform_receipt);
                Ok(())
            }
            Err(RecoveryExecutionError::Evidence(error)) => {
                let Some((RecoveryResource::EvidenceEdges, limit, used)) =
                    case_evidence_quota(self.case, &error)
                else {
                    return Err(RecoveryExecutionError::Evidence(error));
                };
                let candidate = self
                    .coordinator
                    .candidate(candidate_id)
                    .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
                let task = candidate.task().clone();
                let input_node_ids = candidate
                    .inputs()
                    .iter()
                    .flat_map(|input| input.origin_node_ids().iter().copied())
                    .collect();
                let resource = RecoveryResource::EvidenceEdges;
                let omission_index = self.omissions.len();
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task,
                    input_node_ids,
                    resource,
                    limit,
                    used,
                    requested,
                });
                self.transform_proposal_receipts
                    .get_mut(&candidate_id)
                    .ok_or(RecoveryError::InvariantFailure)?
                    .mark_blocked(transform_receipt, omission_index);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn unlinked_proposal_receipts(
        &mut self,
        candidate_id: RecoveryCandidateId,
        transform_receipt: u64,
    ) -> Result<Option<Vec<u64>>, RecoveryExecutionError> {
        let pending_receipt_count =
            self.transform_proposal_receipts
                .get(&candidate_id)
                .map_or(Ok(0), |receipts| {
                    receipts
                        .pending_for(transform_receipt)
                        .map(<[u64]>::len)
                        .ok_or(RecoveryError::InvariantFailure)
                })?;
        if pending_receipt_count == 0 {
            return Ok(None);
        }

        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(pending_receipt_count)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::TransformDiscovery,
                source: Box::new(source),
            })?;
        let registered = self
            .transform_proposal_receipts
            .get(&candidate_id)
            .ok_or(RecoveryError::InvariantFailure)?;
        receipts.extend_from_slice(
            registered
                .pending_for(transform_receipt)
                .ok_or(RecoveryError::InvariantFailure)?,
        );
        self.refresh_case_index()?;
        receipts.retain(|proposal_receipt| {
            let identity = edge_identity(
                transform_receipt,
                *proposal_receipt,
                "proposed_by",
                EvidenceStatus::Unresolved,
                PROPOSED_BY_REASON,
            );
            !self.case_index.edge_identities.contains(&identity)
        });
        Ok(Some(receipts))
    }

    fn finish_scan_work_limit(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        limit: usize,
        work_bytes: usize,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions.push(RecoveryOmission::StageWorkLimit {
            task: RecoveryTask::TransformDiscovery,
            input_node_ids: vec![input_node],
            limit,
            work_bytes,
        });
        self.finish(candidate_id, RecoveryResult::Omitted)
    }

    fn finish_case_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    ) -> Result<(), RecoveryExecutionError> {
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            },
        )?;
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::TransformDiscovery,
            input_node_ids: vec![input_node],
            resource,
            limit,
            used,
            requested,
        });
        Ok(())
    }

    fn enqueue_proposals_for_context(
        &mut self,
        context: TransformDiscoveryContext,
        report_node: u64,
        recipes: &[Recipe],
    ) -> Result<(), RecoveryExecutionError> {
        for (index, recipe) in recipes.iter().enumerate() {
            // Reuse each retained report pair when a context arrives after discovery
            match self
                .coordinator
                .admit_transform_proposal_association(report_node, recipe)?
            {
                TransformProposalAssociationOutcome::Admitted
                | TransformProposalAssociationOutcome::AlreadyRetained => {}
                TransformProposalAssociationOutcome::ResourceExhausted {
                    limit,
                    used,
                    requested,
                    ..
                } => {
                    self.omissions
                        .push(RecoveryOmission::TransformProposalAssociations {
                            report_node_id: report_node,
                            input_node_id: context.input_node,
                            used,
                            limit,
                            requested,
                            omitted_count: recipes.len() - index,
                        });
                    break;
                }
            }
            let task = RecoveryTask::Transform(recipe.clone());
            let result = match context.byte_parent {
                Some(parent_id) => self.coordinator.enqueue_derived(
                    parent_id,
                    self.case,
                    &[context.input_node],
                    task.clone(),
                )?,
                None => self
                    .coordinator
                    .enqueue(self.case, context.input_node, task.clone())?,
            };
            let candidate_id = enqueue_candidate_id(&result);
            self.record_enqueue(result, &task, &[context.input_node])?;
            if let Some(candidate_id) = candidate_id {
                self.associate_proposal(candidate_id, report_node)?;
            }
        }
        Ok(())
    }

    fn admit_proposal_prefix(
        &mut self,
        report_node: u64,
        input_node: u64,
        recipes: &[Recipe],
    ) -> Result<Vec<Recipe>, RecoveryExecutionError> {
        let mut admitted = Vec::new();
        admitted
            .try_reserve_exact(recipes.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::TransformDiscovery,
                source: Box::new(source),
            })?;

        for (index, recipe) in recipes.iter().enumerate() {
            match self
                .coordinator
                .admit_transform_proposal_association(report_node, recipe)?
            {
                TransformProposalAssociationOutcome::Admitted
                | TransformProposalAssociationOutcome::AlreadyRetained => {
                    admitted.push(recipe.clone());
                }
                TransformProposalAssociationOutcome::ResourceExhausted {
                    limit,
                    used,
                    requested,
                    ..
                } => {
                    self.omissions
                        .push(RecoveryOmission::TransformProposalAssociations {
                            report_node_id: report_node,
                            input_node_id: input_node,
                            used,
                            limit,
                            requested,
                            omitted_count: recipes.len() - index,
                        });
                    break;
                }
            }
        }
        Ok(admitted)
    }

    fn associate_proposal(
        &mut self,
        candidate_id: RecoveryCandidateId,
        proposal_receipt: u64,
    ) -> Result<(), RecoveryExecutionError> {
        if !self.transform_proposal_receipts.contains_key(&candidate_id) {
            self.transform_proposal_receipts
                .try_reserve(1)
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::TransformDiscovery,
                    source: Box::new(source),
                })?;
        }
        let receipts = self
            .transform_proposal_receipts
            .entry(candidate_id)
            .or_default();
        let inserted = receipts.try_insert(proposal_receipt).map_err(|source| {
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::TransformDiscovery,
                source: Box::new(source),
            }
        })?;
        if !inserted {
            return Ok(());
        }
        let transform_receipt = self
            .coordinator
            .candidate(candidate_id)
            .and_then(|candidate| match candidate.state() {
                RecoveryCandidateState::Finished { result, .. }
                | RecoveryCandidateState::ContextPending { result, .. } => match result {
                    RecoveryResult::Derived { evidence_node_id }
                    | RecoveryResult::Rejected {
                        node_id: evidence_node_id,
                    } => Some(*evidence_node_id),
                    RecoveryResult::ObservedValidation { .. }
                    | RecoveryResult::Hypothesis { .. }
                    | RecoveryResult::Unsupported
                    | RecoveryResult::Omitted
                    | RecoveryResult::ResourceExhausted { .. } => None,
                },
                RecoveryCandidateState::Queued | RecoveryCandidateState::Running(_) => None,
            });
        if let Some(transform_receipt) = transform_receipt {
            let blocked_omission_index = self
                .transform_proposal_receipts
                .get(&candidate_id)
                .and_then(|receipts| receipts.blocked_omission_index(transform_receipt));
            if let Some(omission_index) = blocked_omission_index {
                let identity = edge_identity(
                    transform_receipt,
                    proposal_receipt,
                    "proposed_by",
                    EvidenceStatus::Unresolved,
                    PROPOSED_BY_REASON,
                );
                if !self.case_index.edge_identities.contains(&identity) {
                    self.extend_proposal_link_omission(omission_index)?;
                }
                return Ok(());
            }
            self.link_transform_proposals(candidate_id, transform_receipt)?;
        }
        Ok(())
    }

    fn extend_proposal_link_omission(
        &mut self,
        omission_index: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let omission = self
            .omissions
            .get_mut(omission_index)
            .ok_or(RecoveryError::InvariantFailure)?;
        let RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(_),
            resource: RecoveryResource::EvidenceEdges,
            requested,
            ..
        } = omission
        else {
            return Err(RecoveryError::InvariantFailure.into());
        };
        *requested = requested
            .checked_add(1)
            .ok_or(RecoveryError::InvariantFailure)?;
        Ok(())
    }
}

fn serialize_transform_proposal_report(
    input_node: u64,
    input_length: usize,
    scan_work_bytes: usize,
    input_blob_id: &str,
    proposal_report: &TransformProposalReport,
    proposal_budget: TransformProposalBudget,
) -> Result<Vec<u8>, RecoveryExecutionError> {
    serde_json::to_vec(&TransformProposalReceipt {
        version: REPORT_VERSION,
        input: TransformProposalInput {
            node_id: input_node,
            blob_id: input_blob_id,
            byte_length: input_length,
        },
        scan: TransformProposalScan {
            operation_count: TRANSFORM_PROPOSAL_OPERATION_COUNT,
            work_bytes_charged: scan_work_bytes,
        },
        proposal_budget,
        proposal_report,
    })
    .map_err(|source| RecoveryExecutionError::Operational {
        stage: RecoveryStage::TransformDiscovery,
        source: Box::new(source),
    })
}
