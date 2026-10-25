use super::{
    DERIVED_REASON, Executor, RESULT_REASON, RecoveryCandidateId, RecoveryExecutionError,
    RecoveryOmission, RecoveryTask, edge_identity,
};
use l2_workbench::{
    evidence::{
        Case, Edge, EvidenceError, EvidenceStatus, MAX_BLOBS, MAX_EDGES, MAX_LIMITATIONS,
        MAX_NODES, MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES,
    },
    recovery::{
        BudgetCheck, RecoveryCandidateState, RecoveryError, RecoveryResource, RecoveryResult,
        classify_case_evidence_quota,
    },
};
use serde_json::{Value, json};
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub(super) struct CaseEvidenceStop {
    resource: RecoveryResource,
    limit: usize,
    used: usize,
    requested: usize,
}

impl CaseEvidenceStop {
    fn from_omission(omission: &RecoveryOmission) -> Option<Self> {
        let RecoveryOmission::ResourceExhausted {
            resource,
            limit,
            used,
            requested,
            ..
        } = omission
        else {
            return None;
        };
        is_case_evidence_resource(*resource).then_some(Self {
            resource: *resource,
            limit: *limit,
            used: *used,
            requested: *requested,
        })
    }
}

const fn is_case_evidence_resource(resource: RecoveryResource) -> bool {
    matches!(
        resource,
        RecoveryResource::EvidenceEdges
            | RecoveryResource::EvidenceNodes
            | RecoveryResource::EvidenceBlobs
            | RecoveryResource::EvidenceBlobBytes
            | RecoveryResource::EvidenceTotalDetailsBytes
            | RecoveryResource::EvidenceSourceRanges
            | RecoveryResource::EvidenceLimitations
    )
}

pub(super) fn case_evidence_quota(
    case: &Case,
    error: &EvidenceError,
) -> Option<(RecoveryResource, usize, usize)> {
    let resource = classify_case_evidence_quota(error)?;
    let limit = match error {
        EvidenceError::QuotaExceeded { maximum, .. }
        | EvidenceError::TotalDetailsTooLarge { maximum, .. } => *maximum,
        _ => return None,
    };
    let used = current_case_usage(case, resource)?;
    Some((resource, limit, used))
}

fn current_case_usage(case: &Case, resource: RecoveryResource) -> Option<usize> {
    let usage = case.resource_usage();
    match resource {
        RecoveryResource::EvidenceBlobs => Some(case.blobs().len()),
        RecoveryResource::EvidenceBlobBytes => Some(usage.blob_bytes),
        RecoveryResource::EvidenceTotalDetailsBytes => Some(usage.details_bytes),
        RecoveryResource::EvidenceSourceRanges => Some(usage.source_ranges),
        RecoveryResource::EvidenceLimitations => Some(case.limitations().len()),
        RecoveryResource::EvidenceNodes => Some(case.nodes().len()),
        RecoveryResource::EvidenceEdges => Some(case.edges().len()),
        _ => None,
    }
}

pub(super) fn recent_case_evidence_stop(
    omissions: &[RecoveryOmission],
) -> Option<CaseEvidenceStop> {
    omissions.iter().find_map(CaseEvidenceStop::from_omission)
}

pub(super) fn saturated_case_evidence(
    case: &Case,
    task: &RecoveryTask,
) -> Option<CaseEvidenceStop> {
    // Discovery searches finish before report retention, so let the report write classify a full Case quota
    if matches!(
        task,
        RecoveryTask::FramingDiscovery
            | RecoveryTask::TransformDiscovery
            | RecoveryTask::RecordDiscovery
    ) {
        return None;
    }

    let usage = case.resource_usage();
    let candidates = [
        (
            RecoveryResource::EvidenceNodes,
            MAX_NODES,
            case.nodes().len(),
        ),
        (
            RecoveryResource::EvidenceEdges,
            MAX_EDGES,
            case.edges().len(),
        ),
        (
            RecoveryResource::EvidenceBlobs,
            MAX_BLOBS,
            case.blobs().len(),
        ),
        (
            RecoveryResource::EvidenceTotalDetailsBytes,
            MAX_TOTAL_DETAILS_BYTES,
            usage.details_bytes,
        ),
        (
            RecoveryResource::EvidenceSourceRanges,
            MAX_TOTAL_SOURCE_RANGES,
            usage.source_ranges,
        ),
        (
            RecoveryResource::EvidenceLimitations,
            MAX_LIMITATIONS,
            case.limitations().len(),
        ),
    ];
    for (resource, limit, used) in candidates {
        if used >= limit {
            return Some(CaseEvidenceStop {
                resource,
                limit,
                used,
                requested: 1,
            });
        }
    }
    let limit = case.blob_byte_limit()?;
    (usage.blob_bytes >= limit).then_some(CaseEvidenceStop {
        resource: RecoveryResource::EvidenceBlobBytes,
        limit,
        used: usage.blob_bytes,
        requested: 1,
    })
}

impl Executor<'_> {
    pub(super) fn stop_candidate_for_case_evidence(
        &mut self,
        candidate_id: RecoveryCandidateId,
        stop: CaseEvidenceStop,
        record_omission: bool,
    ) -> Result<(), RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        let task = candidate.task().clone();
        let origins = candidate
            .inputs()
            .iter()
            .flat_map(|input| input.origin_node_ids().iter().copied())
            .collect::<Vec<_>>();
        self.coordinator.finish(
            self.case,
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource: stop.resource,
                limit: stop.limit,
                used: stop.used,
                requested: stop.requested,
            },
        )?;
        if record_omission {
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task,
                input_node_ids: origins,
                resource: stop.resource,
                limit: stop.limit,
                used: stop.used,
                requested: stop.requested,
            });
        }
        Ok(())
    }

    pub(super) fn stop_after_case_evidence_error(
        &mut self,
        candidate_id: RecoveryCandidateId,
        error: RecoveryExecutionError,
    ) -> Result<CaseEvidenceStop, RecoveryExecutionError> {
        let RecoveryExecutionError::Evidence(evidence_error) = error else {
            return Err(error);
        };
        let Some((resource, limit, used)) = case_evidence_quota(self.case, &evidence_error) else {
            return Err(RecoveryExecutionError::Evidence(evidence_error));
        };
        let stop = CaseEvidenceStop {
            resource,
            limit,
            used,
            requested: 1,
        };
        self.stop_candidate_for_case_evidence(candidate_id, stop, true)?;
        Ok(stop)
    }
}

pub(super) struct TransactionEdges<'a> {
    existing: &'a HashSet<super::EdgeIdentity>,
    staged: HashSet<super::EdgeIdentity>,
}

impl<'a> TransactionEdges<'a> {
    fn new(existing: &'a HashSet<super::EdgeIdentity>) -> Self {
        Self {
            existing,
            staged: HashSet::new(),
        }
    }

    fn contains_or_insert(&mut self, identity: super::EdgeIdentity) -> bool {
        self.existing.contains(&identity) || !self.staged.insert(identity)
    }
}

pub(super) fn add_transaction_edge(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    edge: Edge,
) -> Result<(), RecoveryExecutionError> {
    let identity = edge_identity(
        edge.from,
        edge.to,
        &edge.relation,
        edge.status,
        &edge.reason,
    );
    if identities.contains_or_insert(identity) {
        return Ok(());
    }
    case.add_edge(edge)?;
    Ok(())
}

pub(super) fn add_transaction_links(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    from: u64,
    origins: &[u64],
    relation: &str,
    status: EvidenceStatus,
    reason: &str,
) -> Result<(), RecoveryExecutionError> {
    for origin in origins {
        add_transaction_edge(
            case,
            identities,
            Edge {
                from,
                to: *origin,
                relation: relation.to_owned(),
                status,
                reason: reason.to_owned(),
            },
        )?;
    }
    Ok(())
}

fn contextual_decoding_view_edges(view_node: u64, receipt_node: u64, input_node: u64) -> [Edge; 3] {
    [
        Edge {
            from: receipt_node,
            to: view_node,
            relation: "produced".to_owned(),
            status: EvidenceStatus::Observed,
            reason: DERIVED_REASON.to_owned(),
        },
        Edge {
            from: view_node,
            to: receipt_node,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: DERIVED_REASON.to_owned(),
        },
        Edge {
            from: view_node,
            to: input_node,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: DERIVED_REASON.to_owned(),
        },
    ]
}

impl Executor<'_> {
    pub(super) fn contextual_decoding_view(
        &mut self,
        output_node: u64,
        receipt_node: u64,
        input_node: u64,
    ) -> Result<u64, RecoveryExecutionError> {
        let blob_id = self.node_blob_id(output_node)?.to_owned();
        let key = (blob_id.clone(), receipt_node, input_node);
        if let Some(view_node) = self.case_index.contextual_decoding_views.get(&key).copied() {
            self.ensure_contextual_decoding_view_edges(view_node, receipt_node, input_node)?;
            return Ok(view_node);
        }

        let existing_edges = &self.case_index.edge_identities;
        let case = &mut *self.case;
        let mut identities = TransactionEdges::new(existing_edges);
        let view_node = case.transaction(|case| {
            let view = case.add_node(
                "decoding_output",
                Some(&blob_id),
                Vec::new(),
                json!({
                    "external_acceptance":"not_tested",
                    "shared_transform_receipt":receipt_node,
                    "source_input_node":input_node
                }),
            )?;
            for edge in contextual_decoding_view_edges(view, receipt_node, input_node) {
                add_transaction_edge(case, &mut identities, edge)?;
            }
            Ok::<u64, RecoveryExecutionError>(view)
        })?;
        self.refresh_case_index()?;
        Ok(view_node)
    }

    fn ensure_contextual_decoding_view_edges(
        &mut self,
        view_node: u64,
        receipt_node: u64,
        input_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let edges = contextual_decoding_view_edges(view_node, receipt_node, input_node);
        let all_edges_exist = edges.iter().all(|edge| {
            self.case_index.edge_identities.contains(&edge_identity(
                edge.from,
                edge.to,
                &edge.relation,
                edge.status,
                &edge.reason,
            ))
        });
        if all_edges_exist {
            return Ok(());
        }

        let existing_edges = &self.case_index.edge_identities;
        let case = &mut *self.case;
        let mut identities = TransactionEdges::new(existing_edges);
        case.transaction(|case| {
            for edge in edges {
                add_transaction_edge(case, &mut identities, edge)?;
            }
            Ok::<(), RecoveryExecutionError>(())
        })?;
        self.refresh_case_index()
    }

    pub(super) fn charge_work(
        &mut self,
        candidate_id: RecoveryCandidateId,
        task: &RecoveryTask,
        origins: &[u64],
        requested: usize,
    ) -> Result<bool, RecoveryExecutionError> {
        let record_phase_task = matches!(
            task,
            RecoveryTask::RecordDiscovery | RecoveryTask::AssembleRecords(_)
        );
        if record_phase_task
            && !self.check_record_phase_work(Some(candidate_id), task, origins, requested)?
        {
            return Ok(false);
        }
        match self.coordinator.charge_work(candidate_id, requested)? {
            BudgetCheck::WithinBudget => {
                if record_phase_task {
                    self.record_phase_work_charged = self
                        .record_phase_work_charged
                        .checked_add(requested)
                        .ok_or_else(|| {
                            RecoveryExecutionError::InvalidPolicy(
                                "record phase work counter overflowed".to_owned(),
                            )
                        })?;
                }
                Ok(true)
            }
            BudgetCheck::Exhausted {
                resource,
                limit,
                used,
                requested,
            } => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task: task.clone(),
                    input_node_ids: origins.to_vec(),
                    resource,
                    limit,
                    used,
                    requested,
                });
                Ok(false)
            }
        }
    }

    pub(super) fn charge_record_case_work(
        &mut self,
        requested: usize,
    ) -> Result<bool, RecoveryExecutionError> {
        let task = RecoveryTask::RecordDiscovery;
        if !self.check_record_phase_work(None, &task, &[], requested)? {
            return Ok(false);
        }
        match self.coordinator.charge_case_work(requested) {
            BudgetCheck::WithinBudget => {
                self.record_phase_work_charged = self
                    .record_phase_work_charged
                    .checked_add(requested)
                    .ok_or_else(|| {
                        RecoveryExecutionError::InvalidPolicy(
                            "record phase work counter overflowed".to_owned(),
                        )
                    })?;
                Ok(true)
            }
            BudgetCheck::Exhausted {
                resource,
                limit,
                used,
                requested,
            } => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task,
                    input_node_ids: Vec::new(),
                    resource,
                    limit,
                    used,
                    requested,
                });
                Ok(false)
            }
        }
    }

    fn check_record_phase_work(
        &mut self,
        candidate_id: Option<RecoveryCandidateId>,
        task: &RecoveryTask,
        origins: &[u64],
        requested: usize,
    ) -> Result<bool, RecoveryExecutionError> {
        let used = self.record_phase_work_charged;
        let limit = self.policy.record_phase_work_limit;
        let total = used.checked_add(requested).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy("record phase work total overflowed".to_owned())
        })?;
        if total <= limit {
            return Ok(true);
        }
        if let Some(candidate_id) = candidate_id {
            self.finish(
                candidate_id,
                RecoveryResult::ResourceExhausted {
                    resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
                    limit,
                    used,
                    requested,
                },
            )?;
        }
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: task.clone(),
            input_node_ids: origins.to_vec(),
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit,
            used,
            requested,
        });
        Ok(false)
    }

    pub(super) fn check_output(
        &mut self,
        candidate_id: RecoveryCandidateId,
        task: &RecoveryTask,
        origins: &[u64],
        requested: usize,
    ) -> Result<bool, RecoveryExecutionError> {
        match self.coordinator.check_output(candidate_id, requested)? {
            BudgetCheck::WithinBudget => Ok(true),
            BudgetCheck::Exhausted {
                resource,
                limit,
                used,
                requested,
            } => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task: task.clone(),
                    input_node_ids: origins.to_vec(),
                    resource,
                    limit,
                    used,
                    requested,
                });
                Ok(false)
            }
        }
    }

    pub(super) fn finish(
        &mut self,
        candidate_id: RecoveryCandidateId,
        result: RecoveryResult,
    ) -> Result<(), RecoveryExecutionError> {
        self.case_transaction_and_finish(candidate_id, |_case, _identities| Ok(((), result)))?;
        Ok(())
    }

    pub(super) fn case_transaction_and_finish<T>(
        &mut self,
        candidate_id: RecoveryCandidateId,
        write: impl FnOnce(
            &mut Case,
            &mut TransactionEdges<'_>,
        ) -> Result<(T, RecoveryResult), RecoveryExecutionError>,
    ) -> Result<T, RecoveryExecutionError> {
        self.case_transaction_and_finish_with_coordinator(
            candidate_id,
            |case, identities, _coordinator| write(case, identities),
        )
    }

    pub(super) fn case_transaction_and_finish_with_coordinator<T>(
        &mut self,
        candidate_id: RecoveryCandidateId,
        write: impl FnOnce(
            &mut Case,
            &mut TransactionEdges<'_>,
            &mut l2_workbench::recovery::RecoveryCoordinator,
        ) -> Result<(T, RecoveryResult), RecoveryExecutionError>,
    ) -> Result<T, RecoveryExecutionError> {
        self.refresh_case_index()?;
        let mut edge_identities = TransactionEdges::new(&self.case_index.edge_identities);
        let origins = self.candidate_origins(candidate_id)?;
        let case = &mut *self.case;
        let coordinator = &mut self.coordinator;
        let result = case.transaction(|case| {
            let (value, recovery_result) = write(case, &mut edge_identities, coordinator)?;
            if let Some(contract) = recovery_result.evidence_link_contract() {
                add_transaction_links(
                    case,
                    &mut edge_identities,
                    contract.node_id,
                    &origins,
                    contract.relation,
                    contract.status,
                    RESULT_REASON,
                )?;
            }
            // Completion is last so failed validation rolls the Case back unchanged
            coordinator.finish(case, candidate_id, recovery_result)?;
            Ok::<T, RecoveryExecutionError>(value)
        });
        drop(edge_identities);
        self.refresh_case_index()?;
        result
    }

    pub(super) fn case_transaction<T>(
        &mut self,
        write: impl FnOnce(&mut Case, &mut TransactionEdges<'_>) -> Result<T, RecoveryExecutionError>,
    ) -> Result<T, RecoveryExecutionError> {
        self.refresh_case_index()?;
        let mut edge_identities = TransactionEdges::new(&self.case_index.edge_identities);
        let case = &mut *self.case;
        let result = case.transaction(|case| write(case, &mut edge_identities));
        drop(edge_identities);
        self.refresh_case_index()?;
        result
    }

    fn candidate_origins(
        &self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<Vec<u64>, RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        Ok(candidate
            .inputs()
            .iter()
            .flat_map(|input| input.origin_node_ids().iter().copied())
            .collect())
    }

    pub(super) fn ensure_edge(
        &mut self,
        from: u64,
        to: u64,
        relation: &str,
        status: EvidenceStatus,
        reason: &str,
    ) -> Result<(), RecoveryExecutionError> {
        self.refresh_case_index()?;
        let identity = edge_identity(from, to, relation, status, reason);
        if self.case_index.edge_identities.contains(&identity) {
            return Ok(());
        }
        self.case.add_edge(Edge {
            from,
            to,
            relation: relation.to_owned(),
            status,
            reason: reason.to_owned(),
        })?;
        self.refresh_case_index()
    }

    pub(super) fn receipt_node_bytes_and_finish(
        &mut self,
        candidate_id: RecoveryCandidateId,
        kind: &str,
        bytes: &[u8],
        details: Value,
        result_for_node: impl FnOnce(u64) -> RecoveryResult,
    ) -> Result<u64, RecoveryExecutionError> {
        self.case_transaction_and_finish(candidate_id, |case, _identities| {
            let node_id = case.add_bytes_node(kind, bytes, Vec::new(), details)?;
            let result = result_for_node(node_id);
            Ok((node_id, result))
        })
    }

    pub(super) fn derived_result(
        &self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<u64, RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        match candidate.state() {
            RecoveryCandidateState::Finished {
                result: RecoveryResult::Derived { evidence_node_id },
                ..
            } => Ok(*evidence_node_id),
            _ => Err(RecoveryError::InvariantFailure.into()),
        }
    }

    pub(super) fn node_kind(&mut self, node_id: u64) -> Result<&str, RecoveryExecutionError> {
        self.refresh_case_index()?;
        let position = self
            .case_index
            .node_positions
            .get(&node_id)
            .copied()
            .ok_or(RecoveryError::UnknownEvidenceNode { node_id })?;
        self.case
            .nodes()
            .get(position)
            .map(|node| node.kind.as_str())
            .ok_or_else(|| RecoveryError::InvariantFailure.into())
    }

    pub(super) fn node_blob_id(&mut self, node_id: u64) -> Result<&str, RecoveryExecutionError> {
        self.refresh_case_index()?;
        let position = self
            .case_index
            .node_positions
            .get(&node_id)
            .copied()
            .ok_or(RecoveryError::UnknownEvidenceNode { node_id })?;
        self.case
            .nodes()
            .get(position)
            .ok_or(RecoveryError::InvariantFailure)?
            .blob
            .as_deref()
            .ok_or_else(|| RecoveryError::InputBlobMissing { node_id }.into())
    }

    pub(super) fn node_bytes(&mut self, node_id: u64) -> Result<&[u8], RecoveryExecutionError> {
        self.refresh_case_index()?;
        let blob_id = self.node_blob_id(node_id)?.to_owned();
        let position = self
            .case_index
            .blob_positions
            .get(&blob_id)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        self.case
            .blobs()
            .get(position)
            .map(|blob| blob.bytes.as_slice())
            .ok_or_else(|| RecoveryError::InvariantFailure.into())
    }
}
pub(super) fn canonical_result_link(
    result: &RecoveryResult,
) -> Option<(u64, &'static str, EvidenceStatus)> {
    result
        .evidence_link_contract()
        .map(|contract| (contract.node_id, contract.relation, contract.status))
}
