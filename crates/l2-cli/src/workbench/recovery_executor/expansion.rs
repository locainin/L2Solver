use super::super::expand;
use super::evidence::{
    TransactionEdges, add_transaction_edge, add_transaction_links, case_evidence_quota,
};
use super::format::is_recovery_byte_child_kind;
use super::{
    DERIVED_REASON, Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask,
};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceError, EvidenceStatus},
    recovery::{BudgetCheck, RecoveryError, RecoveryResult},
};
use serde_json::json;

struct ExpansionCommit {
    complete: bool,
    created_node_count: usize,
    enqueue_children: bool,
    children: Vec<u64>,
}

struct ExpansionRequest<'a> {
    candidate_id: RecoveryCandidateId,
    input_node: u64,
    depth: usize,
    origins: &'a [u64],
    limits: super::ExpansionLimits,
}

impl Executor<'_> {
    pub(super) fn run_expansion(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let depth = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
            .depth();
        let limits = self.policy.expansion_limits;
        let commit = self.case_transaction_and_finish_with_coordinator(
            candidate_id,
            |case, identities, coordinator| {
                let request = ExpansionRequest {
                    candidate_id,
                    input_node,
                    depth,
                    origins,
                    limits,
                };
                probe_expansion(case, identities, coordinator, &request)
            },
        );
        let commit = match commit {
            Ok(commit) => commit,
            Err(error) => {
                self.finish_expansion_case_quota(candidate_id, origins, error)?;
                return Ok(());
            }
        };
        if !commit.complete {
            self.omissions.push(RecoveryOmission::ArtifactExpansion {
                input_node_id: input_node,
                created_node_count: commit.created_node_count,
            });
        }
        if commit.enqueue_children {
            self.enqueue_derived_children(candidate_id, &commit.children, false)?;
        }
        Ok(())
    }

    fn finish_expansion_case_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        error: RecoveryExecutionError,
    ) -> Result<(), RecoveryExecutionError> {
        let evidence_error = match &error {
            RecoveryExecutionError::Evidence(evidence_error) => Some(evidence_error),
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::RecursiveExpansion,
                source,
            } => source
                .source()
                .and_then(|cause| cause.downcast_ref::<EvidenceError>()),
            _ => None,
        };
        let quota = match evidence_error {
            Some(evidence_error) => case_evidence_quota(self.case, evidence_error),
            None => None,
        };
        let Some((resource, limit, used)) = quota else {
            return Err(error);
        };
        let requested = 1;
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
            task: RecoveryTask::RecursiveExpansion,
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested,
        });
        Ok(())
    }
}

fn probe_expansion(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    coordinator: &mut l2_workbench::recovery::RecoveryCoordinator,
    request: &ExpansionRequest<'_>,
) -> Result<(ExpansionCommit, RecoveryResult), RecoveryExecutionError> {
    let expansion = {
        let mut service = expand::ExpansionService::new(case, request.limits);
        service.probe_candidate_at_with_work(
            request.input_node,
            request.depth,
            coordinator.remaining_work_bytes(),
        )
    };
    let expansion = match expansion {
        Ok(expansion) => expansion,
        Err(expand::ExpansionError::Rejected(rejection)) => {
            return reject_probe(
                case,
                identities,
                request.input_node,
                request.origins,
                rejection.format,
                &rejection.message,
            );
        }
        Err(source) => {
            return Err(RecoveryExecutionError::Operational {
                stage: RecoveryStage::RecursiveExpansion,
                source: Box::new(source),
            });
        }
    };
    match coordinator.charge_work(request.candidate_id, expansion.work_bytes)? {
        BudgetCheck::WithinBudget => {}
        BudgetCheck::Exhausted { .. } => return Err(RecoveryError::InvariantFailure.into()),
    }
    let (children, result) = record_expansion(
        case,
        identities,
        request.input_node,
        request.depth,
        request.origins,
        &expansion,
    )?;
    let enqueue_children = matches!(result, RecoveryResult::Derived { .. });
    Ok((
        ExpansionCommit {
            complete: expansion.complete,
            created_node_count: expansion.created_nodes.len(),
            enqueue_children,
            children,
        },
        result,
    ))
}

fn reject_probe(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    input_node: u64,
    origins: &[u64],
    format: &str,
    message: &str,
) -> Result<(ExpansionCommit, RecoveryResult), RecoveryExecutionError> {
    let details = json!({"input_node":input_node,"format":format,"reason":message});
    let receipt_bytes =
        serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::RecursiveExpansion,
            source: Box::new(source),
        })?;
    let receipt = case.add_bytes_node(
        "artifact_parse_rejection",
        &receipt_bytes,
        Vec::new(),
        details,
    )?;
    add_transaction_links(
        case,
        identities,
        receipt,
        origins,
        "expansion_rejected",
        EvidenceStatus::ConstraintFailed,
        "A speculative parser rejected this candidate and the frontier continues",
    )?;
    Ok((
        ExpansionCommit {
            complete: true,
            created_node_count: 0,
            enqueue_children: false,
            children: Vec::new(),
        },
        RecoveryResult::Rejected { node_id: receipt },
    ))
}

fn record_expansion(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    input_node: u64,
    depth: usize,
    origins: &[u64],
    expansion: &expand::ExpansionOutcome,
) -> Result<(Vec<u64>, RecoveryResult), RecoveryExecutionError> {
    let (output_nodes, archive_child_count, supported_structure_count) =
        collect_expansion_outputs(case, expansion);
    let root_rejection = expansion
        .rejections
        .iter()
        .find(|item| item.node == input_node);
    let details = json!({
        "input_node":input_node,
        "start_depth":depth,
        "complete":expansion.complete,
        "created_node_count":expansion.created_nodes.len(),
        "archive_child_count":archive_child_count,
        "root_rejection":root_rejection.map(|item| json!({"format":item.format,"reason":item.message}))
    });
    let receipt_bytes =
        serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::RecursiveExpansion,
            source: Box::new(source),
        })?;
    let receipt = case.add_bytes_node(
        "artifact_expansion_receipt",
        &receipt_bytes,
        Vec::new(),
        details,
    )?;
    let result = if let Some(rejection) = root_rejection
        && output_nodes.is_empty()
        && supported_structure_count == 0
    {
        add_transaction_links(
            case,
            identities,
            receipt,
            origins,
            "expansion_rejected",
            EvidenceStatus::ConstraintFailed,
            &format!(
                "The {} parser rejected the exact retained candidate",
                rejection.format
            ),
        )?;
        RecoveryResult::Rejected { node_id: receipt }
    } else if output_nodes.is_empty() && supported_structure_count == 0 {
        RecoveryResult::Unsupported
    } else {
        add_transaction_links(
            case,
            identities,
            receipt,
            origins,
            "expanded_by",
            EvidenceStatus::Observed,
            "The existing artifact service inspected this candidate and retained exact descendants or structure evidence",
        )?;
        for member in &output_nodes {
            add_transaction_edge(
                case,
                identities,
                Edge {
                    from: *member,
                    to: receipt,
                    relation: "derived_from".to_owned(),
                    status: EvidenceStatus::Observed,
                    reason: DERIVED_REASON.to_owned(),
                },
            )?;
        }
        RecoveryResult::Derived {
            evidence_node_id: receipt,
        }
    };
    Ok((output_nodes, result))
}

fn collect_expansion_outputs(
    case: &Case,
    expansion: &expand::ExpansionOutcome,
) -> (Vec<u64>, usize, usize) {
    let node_kind = |node_id| {
        case.nodes()
            .binary_search_by_key(&node_id, |node| node.id)
            .ok()
            .and_then(|position| case.nodes().get(position))
            .map(|node| node.kind.as_str())
    };
    let output_nodes = expansion
        .created_nodes
        .iter()
        .copied()
        .filter(|node_id| node_kind(*node_id).is_some_and(is_recovery_byte_child_kind))
        .collect::<Vec<_>>();
    let archive_child_count = output_nodes
        .iter()
        .filter(|node_id| node_kind(**node_id).is_some_and(|kind| kind == "archive_member"))
        .count();
    let supported_structure_count = expansion
        .created_nodes
        .iter()
        .filter(|node_id| {
            node_kind(**node_id).is_some_and(|kind| {
                matches!(
                    kind,
                    "archive_structure" | "png_structure" | "der_structure"
                )
            })
        })
        .count();
    (output_nodes, archive_child_count, supported_structure_count)
}
