use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    recovery::{RecoveryResourcePolicy, RecoveryTask},
};
use serde_json::json;

#[path = "invariant_support.rs"]
mod invariant;
pub use invariant::{fail, require};

pub fn add_bytes_node(case: &mut Case, kind: &str, bytes: &[u8]) -> u64 {
    case.add_bytes_node(kind, bytes, Vec::new(), json!({}))
        .unwrap_or_else(|_| fail())
}

pub fn add_derived_edge(case: &mut Case, output: u64, input: u64) {
    let edge = Edge {
        from: output,
        to: input,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The output retains the exact input relation used by the fuzz scenario".to_owned(),
    };
    if case.add_edge(edge).is_err() {
        fail();
    }
}

pub fn recovery_policy(input_length: usize) -> RecoveryResourcePolicy {
    use l2_workbench::recovery::proposals::transform_proposal_operations;

    let input_limit = input_length.max(1);
    let max_candidate_task_identity_bytes = [
        RecoveryTask::StructuralValidation,
        RecoveryTask::FramingDiscovery,
        RecoveryTask::RecursiveExpansion,
    ]
    .iter()
    .map(|task| serde_json::to_vec(task).map_or(0, |identity| identity.len()))
    .max()
    .unwrap_or_default()
    .saturating_mul(4);
    let max_proposal_identity_bytes = transform_proposal_operations()
        .map(RecoveryTask::transform)
        .map(|task| serde_json::to_vec(&task).map_or(0, |identity| identity.len()))
        .max()
        .unwrap_or_default()
        .saturating_mul(4);
    RecoveryResourcePolicy {
        max_candidates: 4,
        max_frontier: 4,
        max_inputs_per_candidate: 4,
        max_origins_per_candidate: 4,
        max_input_bytes_per_item: input_limit,
        max_total_input_bytes_per_candidate: input_limit.saturating_mul(2),
        max_depth: 3,
        max_output_bytes: input_limit,
        max_work_bytes: input_limit.saturating_mul(4).saturating_add(16),
        max_candidate_task_identity_bytes,
        max_transform_proposal_identity_bytes: max_proposal_identity_bytes,
        max_transform_proposal_associations: 4,
        max_parent_links: 8,
        max_lineage_work: 64,
        max_context_aliases: 16,
        max_pending_origin_links: 8,
    }
}
