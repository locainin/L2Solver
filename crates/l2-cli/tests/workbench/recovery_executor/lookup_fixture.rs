use l2_workbench::evidence::{Case, Edge, EvidenceStatus};
use serde_json::json;
use std::error::Error;

pub(super) fn link(
    case: &mut Case,
    from: u64,
    to: u64,
    relation: &str,
    status: EvidenceStatus,
) -> Result<(), Box<dyn Error>> {
    case.add_edge(Edge {
        from,
        to,
        relation: relation.to_owned(),
        status,
        reason: "Synthetic lookup observation".to_owned(),
    })?;
    Ok(())
}

pub(super) fn unrelated_edges(
    case: &mut Case,
    relation: &str,
    count: usize,
) -> Result<(), Box<dyn Error>> {
    let from = case.add_node("unrelated_source", None, Vec::new(), json!({}))?;
    let to = case.add_node("unrelated_result", None, Vec::new(), json!({}))?;
    for _ in 0..count {
        link(case, from, to, relation, EvidenceStatus::Observed)?;
    }
    Ok(())
}
