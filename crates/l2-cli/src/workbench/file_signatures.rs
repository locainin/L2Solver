//! Signature observations for byte objects created by workbench commands

use l2_workbench::{
    artifact,
    evidence::{Case, Edge, EvidenceStatus},
};
use serde_json::json;
use std::error::Error;

pub(super) struct AddReport {
    pub retained: usize,
    pub omitted: usize,
}

pub(super) fn add(case: &mut Case, input_node: u64, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    add_limited(case, input_node, bytes, usize::MAX)?;
    Ok(())
}

pub(super) fn add_limited(
    case: &mut Case,
    input_node: u64,
    bytes: &[u8],
    maximum: usize,
) -> Result<AddReport, Box<dyn Error>> {
    let report = artifact::scan_file_signatures(bytes);
    if report.matches.is_empty() {
        return Ok(AddReport {
            retained: 0,
            omitted: 0,
        });
    }
    // Reuse the retained output blob instead of copying derived bytes into each finding
    let input_blob = case
        .nodes()
        .iter()
        .find(|node| node.id == input_node)
        .and_then(|node| node.blob.clone())
        .ok_or("signature input node has no retained byte blob")?;
    let total = report.matches.len();
    let retained = total.min(maximum);
    for evidence in report.evidence_matches().take(retained) {
        let mut details = serde_json::to_value(evidence)?;
        let object = details
            .as_object_mut()
            .ok_or("file signature did not serialize as an object")?;
        object.insert("input_node".to_owned(), json!(input_node));
        object.insert("input_sha256".to_owned(), json!(report.source_sha256));
        object.insert("input_blob".to_owned(), json!(input_blob));
        object.insert(
            "coordinate_base".to_owned(),
            json!("zero_based_from_byte_0_of_input_blob"),
        );
        object.insert(
            "unproven".to_owned(),
            json!([
                "complete_file_boundary",
                "structural_validity",
                "container_subtype",
                "delivery",
                "execution",
                "malicious_intent"
            ]),
        );
        let signature_node = case.add_node(
            "file_signature_match",
            Some(&input_blob),
            Vec::new(),
            details,
        )?;
        case.add_edge(Edge {
            from: input_node,
            to: signature_node,
            relation: "contains_signature".to_owned(),
            status: EvidenceStatus::Observed,
            reason: artifact::FILE_SIGNATURE_RELATION_REASON.to_owned(),
        })?;
    }
    Ok(AddReport {
        retained,
        omitted: total - retained,
    })
}
