use std::error::Error;

use l2_workbench::evidence::{Case, Edge, EvidenceStatus};
use serde_json::json;

#[test]
fn selection_requires_the_matching_observed_parse_edge() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let der = [0x30, 0x03, 0x04, 0x01, b'A'];
    let input = case.add_bytes_node("candidate_object", &der, Vec::new(), json!({}))?;
    let blob = case
        .node(input)
        .and_then(|node| node.blob.clone())
        .ok_or("DER blob is missing")?;
    let structure = case.add_node(
        "der_structure",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node": input,
            "depth": 1,
            "value_count": 2,
            "boundary_range": {"offset": 0, "length": der.len()}
        }),
    )?;
    for (relation, status) in [
        ("parsed_as", EvidenceStatus::Hypothesis),
        ("contains_member", EvidenceStatus::Observed),
    ] {
        case.add_edge(Edge {
            from: input,
            to: structure,
            relation: relation.to_owned(),
            status,
            reason: "Unrelated evidence must not validate an artifact".to_owned(),
        })?;
    }
    assert!(super::super::select_artifacts(&case, None)?.is_empty());

    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "DER structure was parsed".to_owned(),
    })?;
    let selected = super::super::select_artifacts(&case, None)?;
    let artifact = selected.first().ok_or("validated artifact missing")?;
    assert_eq!(artifact.bytes(), der);
    assert_eq!(
        artifact
            .provenance()
            .first()
            .and_then(super::super::provenance::ArtifactProvenance::validated_as),
        Some("der_structure")
    );
    Ok(())
}
