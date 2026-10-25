use l2_pcap::CollectionSummary;
use l2_workbench::{
    capture_collection,
    evidence::{Case, EvidenceError, MAX_NODE_DETAILS_BYTES, MAX_TOTAL_DETAILS_BYTES},
    investigation::BuildResult,
    sha256,
};
use serde_json::{Value, json};
use std::error::Error;

fn source_case() -> Result<(BuildResult, String), Box<dyn Error>> {
    let mut case = Case::new();
    let source_id = case.add_source("source.pcap", "capture", 24, &sha256(b"capture"), None)?;
    Ok((
        BuildResult {
            case,
            complete: true,
        },
        source_id,
    ))
}

#[test]
fn collection_summary_retained_evidence_budget() -> Result<(), Box<dyn Error>> {
    let (mut result, source_id) = source_case()?;
    let summary = CollectionSummary {
        sections: 1,
        reported_sections: 1,
        incomplete_sections: 0,
        capture_dropped: 0,
        interface_dropped: 0,
        ..CollectionSummary::default()
    };

    capture_collection::apply_to_case(&mut result, &source_id, summary)?;

    let node = result
        .case
        .nodes()
        .first()
        .ok_or("summary node is missing")?;
    assert_eq!(node.kind, "capture_collection_summary");
    assert_eq!(
        node.details,
        json!({"source_id": source_id, "summary": capture_collection::to_value(summary)?})
    );
    assert!(result.complete);
    assert!(result.case.collection_complete());
    result.case.validate()?;
    Ok(())
}

#[test]
fn saturated_details_omit_required_summary() -> Result<(), Box<dyn Error>> {
    let (mut result, source_id) = source_case()?;
    // String quotes consume the final two encoded bytes in each full-size detail
    let details = Value::String("x".repeat(MAX_NODE_DETAILS_BYTES - 2));
    let node_count = MAX_TOTAL_DETAILS_BYTES / MAX_NODE_DETAILS_BYTES;
    for _ in 0..node_count {
        result
            .case
            .add_node("observation", None, Vec::new(), details.clone())?;
    }
    let summary = CollectionSummary {
        sections: 1,
        reported_sections: 1,
        incomplete_sections: 0,
        capture_dropped: 0,
        interface_dropped: 0,
        ..CollectionSummary::default()
    };
    let summary_length = serde_json::to_vec(&json!({
        "source_id": source_id,
        "summary": capture_collection::to_value(summary)?,
    }))?
    .len();

    capture_collection::apply_to_case(&mut result, &source_id, summary)?;

    assert_eq!(result.case.nodes().len(), node_count);
    assert!(
        result
            .case
            .nodes()
            .iter()
            .all(|node| node.kind != "capture_collection_summary")
    );
    assert!(!result.complete);
    assert!(!result.case.collection_complete());
    let expected = format!(
        "Mandatory capture_collection_summary for source {source_id} was omitted after the evidence detail budget (node details have {} encoded bytes; case maximum is {MAX_TOTAL_DETAILS_BYTES}); source collection quality is unresolved",
        MAX_TOTAL_DETAILS_BYTES + summary_length
    );
    assert!(result.case.limitations().contains(&expected));
    result.case.validate()?;
    Ok(())
}

#[test]
fn oversized_summary_preserves_case() -> Result<(), Box<dyn Error>> {
    let (mut result, _) = source_case()?;
    let oversized_source_id = "x".repeat(MAX_NODE_DETAILS_BYTES);

    let failure = capture_collection::apply_to_case(
        &mut result,
        &oversized_source_id,
        CollectionSummary::default(),
    )
    .err()
    .ok_or("oversized summary was accepted")?;

    assert!(matches!(
        failure.downcast_ref::<EvidenceError>(),
        Some(EvidenceError::NodeDetailsTooLarge { .. })
    ));
    assert!(result.case.nodes().is_empty());
    assert!(result.complete);
    assert!(result.case.collection_complete());
    result.case.validate()?;
    Ok(())
}

#[test]
fn packet_block_drop_counts_make_collection_incomplete() {
    let known_drops = CollectionSummary {
        packet_block_packets_dropped: 3,
        ..CollectionSummary::default()
    };
    let unavailable_drops = CollectionSummary {
        packet_blocks_with_unavailable_drop_count: 1,
        ..CollectionSummary::default()
    };

    assert!(capture_collection::reports_incomplete_collection(
        known_drops
    ));
    assert!(capture_collection::reports_incomplete_collection(
        unavailable_drops
    ));
}

#[test]
fn old_collection_summary_json_defaults_packet_block_counters() -> Result<(), Box<dyn Error>> {
    let old_summary = r#"{"sections":1,"reported_sections":1,"incomplete_sections":0,"capture_dropped":0,"interface_dropped":0}"#;

    let decoded = capture_collection::from_json(old_summary)?;

    assert_eq!(
        decoded,
        CollectionSummary {
            sections: 1,
            reported_sections: 1,
            incomplete_sections: 0,
            capture_dropped: 0,
            interface_dropped: 0,
            ..CollectionSummary::default()
        }
    );
    Ok(())
}
