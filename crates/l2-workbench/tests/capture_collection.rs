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
    assert_eq!(result.case.nodes().len(), 0);
    assert!(result.complete);
    assert!(result.case.collection_complete());
    result.case.validate()?;
    Ok(())
}

#[test]
fn reported_drop_counts_incomplete() {
    assert!(!capture_collection::reports_incomplete_collection(
        CollectionSummary::default()
    ));

    // Each source of loss must affect completeness without help from another counter
    for (counter, summary) in [
        (
            "incomplete sections",
            CollectionSummary {
                sections: 1,
                reported_sections: 1,
                incomplete_sections: 1,
                ..CollectionSummary::default()
            },
        ),
        (
            "capture drops",
            CollectionSummary {
                sections: 1,
                reported_sections: 1,
                capture_dropped: 1,
                ..CollectionSummary::default()
            },
        ),
        (
            "interface drops",
            CollectionSummary {
                sections: 1,
                reported_sections: 1,
                interface_dropped: 1,
                ..CollectionSummary::default()
            },
        ),
        (
            "packet block drops",
            CollectionSummary {
                packet_block_packets_dropped: 3,
                ..CollectionSummary::default()
            },
        ),
        (
            "unavailable packet block drops",
            CollectionSummary {
                packet_blocks_with_unavailable_drop_count: 1,
                ..CollectionSummary::default()
            },
        ),
    ] {
        assert!(
            capture_collection::reports_incomplete_collection(summary),
            "{counter} must mark collection incomplete"
        );
    }
}

#[test]
fn pcapng_loss_incomplete_collection() -> Result<(), Box<dyn Error>> {
    for summary in [
        CollectionSummary {
            enhanced_packet_packets_dropped: Some(9),
            ..CollectionSummary::default()
        },
        CollectionSummary {
            interface_statistics_interface_dropped: Some(11),
            ..CollectionSummary::default()
        },
        CollectionSummary {
            interface_statistics_os_dropped: Some(3),
            ..CollectionSummary::default()
        },
    ] {
        assert!(capture_collection::reports_incomplete_collection(summary));
        assert_eq!(
            capture_collection::from_json(&capture_collection::to_json(summary)?)?,
            summary
        );
        let (mut result, source_id) = source_case()?;
        capture_collection::apply_to_case(&mut result, &source_id, summary)?;
        assert!(!result.complete);
        assert!(!result.case.collection_complete());
    }
    Ok(())
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

#[test]
fn collection_summary_unverified_authority() -> Result<(), Box<dyn Error>> {
    let summary = CollectionSummary {
        sections: 1,
        reported_sections: 1,
        ..CollectionSummary::default()
    };
    let value = capture_collection::to_value(summary)?;
    assert_eq!(value.get("authority"), Some(&json!("source_declared")));
    assert_eq!(value.get("acquisition_quality"), Some(&json!("unverified")));
    for (field, forged) in [
        ("authority", json!("verified_local")),
        ("authority", json!("absent")),
        ("acquisition_quality", json!("verified")),
    ] {
        let mut forged_summary = value.clone();
        *forged_summary
            .get_mut(field)
            .ok_or("missing summary field")? = forged;
        assert!(capture_collection::from_json(&forged_summary.to_string()).is_err());
    }
    Ok(())
}
