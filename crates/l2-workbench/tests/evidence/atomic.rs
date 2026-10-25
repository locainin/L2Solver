use l2_workbench::evidence::{Case, MAX_NODE_RANGES, SourceRange};
use serde_json::json;
use std::error::Error;

#[test]
fn byte_node_blob_together() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let node = case.add_bytes_node(
        "observation",
        b"exact observed bytes",
        Vec::new(),
        json!({}),
    )?;

    assert_eq!(node, 1);
    assert_eq!(case.blobs().len(), 1);
    assert_eq!(case.nodes().len(), 1);
    assert_eq!(
        case.nodes().first().and_then(|item| item.blob.as_deref()),
        case.blobs().first().map(|blob| blob.id.as_str())
    );
    case.validate()?;
    Ok(())
}

#[test]
fn byte_node_not_orphan_blob() {
    let mut case = Case::new();
    let oversized_details = json!({ "note": "x".repeat(5_000) });

    assert!(
        case.add_bytes_node(
            "observation",
            b"retained bytes",
            Vec::new(),
            oversized_details
        )
        .is_err()
    );
    assert!(case.blobs().is_empty());
    assert!(case.nodes().is_empty());
}

#[test]
fn byte_node_ranges_adding_blob() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("sample.bin", "file", 1, &"0".repeat(64), None)?;
    let invalid_range = SourceRange {
        source,
        packet: None,
        offset: 0,
        length: 2,
    };

    assert!(
        case.add_bytes_node(
            "observation",
            b"retained bytes",
            vec![invalid_range],
            json!({})
        )
        .is_err()
    );
    assert!(case.blobs().is_empty());
    assert!(case.nodes().is_empty());
    Ok(())
}

#[test]
fn node_range_without_adding() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source("sample.bin", "file", 2_048, &"0".repeat(64), None)?;
    let mut ranges = Vec::with_capacity(MAX_NODE_RANGES + 1);
    for offset in 0..=MAX_NODE_RANGES {
        ranges.push(SourceRange {
            source: source.clone(),
            packet: None,
            offset: u64::try_from(offset)?,
            length: 1,
        });
    }

    assert!(
        case.add_node("observation", None, ranges, json!({}))
            .is_err()
    );
    assert!(case.nodes().is_empty());
    Ok(())
}

#[test]
fn incomplete_status_changes_reason_recorded() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for index in 0..l2_workbench::evidence::MAX_LIMITATIONS {
        case.add_limitation(&format!("limitation {index}"))?;
    }

    assert!(case.mark_incomplete("additional limitation").is_err());

    assert!(case.collection_complete());
    assert_eq!(
        case.limitations().len(),
        l2_workbench::evidence::MAX_LIMITATIONS
    );
    Ok(())
}
