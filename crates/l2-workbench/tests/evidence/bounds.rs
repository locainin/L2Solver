use l2_workbench::{evidence::Case, sha256};
use serde_json::json;
use std::error::Error;

#[test]
fn blob_source_without_partial_mutation() -> Result<(), Box<dyn Error>> {
    let mut case = Case::with_blob_limit(l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES)?;
    let blob = vec![0x5a; l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES];
    case.add_blob(&blob)?;
    assert_eq!(
        case.blobs().first().map(|item| item.bytes.len()),
        Some(blob.len())
    );
    assert!(case.add_blob(b"additional unique bytes").is_err());
    assert_eq!(case.blobs().len(), 1);

    for index in 0..l2_workbench::evidence::MAX_SOURCES {
        let content = u64::try_from(index)?.to_le_bytes();
        let label = format!("source-{index}.bin");
        case.add_source(&label, "file", 8, &sha256(&content), None)?;
    }
    let source_count = case.sources().len();
    let content = b"extra";
    assert!(
        case.add_source("extra.bin", "file", 5, &sha256(content), None)
            .is_err()
    );
    assert_eq!(case.sources().len(), source_count);
    Ok(())
}

#[test]
fn aggregate_blob_new_unique() -> Result<(), Box<dyn Error>> {
    let mut case = Case::with_blob_limit(l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES)?;
    let bytes = vec![u8::MAX; l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES - 1];
    case.add_blob(&bytes)?;
    let retained = case.blobs().len();
    assert!(case.add_blob(b"two bytes").is_err());
    assert_eq!(case.blobs().len(), retained);
    Ok(())
}

#[test]
fn default_case_no_blob_ceiling() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = vec![0x5a; l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES];

    case.add_bytes_node("large", &bytes, Vec::new(), json!({}))?;
    case.add_bytes_node(
        "additional",
        b"additional unique bytes",
        Vec::new(),
        json!({}),
    )?;

    assert_eq!(case.blobs().len(), 2);
    assert_eq!(case.blob_byte_limit(), None);
    case.validate()?;
    Ok(())
}

#[test]
fn node_details_limit_rejects_addition() {
    let mut case = Case::new();
    let details = json!({ "note": "x".repeat(l2_workbench::evidence::MAX_NODE_DETAILS_BYTES) });
    assert!(case.add_node("literal", None, Vec::new(), details).is_err());
    assert!(case.nodes().is_empty());
}

#[test]
fn aggregate_details_without_next_node() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let exact_detail =
        serde_json::Value::String("x".repeat(l2_workbench::evidence::MAX_NODE_DETAILS_BYTES - 2));
    let full_nodes = l2_workbench::evidence::MAX_TOTAL_DETAILS_BYTES
        / l2_workbench::evidence::MAX_NODE_DETAILS_BYTES;
    for _ in 0..full_nodes {
        case.add_node("sample", None, Vec::new(), exact_detail.clone())?;
    }
    let node_count = case.nodes().len();
    assert!(
        case.add_node("sample", None, Vec::new(), serde_json::json!("x"))
            .is_err()
    );
    assert_eq!(case.nodes().len(), node_count);
    Ok(())
}

#[test]
fn node_quota_leaves_case_unchanged() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    for expected_id in 1..=l2_workbench::evidence::MAX_NODES {
        let id = case.add_node("observation", None, Vec::new(), json!({}))?;
        assert_eq!(usize::try_from(id)?, expected_id);
    }
    let node_count = case.nodes().len();
    assert!(
        case.add_node("overflow", None, Vec::new(), json!({}))
            .is_err()
    );
    assert_eq!(case.nodes().len(), node_count);
    Ok(())
}

#[test]
fn edge_quota_leaves_case_unchanged() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first = case.add_node("observation", None, Vec::new(), json!({}))?;
    let second = case.add_node("observation", None, Vec::new(), json!({}))?;
    for _ in 0..l2_workbench::evidence::MAX_EDGES {
        case.add_edge(l2_workbench::evidence::Edge {
            from: first,
            to: second,
            relation: "co_occurs".to_owned(),
            status: l2_workbench::evidence::EvidenceStatus::Observed,
            reason: "same input window".to_owned(),
        })?;
    }
    let edge_count = case.edges().len();
    assert!(
        case.add_edge(l2_workbench::evidence::Edge {
            from: first,
            to: second,
            relation: "co_occurs".to_owned(),
            status: l2_workbench::evidence::EvidenceStatus::Observed,
            reason: "same input window".to_owned(),
        })
        .is_err()
    );
    assert_eq!(case.edges().len(), edge_count);
    Ok(())
}
