use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus, SourceRange},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn content_hashes_blobs_source_aliases() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"generic evidence";
    let first_blob = case.add_blob(bytes)?;
    let second_blob = case.add_blob(bytes)?;
    assert_eq!(first_blob, second_blob);
    let source_length = u64::try_from(bytes.len())?;
    let first_source = case.add_source(
        "first.bin",
        "file",
        source_length,
        &sha256(bytes),
        Some(&first_blob),
    )?;
    let second_source = case.add_source(
        "copy.bin",
        "file",
        source_length,
        &sha256(bytes),
        Some(&second_blob),
    )?;

    assert_eq!(first_source, second_source);
    assert_eq!(case.blobs().len(), 1);
    assert_eq!(case.sources().len(), 1);
    assert_eq!(
        case.sources().first().map(|source| source.label.as_str()),
        Some("first.bin")
    );
    assert_eq!(
        case.sources()
            .first()
            .and_then(|source| source.aliases.first())
            .map(String::as_str),
        Some("copy.bin")
    );
    Ok(())
}

#[test]
fn invalid_ranges_endpoints_not_case() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"abc";
    let blob = case.add_blob(bytes)?;
    let source = case.add_source("sample.bin", "file", 3, &sha256(bytes), Some(&blob))?;
    let invalid_range = SourceRange {
        source,
        packet: Some(1),
        offset: 2,
        length: 2,
    };
    assert!(
        case.add_node("literal", None, vec![invalid_range], json!({}))
            .is_err()
    );
    assert!(
        case.add_node("literal", Some("sha256:unknown"), Vec::new(), json!({}))
            .is_err()
    );
    assert_eq!(case.nodes().len(), 0);

    let node = case.add_node("literal", Some(&blob), Vec::new(), json!({}))?;
    assert!(
        case.add_edge(Edge {
            from: node,
            to: node + 1,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "unavailable endpoint".to_owned(),
        })
        .is_err()
    );
    assert_eq!(case.edges().len(), 0);
    Ok(())
}

#[test]
fn source_labels_use_basenames() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"x";
    assert!(
        case.add_source("nested/path.bin", "file", 1, &sha256(bytes), None)
            .is_err()
    );
    let source = case.add_source("artifact.bin", "file", 1, &sha256(bytes), None)?;
    let node = case.add_node(
        "literal_ip",
        None,
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 1,
        }],
        json!({ "role": "observed literal" }),
    )?;
    case.add_edge(Edge {
        from: node,
        to: node,
        relation: "same_value".to_owned(),
        status: EvidenceStatus::Unresolved,
        reason: "value equality does not establish ownership".to_owned(),
    })?;
    case.validate()?;
    Ok(())
}

#[test]
fn alias_limit_prevents_blob_attachment() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"same bytes";
    let digest = sha256(bytes);
    let source = case.add_source("primary.bin", "file", 10, &digest, None)?;
    for index in 0..l2_workbench::evidence::MAX_SOURCE_ALIASES {
        let label = format!("alias-{index}.bin");
        case.add_source(&label, "file", 10, &digest, None)?;
    }
    let blob = case.add_blob(bytes)?;
    let alias_count = case
        .sources()
        .first()
        .map(|entry| entry.aliases.len())
        .ok_or("source was not stored")?;
    assert!(
        case.add_source("overflow.bin", "file", 10, &digest, Some(&blob))
            .is_err()
    );
    let stored_source = case.sources().first().ok_or("source was not stored")?;
    assert_eq!(stored_source.id, source);
    assert_eq!(stored_source.aliases.len(), alias_count);
    assert!(stored_source.blob.is_none());
    Ok(())
}
