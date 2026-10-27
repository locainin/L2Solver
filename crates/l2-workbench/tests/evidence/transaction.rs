use l2_workbench::{
    evidence::{Case, Edge, EvidenceError, EvidenceStatus, SourceRange},
    sha256,
};
use serde_json::json;

#[test]
fn transaction_commits_case_changes() -> Result<(), EvidenceError> {
    let mut case = Case::with_blob_limit(64)?;

    let result = case.transaction(|case| {
        let source_bytes = b"captured source";
        let blob = case.add_blob(source_bytes)?;
        let source = case.add_source(
            "capture.bin",
            "file",
            15,
            &sha256(source_bytes),
            Some(&blob),
        )?;
        let first = case.add_node(
            "observation",
            Some(&blob),
            vec![SourceRange {
                source,
                packet: None,
                offset: 0,
                length: 4,
            }],
            json!({"part": "first"}),
        )?;
        let second = case.add_bytes_node("derived", b"derived", Vec::new(), json!({}))?;
        case.add_edge(Edge {
            from: second,
            to: first,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "derived from the retained source".to_owned(),
        })?;
        case.mark_incomplete("The transaction records a bounded sample")?;
        Ok((first, second))
    })?;

    assert_eq!(result, (1, 2));
    assert_eq!(case.sources().len(), 1);
    assert_eq!(case.blobs().len(), 2);
    assert_eq!(case.nodes().len(), 2);
    assert_eq!(case.edges().len(), 1);
    assert_eq!(
        case.limitations(),
        &["The transaction records a bounded sample"]
    );
    assert!(!case.collection_complete());
    assert_eq!(case.blob_byte_limit(), Some(64));
    case.validate()?;
    Ok(())
}

#[test]
fn transaction_error_restores_case() -> Result<(), EvidenceError> {
    let mut case = Case::with_blob_limit(64)?;
    let original_bytes = b"original";
    let original_blob = case.add_blob(original_bytes)?;
    let original_source =
        case.add_source("original.bin", "file", 8, &sha256(original_bytes), None)?;
    let original_node = case.add_node(
        "original",
        Some(&original_blob),
        vec![SourceRange {
            source: original_source,
            packet: None,
            offset: 0,
            length: 2,
        }],
        json!({"existing": true}),
    )?;
    let before = case.try_clone()?;

    let result = case.transaction(|case| {
        case.add_bytes_node("new", b"new blob", Vec::new(), json!({"count": 2}))?;
        case.add_source(
            "alternate.bin",
            "file",
            8,
            &sha256(original_bytes),
            Some(&original_blob),
        )?;
        case.add_source("new-source.bin", "file", 1, &"a".repeat(64), None)?;
        case.add_edge(Edge {
            from: original_node,
            to: 2,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "a later observation supports the original".to_owned(),
        })?;
        case.mark_incomplete("A later collection step was omitted")?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });

    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case, before);
    assert_eq!(case.blob_byte_limit(), Some(64));
    assert!(
        case.sources()
            .first()
            .is_some_and(|source| source.aliases.is_empty() && source.blob.is_none())
    );
    case.validate()?;
    Ok(())
}

#[test]
fn rollback_removes_dedup_index() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    let bytes = b"retry blob";
    let expected_id = format!("sha256:{}", sha256(bytes));

    let result = case.transaction(|case| {
        assert_eq!(case.add_blob(bytes)?, expected_id);
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert!(case.blobs().is_empty());

    assert_eq!(case.add_blob(bytes)?, expected_id);
    case.add_bytes_node("retry", bytes, Vec::new(), json!({}))?;
    case.validate()?;
    Ok(())
}

#[test]
fn nested_transactions_follow_results() -> Result<(), EvidenceError> {
    let mut case = Case::new();

    let result = case.transaction(|case| {
        case.add_limitation("outer change")?;
        case.transaction(|case| case.add_limitation("inner committed change"))?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert!(case.limitations().is_empty());
    assert!(case.collection_complete());

    case.transaction(|case| {
        case.add_limitation("outer committed change")?;
        let inner = case.transaction(|case| {
            case.mark_incomplete("inner rollback")?;
            Err::<(), _>(EvidenceError::InvalidSourceRange)
        });
        assert_eq!(inner, Err(EvidenceError::InvalidSourceRange));
        Ok(())
    })?;

    assert_eq!(case.limitations(), &["outer committed change"]);
    assert!(case.collection_complete());
    case.validate()?;
    Ok(())
}
