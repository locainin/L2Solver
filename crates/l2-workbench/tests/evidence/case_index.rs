use super::{Case, Edge, EvidenceError, EvidenceStatus, SourceRange};

#[test]
fn edge_index_tracks_large_relation_sets_and_statuses() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    let from = case.add_bytes_node("index_test", b"from", Vec::new(), serde_json::json!({}))?;
    let to = case.add_bytes_node("index_test", b"to", Vec::new(), serde_json::json!({}))?;

    for value in 0..65_536 {
        case.add_edge(Edge {
            from,
            to,
            relation: format!("relation-{value}"),
            status: EvidenceStatus::Observed,
            reason: "large relation index".to_owned(),
        })?;
    }
    case.add_edge(Edge {
        from,
        to,
        relation: "relation-65535".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: "status is part of the relation identity".to_owned(),
    })?;

    assert_eq!(case.edge_index.len(), 2 * 65_537);
    assert!(case.has_edge(from, to, "relation-65535", EvidenceStatus::Observed));
    assert!(case.has_edge(from, to, "relation-65535", EvidenceStatus::Hypothesis));
    assert!(!case.has_edge(
        from,
        to,
        "relation-65535",
        EvidenceStatus::ConstraintSatisfied
    ));

    Ok(())
}

#[test]
fn exact_edge_lookup_checks_text_after_a_hash_collision() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    let from = case.add_node("from", None, Vec::new(), serde_json::json!({}))?;
    let to = case.add_node("to", None, Vec::new(), serde_json::json!({}))?;
    let first = Edge {
        from,
        to,
        relation: "supports".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "first reason".to_owned(),
    };
    let second = Edge {
        reason: "different reason".to_owned(),
        ..first.clone()
    };
    case.add_edge(first.clone())?;
    case.add_edge(second)?;

    // Put a different edge at the hash head to exercise collision resolution
    let key = super::edge_index_key(&case.edge_hash, &first, true);
    case.edge_index.insert(key, 1);
    let link = case
        .edge_links
        .get_mut(1)
        .ok_or(EvidenceError::InvalidJson)?;
    link.exact = 1;
    assert!(case.contains_exact_edge(
        from,
        to,
        "supports",
        EvidenceStatus::Observed,
        "first reason"
    ));
    assert!(!case.contains_exact_edge(from, to, "supports", EvidenceStatus::Observed, "missing"));
    Ok(())
}

#[test]
fn coarse_edge_lookup_checks_relation_after_a_hash_collision() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    let from = case.add_node("from", None, Vec::new(), serde_json::json!({}))?;
    let to = case.add_node("to", None, Vec::new(), serde_json::json!({}))?;
    let first = Edge {
        from,
        to,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "first relation".to_owned(),
    };
    let second = Edge {
        relation: "contains_member".to_owned(),
        ..first.clone()
    };
    case.add_edge(first.clone())?;
    case.add_edge(second)?;

    // Put a different relation at the collision-chain head
    let key = super::edge_index_key(&case.edge_hash, &first, false);
    case.edge_index.insert(key, 1);
    case.edge_links
        .get_mut(1)
        .ok_or(EvidenceError::InvalidJson)?
        .coarse = 0;
    assert!(!case.has_edge(from, to, "parsed_as", EvidenceStatus::Observed));
    let link = case
        .edge_links
        .get_mut(1)
        .ok_or(EvidenceError::InvalidJson)?;
    link.coarse = 1;
    assert!(case.has_edge(from, to, "parsed_as", EvidenceStatus::Observed));
    Ok(())
}

#[test]
fn inconsistent_blob_byte_total_is_fatal_not_a_quota_omission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut case = Case::new();
    case.add_bytes_node("sample", b"blob", Vec::new(), serde_json::json!({}))?;
    case.blob_bytes += 1;

    let error = case
        .validate()
        .err()
        .ok_or_else(|| std::io::Error::other("the cached total was accepted"))?;
    assert_eq!(
        error,
        EvidenceError::InconsistentResourceCount {
            field: "blob bytes",
        }
    );
    assert_eq!(crate::recovery::classify_case_evidence_quota(&error), None);

    Ok(())
}

#[test]
fn inconsistent_source_range_total_is_fatal_not_a_quota_omission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut case = Case::new();
    let source = case.add_source("sample.bin", "file", 4, &crate::sha256(b"data"), None)?;
    case.add_node(
        "sample",
        None,
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 1,
        }],
        serde_json::json!({}),
    )?;
    case.range_count += 1;

    let error = case
        .validate()
        .err()
        .ok_or_else(|| std::io::Error::other("the cached total was accepted"))?;
    assert_eq!(
        error,
        EvidenceError::InconsistentResourceCount {
            field: "source ranges",
        }
    );
    assert_eq!(crate::recovery::classify_case_evidence_quota(&error), None);

    Ok(())
}
