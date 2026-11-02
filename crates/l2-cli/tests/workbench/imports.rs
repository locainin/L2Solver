use super::support::{ipv4_header_frame, path_arg, run, save_case};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, MAX_EDGES};
use serde_json::json;
use std::{collections::BTreeSet, error::Error, fs};

#[test]
fn import_relationships_retained_packet_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("addresses.txt");
    fs::write(&imported, b"10.2.0.1\n10.1.0.1\n")?;
    let mut case = Case::new();
    let packet = case.add_bytes_node(
        "packet",
        &ipv4_header_frame([10, 1, 0, 1], [10, 1, 0, 2]),
        Vec::new(),
        json!({"link_type":1,"source_ip":"10.2.0.1","destination_ip":"10.2.0.2"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "file",
        ],
        &[],
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let imported_case = Case::from_json(&output.stdout)?;
    let linked_addresses: BTreeSet<_> = imported_case
        .nodes()
        .iter()
        .filter(|node| node.kind == "ipv4_literal")
        .filter(|node| {
            imported_case
                .edges()
                .iter()
                .any(|edge| edge.from == node.id && edge.to == packet)
        })
        .filter_map(|node| {
            node.details
                .get("parsed")
                .and_then(serde_json::Value::as_str)
        })
        .collect();
    assert_eq!(linked_addresses, BTreeSet::from(["10.1.0.1"]));
    Ok(())
}

#[test]
fn import_not_ethernet_declared_type() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("address.txt");
    fs::write(&imported, b"10.3.0.1")?;
    let mut case = Case::new();
    let packet = case.add_bytes_node(
        "packet",
        &ipv4_header_frame([10, 3, 0, 1], [10, 3, 0, 2]),
        Vec::new(),
        json!({"link_type":127}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "file",
        ],
        &[],
    )?;
    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    assert!(
        !imported_case
            .edges()
            .iter()
            .any(|edge| { edge.to == packet && edge.relation == "same_address_value" })
    );
    Ok(())
}

#[test]
fn import_packet_without_ip_header() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("address.txt");
    fs::write(&imported, b"10.4.0.1")?;
    let mut case = Case::new();
    let missing_bytes = case.add_node(
        "packet",
        None,
        Vec::new(),
        json!({"link_type":1,"source_ip":"10.4.0.1"}),
    )?;
    let non_ip_bytes = case.add_bytes_node(
        "packet",
        &[0; 14],
        Vec::new(),
        json!({"link_type":1,"source_ip":"10.4.0.1"}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "file",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    assert!(!imported_case.edges().iter().any(|edge| {
        edge.relation == "same_address_value" && [missing_bytes, non_ip_bytes].contains(&edge.to)
    }));
    Ok(())
}

#[test]
fn import_packet_shares_retained_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("address.txt");
    fs::write(&imported, b"10.5.0.1")?;
    let mut case = Case::new();
    let frame = ipv4_header_frame([10, 5, 0, 1], [10, 5, 0, 2]);
    let first = case.add_bytes_node("packet", &frame, Vec::new(), json!({"link_type":1}))?;
    let second = case.add_bytes_node("packet", &frame, Vec::new(), json!({"link_type":1}))?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "file",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    let linked_packets: BTreeSet<_> = imported_case
        .edges()
        .iter()
        .filter(|edge| edge.relation == "same_address_value")
        .map(|edge| edge.to)
        .collect();
    assert_eq!(linked_packets, BTreeSet::from([first, second]));
    Ok(())
}

#[test]
fn import_prior_incomplete_collection_status() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("candidate.bin");
    fs::write(&imported, b"\0\xff")?;
    let mut case = Case::new();
    case.mark_incomplete("Some earlier observations were omitted")?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
        ],
        &[],
    )?;

    assert_eq!(output.status.code(), Some(3));
    let imported_case = Case::from_json(&output.stdout)?;
    assert!(!imported_case.collection_complete());
    assert!(
        imported_case
            .nodes()
            .iter()
            .any(|node| node.kind == "imported_source")
    );
    Ok(())
}

#[test]
fn import_file_signature_source_node() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("image.bin");
    fs::write(&imported, b"RIFF\x11\x22\x33\x44WAVE")?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    let source = imported_case
        .nodes()
        .iter()
        .find(|node| node.kind == "imported_source")
        .ok_or("imported source node is missing")?;
    let signature = imported_case
        .nodes()
        .iter()
        .find(|node| node.kind == "file_signature_match")
        .ok_or("file signature node is missing")?;
    assert!(source.id < signature.id);
    assert_eq!(
        source.details.get("scan_mode"),
        Some(&json!("literal-signature"))
    );
    assert_eq!(signature.details.get("rule_id"), Some(&json!("riff-wave")));
    let edge = imported_case
        .edges()
        .iter()
        .find(|edge| {
            edge.from == source.id
                && edge.to == signature.id
                && edge.relation == "contains_signature"
                && edge.status == EvidenceStatus::Observed
        })
        .ok_or("signature relationship is missing")?;
    assert!(edge.reason.contains("exact or explicitly masked"));
    Ok(())
}

#[test]
fn duplicate_address_not_relationship_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("address.bin");
    fs::write(&imported, b"10.0.0.1")?;
    let mut case = Case::new();
    let packet = case.add_bytes_node(
        "packet",
        &ipv4_header_frame([10, 0, 0, 1], [10, 0, 0, 1]),
        Vec::new(),
        json!({"link_type":1,"source_ip":"10.0.0.1","destination_ip":"10.0.0.1"}),
    )?;
    for _ in 0..MAX_EDGES - 1 {
        case.add_edge(Edge {
            from: packet,
            to: packet,
            relation: "retained".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "bounded fixture edge".to_owned(),
        })?;
    }
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
        ],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let imported_case = Case::from_json(&output.stdout)?;
    assert!(imported_case.collection_complete());
    assert_eq!(imported_case.edges().len(), MAX_EDGES);
    assert_eq!(
        imported_case
            .edges()
            .iter()
            .filter(|edge| edge.relation == "same_address_value")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn omitted_optional_relationship_collection_complete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("image.bin");
    fs::write(&imported, b"\x89PNG\r\n\x1a\n")?;
    let mut case = Case::new();
    let anchor = case.add_node("anchor", None, Vec::new(), json!({}))?;
    for _ in 0..MAX_EDGES {
        case.add_edge(Edge {
            from: anchor,
            to: anchor,
            relation: "retained".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "bounded fixture edge".to_owned(),
        })?;
    }
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    assert!(
        imported_case.collection_complete(),
        "optional relationship coverage must not change retained-source completeness"
    );
    assert!(
        imported_case
            .limitations()
            .iter()
            .any(|limitation| { limitation.contains("file-signature relationships were omitted") })
    );
    assert!(
        !imported_case
            .edges()
            .iter()
            .any(|edge| edge.relation == "contains_signature")
    );
    Ok(())
}

#[test]
fn attachment_import_ahead_optional_observations() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("repeated-values.bin");
    let mut bytes = Vec::new();
    for _ in 0..5_000 {
        bytes.extend_from_slice(b"entry-value\0");
    }
    fs::write(&imported, &bytes)?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
            "--scan-mode",
            "none",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    assert_eq!(imported_case.nodes().len(), 1);
    let source = imported_case
        .nodes()
        .first()
        .ok_or("imported source node is missing")?;
    assert_eq!(source.kind, "imported_source");
    assert_eq!(source.id, 1);
    assert_eq!(source.details.get("scan_mode"), Some(&json!("none")));
    assert_eq!(source.details.get("scanned_bytes"), Some(&json!(0)));
    assert_eq!(
        source.details.get("unscanned_bytes"),
        Some(&json!(bytes.len()))
    );
    assert_eq!(
        imported_case
            .blobs()
            .first()
            .map(|blob| blob.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    Ok(())
}

#[test]
fn import_attach_more_legacy_default() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("large.bin");
    let bytes = vec![0xA5; 1_048_577];
    fs::write(&imported, &bytes)?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--kind",
            "binary",
            "--scan-mode",
            "none",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    let source = imported_case
        .nodes()
        .first()
        .ok_or("imported source node is missing")?;
    assert_eq!(source.details.get("source_complete"), Some(&json!(true)));
    assert_eq!(
        imported_case.blobs().first().map(|blob| blob.bytes.len()),
        Some(bytes.len())
    );
    Ok(())
}

#[test]
fn import_explicit_without_changing_case() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("over-limit.bin");
    fs::write(&imported, b"more than eight bytes")?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;
    let original_case = fs::read(&case_path)?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--max-input-bytes",
            "8",
            "--scan-mode",
            "none",
        ],
        &[],
    )?;

    assert!(!output.status.success());
    assert_eq!(output.stdout.len(), 0);
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds the input byte ceiling"));
    assert_eq!(fs::read(&case_path)?, original_case);
    Ok(())
}

#[test]
fn import_partial_coverage_source_details() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("partial.txt");
    let bytes = b"first-string\0second-string";
    fs::write(&imported, bytes)?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--max-scan-bytes",
            "12",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    let source = imported_case
        .nodes()
        .first()
        .ok_or("imported source node is missing")?;
    assert_eq!(source.id, 1);
    assert_eq!(source.details.get("scanned_offset"), Some(&json!(0)));
    assert_eq!(source.details.get("scanned_bytes"), Some(&json!(12)));
    assert_eq!(
        source.details.get("unscanned_bytes"),
        Some(&json!(bytes.len() - 12))
    );
    assert_eq!(source.details.get("scan_complete"), Some(&json!(false)));
    assert_eq!(
        imported_case
            .nodes()
            .iter()
            .filter(|node| node.kind == "ascii_string")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn import_finding_not_source_completeness() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let imported = directory.path().join("many-strings.bin");
    let mut bytes = Vec::new();
    for _ in 0..9 {
        bytes.extend_from_slice(b"text\0");
    }
    fs::write(&imported, &bytes)?;
    let case_path = save_case(directory.path(), "case.json", &Case::new())?;

    let output = run(
        &[
            "import",
            path_arg(&case_path)?,
            path_arg(&imported)?,
            "--max-findings",
            "2",
        ],
        &[],
    )?;

    assert!(output.status.success());
    let imported_case = Case::from_json(&output.stdout)?;
    let source = imported_case
        .nodes()
        .first()
        .ok_or("imported source node is missing")?;
    assert_eq!(source.details.get("source_complete"), Some(&json!(true)));
    assert_eq!(source.details.get("scan_complete"), Some(&json!(false)));
    assert_eq!(source.details.get("retained_findings"), Some(&json!(2)));
    assert_eq!(source.details.get("omitted_findings"), Some(&json!(7)));
    assert_eq!(imported_case.nodes().len(), 3);
    assert!(imported_case.collection_complete());
    Ok(())
}
