use l2_workbench::evidence::{Case, ImportScanMode, ImportScanOptions, MAX_BLOB_TOTAL_BYTES};
use std::error::Error;

#[test]
fn import_ip_ascii_source_offsets() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"host=192.0.2.1\nname=sample\n";
    let report = case.scan_import("settings.txt", "text", bytes)?;
    assert_eq!(report.ipv4_literals, 1);
    assert!(report.ascii_strings >= 1);
    assert!(report.source_complete);
    assert!(report.scan_complete);
    assert_eq!(report.scanned_bytes, bytes.len());
    assert_eq!(report.unscanned_bytes, 0);
    assert!(case.collection_complete());
    assert_eq!(report.source_node_id, 1);
    assert!(report.node_ids.iter().all(|id| *id > report.source_node_id));

    let address = case
        .nodes()
        .iter()
        .find(|node| node.kind == "ipv4_literal")
        .ok_or("IPv4 literal node was not recorded")?;
    let range = address
        .ranges
        .first()
        .ok_or("IPv4 source range was not recorded")?;
    assert_eq!(range.offset, 5);
    assert_eq!(range.length, 9);
    assert_eq!(range.packet, None);

    let text = case
        .nodes()
        .iter()
        .find(|node| node.kind == "ascii_string")
        .ok_or("ASCII string node was not recorded")?;
    let string_range = text
        .ranges
        .first()
        .ok_or("ASCII source range was not recorded")?;
    assert_eq!(string_range.offset, 0);
    assert_eq!(string_range.length, 14);
    case.validate()?;
    Ok(())
}

#[test]
fn finding_free_limited_coverage_visible() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let report = case.scan_import("bytes.bin", "binary", b"\0\xff")?;

    assert_eq!(report.retained_findings, 0);
    assert!(report.source_complete);
    assert!(report.scan_complete);
    assert!(!report.limitations.is_empty());
    assert!(case.collection_complete());
    Ok(())
}

#[test]
fn import_supported_file_signatures_candidates() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"\x89PNG\r\n\x1a\nimported bytes";
    let report = case.scan_import("image.bin", "binary", bytes)?;

    assert_eq!(report.file_signatures, 1);
    let signature = case
        .nodes()
        .iter()
        .find(|node| node.kind == "file_signature_match")
        .ok_or("file signature match was not retained")?;
    let range = signature
        .ranges
        .first()
        .ok_or("file signature source range is missing")?;
    assert_eq!((range.offset, range.length), (0, 8));
    assert_eq!(range.packet, None);
    assert_eq!(
        signature.details.get("rule_id"),
        Some(&serde_json::json!("png"))
    );
    assert_eq!(
        signature.details.pointer("/catalogue/version"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        signature.details.pointer("/catalogue/reviewed_on"),
        Some(&serde_json::json!("2026-10-22"))
    );
    assert!(
        signature
            .details
            .get("interpretation")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| text.contains("candidate"))
    );
    Ok(())
}

#[test]
fn import_ipv6_ranges_separate_wrappers() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"[2001:db8::1] service=192.0.2.1:443";
    let report = case.scan_import("addresses.txt", "text", bytes)?;

    assert_eq!(report.ipv6_literals, 1);
    assert_eq!(report.ipv4_literals, 1);
    let ipv6 = case
        .nodes()
        .iter()
        .find(|node| node.kind == "ipv6_literal")
        .ok_or("IPv6 literal node was not recorded")?;
    let ipv6_range = ipv6.ranges.first().ok_or("IPv6 range was not recorded")?;
    assert_eq!((ipv6_range.offset, ipv6_range.length), (1, 11));

    let ipv4 = case
        .nodes()
        .iter()
        .find(|node| node.kind == "ipv4_literal")
        .ok_or("IPv4 literal node was not recorded")?;
    let ipv4_range = ipv4.ranges.first().ok_or("IPv4 range was not recorded")?;
    assert_eq!((ipv4_range.offset, ipv4_range.length), (22, 9));
    Ok(())
}

#[test]
fn attachment_import_without_observation_nodes() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut bytes = Vec::new();
    for _ in 0..5_000 {
        bytes.extend_from_slice(b"entry-value\0");
    }
    let options = ImportScanOptions {
        mode: ImportScanMode::None,
        ..ImportScanOptions::default()
    };

    let report = case.scan_import_with_options("large.txt", "binary", &bytes, options)?;

    assert!(report.source_complete);
    assert!(!report.scan_complete);
    assert_eq!(report.scanned_bytes, 0);
    assert_eq!(report.unscanned_bytes, bytes.len());
    assert_eq!(report.retained_findings, 0);
    assert_eq!(report.omitted_findings, 0);
    assert_eq!(case.nodes().len(), 1);
    assert_eq!(
        case.nodes().first().map(|node| node.kind.as_str()),
        Some("imported_source")
    );
    assert_eq!(
        case.blobs().first().map(|blob| blob.bytes.as_slice()),
        Some(bytes.as_slice())
    );
    case.validate()?;
    Ok(())
}

#[test]
fn attachment_import_larger_legacy_default() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = vec![0xA5; 1_048_577];
    let options = ImportScanOptions {
        mode: ImportScanMode::None,
        ..ImportScanOptions::default()
    };

    let report = case.scan_import_with_options("large.bin", "binary", &bytes, options)?;

    assert_eq!(report.source_length, u64::try_from(bytes.len())?);
    assert!(report.source_complete);
    assert_eq!(
        case.blobs().first().map(|blob| blob.bytes.len()),
        Some(bytes.len())
    );
    case.validate()?;
    Ok(())
}

#[test]
fn literal_exact_partial_byte_coverage() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let bytes = b"first-string\0second-string";
    let options = ImportScanOptions {
        max_scan_bytes: 12,
        ..ImportScanOptions::default()
    };

    let report = case.scan_import_with_options("partial.bin", "binary", bytes, options)?;

    assert_eq!(report.scanned_offset, 0);
    assert_eq!(report.scanned_bytes, 12);
    assert_eq!(report.unscanned_bytes, bytes.len() - 12);
    assert!(!report.scan_complete);
    assert!(report.source_complete);
    Ok(())
}

#[test]
fn literal_exact_finding_budget_exhausted() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    for _ in 0..9 {
        bytes.extend_from_slice(b"text\0");
    }
    let mut case = Case::new();
    let options = ImportScanOptions {
        max_findings: 2,
        ..ImportScanOptions::default()
    };

    let report = case.scan_import_with_options("many-strings.bin", "binary", &bytes, options)?;

    assert_eq!(report.ascii_strings, 9);
    assert_eq!(report.retained_findings, 2);
    assert_eq!(report.omitted_findings, 7);
    assert!(report.source_complete);
    assert!(!report.scan_complete);
    assert!(case.collection_complete());
    Ok(())
}

#[test]
fn failed_import_leaves_case_unchanged() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_node("existing", None, Vec::new(), serde_json::json!({}))?;
    let before = case.try_clone()?;

    assert!(
        case.scan_import("invalid\nlabel", "binary", b"contents")
            .is_err()
    );
    assert_eq!(case, before);
    Ok(())
}

#[test]
fn import_omitted_strings_finding_budget() -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    for _ in 0..(l2_workbench::evidence::MAX_IMPORT_FINDINGS + 2) {
        bytes.extend_from_slice(b"text\0");
    }
    let mut case = Case::new();
    let report = case.scan_import("many-strings.bin", "binary", &bytes)?;
    assert!(report.source_complete);
    assert!(!report.scan_complete);
    assert!(case.collection_complete());
    assert!(report.omitted_findings > 0);
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("observations were omitted") })
    );
    assert!(case.nodes().len() <= l2_workbench::evidence::MAX_IMPORT_FINDINGS + 1);
    Ok(())
}

#[test]
fn import_case_blob_not_retained() -> Result<(), Box<dyn Error>> {
    let mut case = Case::with_blob_limit(MAX_BLOB_TOTAL_BYTES)?;
    let bytes = vec![0x5a; MAX_BLOB_TOTAL_BYTES];
    let blob = case.add_blob(&bytes)?;
    case.add_node(
        "retained_blob",
        Some(&blob),
        Vec::new(),
        serde_json::json!({}),
    )?;

    let report = case.scan_import("small.bin", "binary", b"\0\xff")?;

    assert!(!report.blob_retained);
    assert!(!report.source_complete);
    assert!(report.scan_complete);
    assert!(!case.collection_complete());
    case.validate()?;
    Ok(())
}
