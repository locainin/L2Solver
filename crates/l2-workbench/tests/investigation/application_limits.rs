use super::{
    case_support::located_records,
    support::{fragment, tcp},
};
use l2_workbench::{
    investigation::{BuildInput, build},
    sha256,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn dns_omissions_mark_partial() -> Result<(), Box<dyn Error>> {
    let mut dns_message = vec![0; 12];
    let question_count = u16::try_from(l2_discovery::dns::MAX_ENTRIES + 1)?;
    dns_message
        .get_mut(4..6)
        .ok_or("DNS header is missing the question count")?
        .copy_from_slice(&question_count.to_be_bytes());
    for _ in 0..question_count {
        dns_message.extend_from_slice(&[0, 0, 1, 0, 1]);
    }
    let dns_length = u16::try_from(dns_message.len())?;
    let mut dns_frame = dns_length.to_be_bytes().to_vec();
    dns_frame.extend_from_slice(&dns_message);
    let payload = dns_frame.repeat(l2_workbench::application::MAX_ENTRIES);

    let mut frames = vec![tcp(false, 100, 2, b"")?];
    for (index, segment) in payload.chunks(60_000).enumerate() {
        let sequence_offset = u32::try_from(index * 60_000)?;
        frames.push(tcp(false, 101 + sequence_offset, 0x18, segment)?);
    }
    frames.push(fragment(
        0,
        &[
            0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0, b'a', b'b', b'c', b'd', b'e', b'f',
        ],
    )?);

    let (records, length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "coverage.pcap",
        length,
        sha256_hex: &sha256(b"coverage source"),
        records: &records,
        frames_seen: 4,
    })?;
    let checks = node(&result.case, "application_checks")?;
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == checks.blob.as_ref())
        .ok_or("missing structured parser coverage blob")?;
    let details: Value = serde_json::from_slice(&blob.bytes)?;
    assert_eq!(
        details
            .pointer("/dns_tcp/budget_omissions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(l2_workbench::application::MAX_ENTRIES)
    );
    assert!(
        result
            .case
            .nodes()
            .iter()
            .any(|node| node.kind == "udp_payload")
    );
    assert!(!result.complete);
    assert!(!result.case.collection_complete());
    assert!(result.case.limitations().iter().any(|limitation| {
        limitation.contains("Optional application parser candidates were omitted")
    }));
    Ok(())
}

#[test]
fn ftp_entries_mark_partial() -> Result<(), Box<dyn Error>> {
    let payload = b"NOOP\r\n".repeat(257);
    let (records, length) = located_records(vec![tcp(false, 100, 2, &payload)?])?;
    let result = build(BuildInput {
        label: "parser-budget.pcap",
        length,
        sha256_hex: &sha256(b"parser budget source"),
        records: &records,
        frames_seen: 1,
    })?;
    let checks = node(&result.case, "application_checks")?;
    let ftp = checks
        .details
        .get("ftp")
        .ok_or("missing FTP parser summary")?;
    assert_eq!(ftp.get("items"), Some(&Value::from(256)));
    assert_eq!(
        ftp.pointer("/unparsed/0/offset"),
        Some(&Value::from(256 * 6))
    );
    assert_eq!(ftp.pointer("/unparsed/0/length"), Some(&Value::from(6)));
    assert_eq!(
        ftp.pointer("/budget_omissions/0/budget"),
        Some(&Value::from("entries"))
    );
    assert_eq!(
        ftp.pointer("/budget_omissions/0/range/offset"),
        Some(&Value::from(256 * 6))
    );
    assert_eq!(
        ftp.pointer("/budget_omissions/0/range/length"),
        Some(&Value::from(6))
    );
    assert!(!result.complete);
    assert!(!result.case.collection_complete());
    assert!(result.case.limitations().iter().any(|limitation| {
        limitation.contains("Optional application parser candidates were omitted")
    }));
    Ok(())
}

#[test]
fn http_entries_mark_partial() -> Result<(), Box<dyn Error>> {
    let request = b"GET / HTTP/1.1\r\n\r\n";
    let payload = request.repeat(l2_workbench::application::MAX_ENTRIES + 1);
    let (records, length) = located_records(vec![tcp(false, 100, 2, &payload)?])?;
    let result = build(BuildInput {
        label: "http-parser-budget.pcap",
        length,
        sha256_hex: &sha256(b"http parser budget source"),
        records: &records,
        frames_seen: 1,
    })?;
    let checks = node(&result.case, "application_checks")?;
    let http = checks
        .details
        .get("http")
        .ok_or("missing HTTP parser summary")?;
    assert_eq!(
        http.get("messages"),
        Some(&Value::from(l2_workbench::application::MAX_ENTRIES))
    );
    assert_eq!(
        http.pointer("/budget_omissions/0/budget"),
        Some(&Value::from("entries"))
    );
    assert!(!result.complete);
    assert!(!result.case.collection_complete());
    assert!(result.case.limitations().iter().any(|limitation| {
        limitation.contains("Optional application parser candidates were omitted")
    }));
    Ok(())
}

#[test]
fn unsupported_syntax_preserves_collection_completeness() -> Result<(), Box<dyn Error>> {
    let (records, length) = located_records(vec![tcp(false, 100, 2, b"\0\r\n")?])?;
    let result = build(BuildInput {
        label: "unsupported-syntax.pcap",
        length,
        sha256_hex: &sha256(b"unsupported syntax source"),
        records: &records,
        frames_seen: 1,
    })?;
    let checks = node(&result.case, "application_checks")?;
    let ftp = checks
        .details
        .get("ftp")
        .ok_or("missing FTP parser summary")?;
    assert_eq!(ftp.get("status"), Some(&Value::from("unsupported")));
    assert_eq!(ftp.get("budget_omissions"), Some(&Value::Array(Vec::new())));
    assert_eq!(ftp.pointer("/unparsed/0/offset"), Some(&Value::from(0)));
    assert_eq!(ftp.pointer("/unparsed/0/length"), Some(&Value::from(3)));
    assert!(result.complete);
    assert!(result.case.collection_complete());
    Ok(())
}

fn node<'a>(
    case: &'a l2_workbench::evidence::Case,
    kind: &str,
) -> Result<&'a l2_workbench::evidence::Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == kind)
        .ok_or_else(|| format!("missing {kind} node").into())
}
