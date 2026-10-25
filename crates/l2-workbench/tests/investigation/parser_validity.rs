use super::{case_support::located_records, support::tcp};
use l2_workbench::{
    investigation::{BuildInput, build},
    sha256,
};
use std::error::Error;

#[test]
fn invalid_ftp_not_evidence_incomplete() -> Result<(), Box<dyn Error>> {
    let mut payload = b"AB\0".to_vec();
    payload.extend(std::iter::repeat_n(
        b'A',
        l2_workbench::application::MAX_LINE_BYTES,
    ));
    let (records, length) = located_records(vec![tcp(false, 100, 2, &payload)?])?;
    let result = build(BuildInput {
        label: "unknown-payload.pcap",
        length,
        sha256_hex: &sha256(b"unknown retained source"),
        records: &records,
        frames_seen: 1,
    })?;
    let checks = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "application_checks")
        .ok_or("missing application checks")?;
    assert_eq!(
        checks
            .details
            .pointer("/ftp/status")
            .and_then(serde_json::Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        checks
            .details
            .pointer("/ftp/budget_omissions")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert!(result.complete);
    assert!(result.case.collection_complete());
    assert!(
        result
            .case
            .nodes()
            .iter()
            .any(|node| node.kind == "tcp_byte_run")
    );
    Ok(())
}
