use super::{case_support::located_records, support::tcp};
use l2_workbench::{
    investigation::{BuildInput, build},
    sha256,
};
use std::error::Error;

#[test]
fn tcp_run_blob_and_source_mapping_stay_bound_to_each_direction() -> Result<(), Box<dyn Error>> {
    let client_bytes = b"client payload";
    let server_bytes = b"server payload";
    let (records, source_length) = located_records(vec![
        tcp(false, 100, 0x02, b"")?,
        tcp(true, 200, 0x12, b"")?,
        tcp(false, 101, 0x18, client_bytes)?,
        tcp(true, 201, 0x18, server_bytes)?,
    ])?;
    let result = build(BuildInput {
        label: "two-direction-run.pcap",
        length: source_length,
        sha256_hex: &sha256(b"two-direction TCP source"),
        records: &records,
        frames_seen: u64::try_from(records.len())?,
    })?;

    for (packet, expected_bytes) in [(3, client_bytes), (4, server_bytes)] {
        let run = result
            .case
            .nodes()
            .iter()
            .find(|node| {
                node.kind == "tcp_byte_run"
                    && node.ranges.iter().any(|range| range.packet == Some(packet))
            })
            .ok_or("TCP byte-run node is missing")?;
        let blob_id = run.blob.as_deref().ok_or("TCP byte-run blob is missing")?;
        let blob = result
            .case
            .blob(blob_id)
            .ok_or("TCP byte-run blob was not retained")?;
        let source_length = run
            .ranges
            .iter()
            .filter(|range| range.packet == Some(packet))
            .try_fold(0_u64, |length, range| length.checked_add(range.length))
            .ok_or("TCP byte-run source length overflow")?;

        assert_eq!(blob.bytes, expected_bytes);
        assert_eq!(source_length, u64::try_from(expected_bytes.len())?);
    }
    Ok(())
}

#[test]
fn large_tcp_run_marks_partial() -> Result<(), Box<dyn Error>> {
    let run_bytes = vec![b'x'; 1_500_000];
    let mut frames = vec![tcp(false, 100, 0x02, b"")?];
    for (index, chunk) in run_bytes.chunks(60_000).enumerate() {
        let offset = u32::try_from(
            index
                .checked_mul(60_000)
                .ok_or("TCP payload offset overflow")?,
        )?;
        frames.push(tcp(false, 101 + offset, 0x18, chunk)?);
    }
    frames.push(tcp(
        false,
        101 + u32::try_from(run_bytes.len())?,
        0x11,
        b"",
    )?);
    let (records, source_length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "large-run.pcap",
        length: source_length,
        sha256_hex: &sha256(b"generic large TCP run source"),
        records: &records,
        frames_seen: u64::try_from(records.len())?,
    })?;

    assert!(!result.complete);
    assert!(!result.case.collection_complete());
    assert!(result.case.limitations().iter().any(|limitation| {
        limitation.starts_with("Optional application parser candidates were omitted")
    }));
    assert!(!result.case.limitations().iter().any(|limitation| {
        limitation.starts_with("Case analysis stopped after an evidence resource budget")
    }));
    let run_node = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "tcp_byte_run")
        .ok_or("large TCP byte-run node is missing")?;
    let run_blob_id = run_node
        .blob
        .as_deref()
        .ok_or("large TCP byte-run blob is missing")?;
    let run_blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| blob.id == run_blob_id)
        .ok_or("large TCP byte-run blob was not retained")?;
    assert_eq!(run_blob.bytes, run_bytes);

    let checks = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "application_checks")
        .ok_or("application parser coverage is missing")?;
    for parser in ["dns_tcp", "http", "ftp"] {
        assert_eq!(
            checks
                .details
                .pointer(&format!("/{parser}/budget_omissions/0/budget")),
            Some(&serde_json::json!("input_bytes"))
        );
    }

    let encoded = result.case.to_json()?;
    let restored = l2_workbench::evidence::Case::from_json(&encoded)?;
    let restored_blob = restored
        .blobs()
        .iter()
        .find(|blob| blob.id == run_blob_id)
        .ok_or("large TCP byte-run blob was not restored")?;
    assert_eq!(restored_blob.bytes, run_bytes);
    Ok(())
}
