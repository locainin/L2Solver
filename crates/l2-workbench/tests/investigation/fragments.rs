use super::{case_support::located_records, support::fragment};
use l2_workbench::{
    evidence::{Case, MAX_NODE_RANGES},
    investigation::{BuildInput, build},
    sha256,
};
use std::error::Error;

fn fragment_case(tail: &[u8]) -> Result<Case, Box<dyn Error>> {
    let (records, length) = located_records(vec![
        fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?,
        fragment(1, tail)?,
    ])?;
    Ok(build(BuildInput {
        label: "fragments.pcap",
        length,
        sha256_hex: &sha256(b"fragment source"),
        records: &records,
        frames_seen: 2,
    })?
    .case)
}

#[test]
fn recovered_udp_candidate_supplies_header() -> Result<(), Box<dyn Error>> {
    let case = fragment_case(b"abcdef")?;
    let candidate = case
        .nodes()
        .iter()
        .find(|node| node.kind == "fragment_candidate")
        .ok_or("missing fragment candidate")?;
    let payload = case
        .nodes()
        .iter()
        .find(|node| node.kind == "udp_payload")
        .ok_or("missing UDP payload")?;
    assert!(case.edges().iter().any(|edge| edge.from == candidate.id
        && edge.to == payload.id
        && edge.relation == "derived_from"));
    assert_eq!(candidate.ranges.len(), 2);
    assert_eq!(payload.ranges.len(), 1);
    assert_eq!(
        payload.ranges.first().and_then(|range| range.packet),
        Some(2)
    );
    Ok(())
}

#[test]
fn recovered_udp_length_exact_provenance() -> Result<(), Box<dyn Error>> {
    let case = fragment_case(b"abcdefX")?;
    let trailing = case
        .nodes()
        .iter()
        .find(|node| node.kind == "udp_trailing_bytes")
        .ok_or("missing recovered UDP trailing bytes")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == trailing.blob.as_ref())
        .ok_or("missing trailing blob")?;
    assert_eq!(blob.bytes, b"X");
    assert_eq!(trailing.ranges.len(), 1);
    assert_eq!(
        trailing
            .ranges
            .first()
            .map(|range| (range.packet, range.length)),
        Some((Some(2), 1))
    );
    assert!(
        case.edges()
            .iter()
            .any(|edge| edge.to == trailing.id && edge.relation == "derived_from")
    );
    Ok(())
}

#[test]
fn over_fragmented_http_extraction_omission() -> Result<(), Box<dyn Error>> {
    let mut frames = Vec::with_capacity(MAX_NODE_RANGES + 4);
    for _ in 1..MAX_NODE_RANGES {
        frames.push(fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?);
    }
    frames.push(fragment(1, b"abcdef")?);
    frames.push(fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?);
    let payload = b"POST /data HTTP/1.1\r\nContent-Length: 4\r\n\r\n4142";
    frames.extend([
        super::support::tcp(false, 100, 2, b"")?,
        super::support::tcp(false, 101, 0x18, payload)?,
        super::support::tcp(false, 101 + u32::try_from(payload.len())?, 0x11, b"")?,
    ]);
    let frames_seen = u64::try_from(frames.len())?;
    let (records, length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "over-fragmented.pcap",
        length,
        sha256_hex: &sha256(b"over-fragmented source"),
        records: &records,
        frames_seen,
    })?;

    let candidate = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "fragment_candidate")
        .ok_or("missing fragment candidate")?;
    assert_eq!(candidate.ranges.len(), MAX_NODE_RANGES);
    assert_eq!(
        candidate.details.pointer("/provenance/fragment_count"),
        Some(&serde_json::json!(MAX_NODE_RANGES + 1))
    );
    assert_eq!(
        candidate
            .details
            .pointer("/provenance/source_ranges_omitted"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        candidate.details.pointer("/coverage/missing"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        candidate.details.pointer("/coverage/omitted_observations"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        candidate.details.pointer("/unique_coverage"),
        Some(&serde_json::json!(false))
    );
    assert!(!result.complete);
    assert!(result.case.limitations().iter().any(|limitation| {
        limitation.contains("fragment candidate") && limitation.contains("source ranges")
    }));
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing later HTTP body")?;
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == body.blob.as_ref())
        .ok_or("missing later HTTP body blob")?;
    assert_eq!(blob.bytes, b"4142");
    Ok(())
}

#[test]
fn fragment_candidate_budget_origins() -> Result<(), Box<dyn Error>> {
    let mut frames = Vec::with_capacity(MAX_NODE_RANGES);
    for _ in 1..MAX_NODE_RANGES {
        frames.push(fragment(0x2000, &[0x9c, 0x40, 0x23, 0x45, 0, 14, 0, 0])?);
    }
    frames.push(fragment(1, b"abcdef")?);
    let frames_seen = u64::try_from(frames.len())?;
    let (records, length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "range-budget.pcap",
        length,
        sha256_hex: &sha256(b"range budget source"),
        records: &records,
        frames_seen,
    })?;
    let candidate = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "fragment_candidate")
        .ok_or("missing fragment candidate")?;
    assert_eq!(candidate.ranges.len(), MAX_NODE_RANGES);
    assert_eq!(
        candidate.details.pointer("/provenance/fragment_count"),
        Some(&serde_json::json!(MAX_NODE_RANGES))
    );
    assert_eq!(
        candidate
            .details
            .pointer("/provenance/source_ranges_omitted"),
        Some(&serde_json::json!(0))
    );
    assert!(result.complete);
    Ok(())
}
