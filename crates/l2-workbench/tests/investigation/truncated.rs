#[path = "../../../../tests/fixtures/truncated_tcp.rs"]
mod fixture;

use super::case_support::located_records;
use l2_workbench::{
    investigation::{BuildInput, build, build_selected_with_limits_and_memory},
    job::MemoryBudget,
    reconstruction::Limits,
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn truncated_conflict_not_complete_body() -> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let mut conflict = payload.to_vec();
    let body = conflict.len() - 3;
    *conflict.get_mut(body).ok_or("missing body")? = b'x';
    let frames = vec![
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(101, 0x18, payload, 0)?,
        fixture::tcp(101, 0x18, &conflict, 8)?,
        fixture::tcp(101 + u32::try_from(payload.len())?, 0x11, b"", 0)?,
    ];
    let (records, length) = located_records(frames)?;
    let result = build(BuildInput {
        label: "truncated.pcap",
        length,
        sha256_hex: &sha256(b"truncated source"),
        records: &records,
        frames_seen: 4,
    })?;
    assert!(!result.complete);
    let packet = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "packet" && node.details.get("record") == Some(&json!(3)))
        .ok_or("missing truncated packet")?;
    assert_eq!(
        packet
            .details
            .pointer("/truncated_tcp_payload/missing_bytes"),
        Some(&json!(8))
    );
    assert_eq!(
        packet
            .details
            .pointer("/truncated_tcp_payload/captured_bytes"),
        Some(&json!(payload.len()))
    );
    assert!(!result.case.nodes().iter().any(|node| {
        node.kind == "http_body"
            && node.details.get("status").and_then(|value| value.as_str()) == Some("complete")
    }));
    Ok(())
}

#[test]
fn sparse_range_respects_memory_budget() -> Result<(), Box<dyn Error>> {
    let frames = vec![
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(1_000_101, 0x18, b"a", 0)?,
    ];
    let (records, length) = located_records(frames)?;
    let memory = MemoryBudget::new(1024 * 1024);
    let result = build_selected_with_limits_and_memory(
        BuildInput {
            label: "sparse.pcap",
            length,
            sha256_hex: &sha256(b"sparse source"),
            records: &records,
            frames_seen: 2,
        },
        2,
        Limits::default(),
        &memory,
    )?;
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("missing capture summary")?;
    assert_eq!(
        summary.details.get("unmeasured_omitted_ranges"),
        Some(&json!(1))
    );
    assert!(!result.complete);
    assert!(memory.snapshot()?.peak_bytes <= 1024 * 1024);
    Ok(())
}

#[test]
fn conflict_spans_mark_partial() -> Result<(), Box<dyn Error>> {
    let base = vec![b'a'; 8_194];
    let changed: Vec<_> = (0..base.len())
        .map(|offset| if offset % 2 == 0 { b'a' } else { b'x' })
        .collect();
    let frames = vec![
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(101, 0x18, &base, 0)?,
        fixture::tcp(101, 0x18, &changed, 0)?,
    ];
    let (records, length) = located_records(frames)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let result = build_selected_with_limits_and_memory(
        BuildInput {
            label: "conflicts.pcap",
            length,
            sha256_hex: &sha256(b"conflicting source"),
            records: &records,
            frames_seen: 3,
        },
        3,
        Limits::default(),
        &memory,
    )?;
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("missing capture summary")?;
    assert_eq!(
        summary.details.get("omitted_sequence_ranges"),
        Some(&json!(1))
    );
    assert!(
        summary
            .details
            .get("omitted_tcp_bytes")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|count| count > 0)
    );
    assert!(!result.complete);
    assert!(result.case.nodes().len() < 10_000);
    Ok(())
}
