use super::{case_support::located_records, support::tcp};
use l2_workbench::{
    investigation::{BuildInput, RecordWindow, build_window},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn explicit_window_numbers_file_provenance() -> Result<(), Box<dyn Error>> {
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, b"ab")?,
        tcp(false, 103, 0x18, b"cd")?,
        tcp(false, 105, 0x11, b"")?,
    ])?;
    let input = BuildInput {
        label: "window.pcap",
        length,
        sha256_hex: &sha256(b"whole source"),
        records: records.get(2..).ok_or("missing window records")?,
        frames_seen: 4,
    };
    let result = build_window(input, RecordWindow { first: 3, last: 4 })?;
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("missing summary")?;
    assert_eq!(
        summary.details.get("record_window"),
        Some(&json!({"first":3,"last":4}))
    );
    assert_eq!(summary.details.get("outside_scope_frames"), Some(&json!(2)));
    assert_eq!(summary.details.get("omitted_frames"), Some(&json!(0)));
    let packets: Vec<_> = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .collect();
    assert_eq!(packets.len(), 2);
    assert_eq!(
        packets.first().and_then(|node| node.details.get("record")),
        Some(&json!(3))
    );
    assert_eq!(
        packets
            .first()
            .and_then(|node| node.ranges.first())
            .and_then(|range| range.packet),
        Some(3)
    );
    assert!(result.complete);
    assert!(
        result
            .case
            .limitations()
            .iter()
            .any(|text| text.contains("selected record window"))
    );
    Ok(())
}

#[test]
fn window_missing_misnumbered_members() -> Result<(), Box<dyn Error>> {
    let (records, length) = located_records(vec![tcp(false, 100, 2, b"")?])?;
    let input = BuildInput {
        label: "window.pcap",
        length,
        sha256_hex: &sha256(b"source"),
        records: &records,
        frames_seen: 3,
    };
    assert!(build_window(input, RecordWindow { first: 2, last: 3 }).is_err());
    assert!(build_window(input, RecordWindow { first: 0, last: 1 }).is_err());
    assert!(build_window(input, RecordWindow { first: 1, last: 4 }).is_err());
    Ok(())
}
