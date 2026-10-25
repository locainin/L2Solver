use super::{case_support::located_records, support::tcp};
use l2_workbench::{
    investigation::{BuildInput, build_selected},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn selected_flow_across_distant_source() -> Result<(), Box<dyn Error>> {
    let payload = b"POST /evidence HTTP/1.1\r\nContent-Length: 4\r\n\r\nABCD";
    let mut frames = vec![tcp(false, 100, 2, b"")?];
    frames.extend(std::iter::repeat_n(tcp(true, 900, 0x10, b"other")?, 1401));
    frames.push(tcp(false, 101, 0x18, payload)?);
    frames.push(tcp(true, 905, 0x10, b"other")?);
    frames.push(tcp(false, 101 + u32::try_from(payload.len())?, 0x11, b"")?);
    let (records, length) = located_records(frames)?;
    let records: Vec<_> = records
        .into_iter()
        .filter(|record| matches!(record.number, 1 | 1403 | 1405))
        .collect();
    let result = build_selected(
        BuildInput {
            label: "source.pcap",
            length,
            sha256_hex: &sha256(b"caller-verified source"),
            records: &records,
            frames_seen: 1405,
        },
        3,
    )?;
    let body = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "http_body")
        .ok_or("missing body")?;
    assert_eq!(
        body.ranges.first().and_then(|range| range.packet),
        Some(1403)
    );
    let blob = result
        .case
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == body.blob.as_ref())
        .ok_or("missing body bytes")?;
    assert_eq!(blob.bytes, b"ABCD");
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("missing summary")?;
    assert_eq!(
        summary.details.get("input_selection"),
        Some(&json!("selected_records"))
    );
    assert_eq!(
        summary.details.get("outside_scope_frames"),
        Some(&json!(1402))
    );
    assert!(result.complete);
    Ok(())
}

#[test]
fn selected_analysis_unretained_members_explicit() -> Result<(), Box<dyn Error>> {
    let (mut records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x10, b"abc")?,
    ])?;
    let digest = sha256(b"source");
    let input = |records: &[l2_workbench::investigation::Record]| {
        build_selected(
            BuildInput {
                label: "source.pcap",
                length,
                sha256_hex: &digest,
                records,
                frames_seen: 4,
            },
            3,
        )
    };
    let result = input(&records)?;
    assert!(!result.complete);
    let summary = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or("missing summary")?;
    assert_eq!(summary.details.get("omitted_frames"), Some(&json!(1)));
    records.get_mut(1).ok_or("missing record")?.number = 1;
    assert!(input(&records).is_err());
    records.get_mut(1).ok_or("missing record")?.number = 5;
    assert!(input(&records).is_err());
    records.get_mut(0).ok_or("missing record")?.number = 0;
    assert!(input(&records).is_err());
    Ok(())
}
