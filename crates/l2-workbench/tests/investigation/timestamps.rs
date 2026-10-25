use super::support::tcp;
use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, CapturedFrame, TimestampResolution,
    TimestampSource,
};
use l2_workbench::{
    investigation::{BuildInput, Record, build},
    sha256,
};
use serde_json::json;
use std::error::Error;

#[test]
fn timestamp_ranges_separately_frame_bytes() -> Result<(), Box<dyn Error>> {
    for (locator, expected) in [
        (
            CaptureLocator::ClassicPcap {
                record_offset: 24,
                data_offset: 40,
            },
            24,
        ),
        (
            CaptureLocator::PcapNg {
                block_offset: 40,
                data_offset: 68,
                block_type: 6,
            },
            52,
        ),
    ] {
        let original = tcp(false, 100, 2, b"")?;
        let metadata = CaptureMetadata::new(
            original.metadata().interface(),
            original.metadata().original_len(),
            Some(locator),
            Some(CaptureTimestamp::new(
                1000,
                TimestampResolution::MICROSECOND,
                0,
                TimestampSource::CaptureFile,
            )),
            original.metadata().direction(),
            None,
            original.metadata().fcs(),
        );
        let records = [Record {
            number: 1,
            frame: CapturedFrame::new(original.bytes().to_vec(), metadata)?,
        }];
        let result = build(BuildInput {
            label: "clock.pcap",
            length: 4096,
            sha256_hex: &sha256(b"source"),
            records: &records,
            frames_seen: 1,
        })?;
        let packet = result
            .case
            .nodes()
            .iter()
            .find(|node| node.kind == "packet")
            .ok_or("missing packet")?;
        assert_eq!(
            packet.details.pointer("/timestamp_source_ranges/0/offset"),
            Some(&json!(expected))
        );
        assert_eq!(
            packet.details.pointer("/timestamp_source_ranges/0/length"),
            Some(&json!(8))
        );
        assert_ne!(
            packet.ranges.first().map(|range| range.offset),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn absent_timestamps_not_source_ranges() -> Result<(), Box<dyn Error>> {
    let (records, length) = super::case_support::located_records(vec![tcp(false, 100, 2, b"")?])?;
    let result = build(BuildInput {
        label: "no-clock.pcap",
        length,
        sha256_hex: &sha256(b"source"),
        records: &records,
        frames_seen: 1,
    })?;
    let packet = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "packet")
        .ok_or("missing packet")?;
    assert_eq!(
        packet.details.get("timestamp_source_ranges"),
        Some(&json!([]))
    );
    Ok(())
}
