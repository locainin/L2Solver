//! Check exact source ranges when indexing captured packets

use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, TimestampResolution,
    TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use std::error::Error;

#[test]
fn pcapng_packet_range_points_to_the_original_frame_bytes() -> Result<(), Box<dyn Error>> {
    let original = super::tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40000,
        443,
        101,
        0x18,
        b"HELLO",
    )?;
    let interface = original.metadata().interface();
    let timestamp = CaptureTimestamp::new(
        1,
        TimestampResolution::MICROSECOND,
        0,
        TimestampSource::CaptureFile,
    );
    let frame = CapturedFrame::new(
        original.bytes().to_vec(),
        CaptureMetadata::new(
            interface,
            u32::try_from(original.bytes().len())?,
            None,
            Some(timestamp),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        ),
    )?;
    let config = InterfaceConfig::new(
        65_535,
        TimestampResolution::MICROSECOND,
        0,
        FcsStatus::Unknown,
    )?;
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(interface, config, &frame)?;
    writer.finish()?;
    let capture = writer.into_inner();

    // The recorded offset must identify the actual frame within the source bytes
    let (case, _) = super::index_pcapng_packets(&capture)?;
    let node = case.nodes().first().ok_or("packet node missing")?;
    let range = node.ranges.first().ok_or("packet source range missing")?;
    let start = usize::try_from(range.offset)?;
    let end = start
        .checked_add(usize::try_from(range.length)?)
        .ok_or("range overflow")?;
    assert_eq!(range.packet, Some(1));
    assert_eq!(range.source, format!("sha256:{}", super::sha256(&capture)));
    assert_eq!(capture.get(start..end), Some(frame.bytes()));
    Ok(())
}
