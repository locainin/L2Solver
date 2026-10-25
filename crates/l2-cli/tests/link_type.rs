use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use std::{error::Error, process::Command};

#[test]
fn reports_non_ethernet_link_types() -> Result<(), Box<dyn Error>> {
    let link_type = LinkType::Ieee80211;
    let timestamp = CaptureTimestamp::new(
        1,
        TimestampResolution::MICROSECOND,
        0,
        TimestampSource::Unknown,
    );
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 0,
        },
        14,
        None,
        Some(timestamp),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
    .with_link_type(link_type);
    let frame = CapturedFrame::new(
        // These bytes resemble an Ethernet header but are raw 802.11 evidence
        vec![0xff; 14],
        metadata,
    )?;
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(
        InterfaceId {
            section: 0,
            index: 0,
        },
        InterfaceConfig::new_with_link_type(
            link_type,
            64,
            TimestampResolution::MICROSECOND,
            0,
            FcsStatus::Unknown,
        )?,
    )?;
    writer.write_frame(&frame)?;
    writer.finish()?;
    let directory = std::env::temp_dir().join(format!("l2solver-link-type-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("wireless.pcapng");
    std::fs::write(&path, writer.into_inner())?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["inspect"])
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("unsupported link type"));
    assert!(!text.contains("->"));

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["observe"])
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stdout)?.contains("unsupported_link=1"));

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["json"])
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let json = String::from_utf8(output.stdout)?;
    assert!(json.contains("\"link_type\":\"Ieee80211\""));
    assert!(json.contains("\"link_type_raw\":105"));
    assert!(json.contains("unsupported link type"));

    std::fs::remove_dir_all(directory)?;
    Ok(())
}
