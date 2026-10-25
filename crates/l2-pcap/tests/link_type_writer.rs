use l2_capture::{CaptureMetadata, CaptureTimestamp, CapturedFrame, InterfaceId, LinkType};
use l2_pcap::{InterfaceConfig, PcapNgReader, PcapNgWriter, TimestampResolution, TimestampSource};
use std::io::Cursor;

fn frame(link_type: LinkType) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
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
        2,
        None,
        Some(timestamp),
        l2_capture::Direction::Unknown,
        None,
        l2_capture::FcsStatus::Unknown,
    )
    .with_link_type(link_type);
    Ok(CapturedFrame::new(vec![0xaa, 0xbb], metadata)?)
}

#[test]
fn pcapng_writer_round_trips_type() -> Result<(), Box<dyn std::error::Error>> {
    for link_type in [
        LinkType::Ethernet,
        LinkType::Ieee80211,
        LinkType::Ieee80211Radiotap,
        LinkType::Unknown(0x1234),
    ] {
        let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
        let config = InterfaceConfig::new(
            64,
            TimestampResolution::MICROSECOND,
            0,
            l2_capture::FcsStatus::Unknown,
        )?
        .with_link_type(link_type);
        assert_eq!(config.link_type(), link_type);
        writer.add_interface(
            InterfaceId {
                section: 0,
                index: 0,
            },
            config,
        )?;
        writer.write_frame(&frame(link_type)?)?;
        writer.finish()?;
        let mut reader = PcapNgReader::new(Cursor::new(writer.into_inner()))?;
        let decoded = reader.next_packet()?.ok_or("missing frame")?;
        assert_eq!(decoded.metadata().link_type(), link_type);
    }
    Ok(())
}

#[test]
fn frame_interface_type_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(
        InterfaceId {
            section: 0,
            index: 0,
        },
        InterfaceConfig::new_with_link_type(
            LinkType::Ethernet,
            64,
            TimestampResolution::MICROSECOND,
            0,
            l2_capture::FcsStatus::Unknown,
        )?,
    )?;

    assert!(matches!(
        writer.write_frame(&frame(LinkType::Ieee80211)?),
        Err(l2_pcap::WriterError::LinkTypeConfigurationMismatch)
    ));
    Ok(())
}
