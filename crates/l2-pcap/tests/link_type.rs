#[path = "reader/common.rs"]
pub mod pcap_fixture;
#[path = "common/pcapng.rs"]
pub mod pcapng_fixture;

use l2_capture::LinkType;
use l2_pcap::{CaptureReader, PcapNgReader};
use std::io::Cursor;

#[test]
fn maps_ethernet_wireless_link_types() -> Result<(), Box<dyn std::error::Error>> {
    for (network, expected) in [
        (1, LinkType::Ethernet),
        (105, LinkType::Ieee80211),
        (127, LinkType::Ieee80211Radiotap),
    ] {
        let capture = pcap_fixture::one_packet(
            pcap_fixture::CaptureConfig {
                order: pcap_fixture::ByteOrder::Little,
                nanoseconds: false,
                snaplen: 64,
                network,
            },
            pcap_fixture::PacketConfig {
                seconds: 0,
                fraction: 0,
                bytes: &[0xaa, 0xbb],
                original_len: 2,
            },
        );
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        assert_eq!(reader.link_type(), expected);
        let frame = reader.next_packet()?.ok_or("missing frame")?;
        assert_eq!(frame.metadata().link_type(), expected);
    }
    Ok(())
}

#[test]
fn classic_frames_types_opaque_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let payload = [0x00, 0x45, 0x00, 0xff];
    for raw_link_type in [12_u16, 228, 0x1234] {
        let capture = pcap_fixture::one_packet(
            pcap_fixture::CaptureConfig {
                order: pcap_fixture::ByteOrder::Little,
                nanoseconds: false,
                snaplen: 64,
                network: u32::from(raw_link_type),
            },
            pcap_fixture::PacketConfig {
                seconds: 1,
                fraction: 0,
                bytes: &payload,
                original_len: u32::try_from(payload.len())?,
            },
        );
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        let expected = LinkType::Unknown(raw_link_type);
        assert_eq!(reader.link_type(), expected);

        let frame = reader.next_packet()?.ok_or("missing opaque frame")?;
        assert_eq!(frame.bytes(), payload);
        assert_eq!(frame.metadata().link_type(), expected);
        assert!(!frame.metadata().link_type().is_supported());
        assert!(reader.next_packet()?.is_none());
    }
    Ok(())
}

#[test]
fn interface_types_per_frame() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = pcapng_fixture::section_header(pcapng_fixture::ByteOrder::Little, -1);
    let mut raw_wireless = pcapng_fixture::interface(pcapng_fixture::ByteOrder::Little, 64, &[]);
    raw_wireless
        .get_mut(8..10)
        .ok_or("missing link type field")?
        .copy_from_slice(&105_u16.to_le_bytes());
    capture.extend_from_slice(&raw_wireless);
    capture.extend_from_slice(&pcapng_fixture::enhanced_packet_without_options(
        pcapng_fixture::ByteOrder::Little,
        0,
        1,
        &[0x01, 0x02],
        2,
    ));
    let mut radiotap = pcapng_fixture::interface(pcapng_fixture::ByteOrder::Little, 64, &[]);
    radiotap
        .get_mut(8..10)
        .ok_or("missing link type field")?
        .copy_from_slice(&127_u16.to_le_bytes());
    capture.extend_from_slice(&radiotap);
    capture.extend_from_slice(&pcapng_fixture::enhanced_packet_without_options(
        pcapng_fixture::ByteOrder::Little,
        1,
        2,
        &[0x03, 0x04],
        2,
    ));
    let mut unknown = pcapng_fixture::interface(pcapng_fixture::ByteOrder::Little, 64, &[]);
    unknown
        .get_mut(8..10)
        .ok_or("missing link type field")?
        .copy_from_slice(&0x1234_u16.to_le_bytes());
    capture.extend_from_slice(&unknown);
    capture.extend_from_slice(&pcapng_fixture::enhanced_packet_without_options(
        pcapng_fixture::ByteOrder::Little,
        2,
        3,
        &[0x05, 0x06],
        2,
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let first = reader.next_packet()?.ok_or("missing wireless frame")?;
    assert_eq!(first.metadata().link_type(), LinkType::Ieee80211);
    assert_eq!(
        reader
            .interface_descriptions()
            .first()
            .ok_or("missing wireless interface")?
            .link_type(),
        LinkType::Ieee80211
    );
    assert_eq!(
        reader
            .interface_descriptions()
            .first()
            .ok_or("missing wireless interface")?
            .link_type_raw(),
        105
    );
    let second = reader.next_packet()?.ok_or("missing radiotap frame")?;
    assert_eq!(second.metadata().link_type(), LinkType::Ieee80211Radiotap);
    assert_eq!(
        reader
            .interface_descriptions()
            .get(1)
            .ok_or("missing radiotap interface")?
            .link_type_raw(),
        127
    );
    let third = reader.next_packet()?.ok_or("missing unknown frame")?;
    assert_eq!(third.metadata().link_type(), LinkType::Unknown(0x1234));
    assert_eq!(third.bytes(), [0x05, 0x06]);
    assert!(!third.metadata().link_type().is_supported());
    Ok(())
}
