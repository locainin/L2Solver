pub mod common;

use common::pcapng::{
    ByteOrder, enhanced_packet, enhanced_packet_without_options, first_frame, interface,
    interface_without_options, packet_block, packet_block_without_options, section_header,
    section_header_without_options, simple_packet,
};
use l2_capture::{
    CaptureLocator, Direction, FcsStatus, FrameError, InterfaceId, LinkType, MAX_FCS_LENGTH,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{CaptureLimits, Error, MAX_FRAME_LENGTH, PcapNgReader};
use std::io::Cursor;

#[test]
fn preserves_empty_packet_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut enhanced_capture = section_header_without_options(ByteOrder::Little, -1);
    enhanced_capture.extend_from_slice(&interface_without_options(ByteOrder::Little, 64));
    enhanced_capture.extend_from_slice(&enhanced_packet_without_options(
        ByteOrder::Little,
        0,
        0,
        &[],
        0,
    ));
    let mut enhanced_reader = PcapNgReader::new(Cursor::new(enhanced_capture))?;
    let enhanced = first_frame(&mut enhanced_reader)?;
    assert!(enhanced.bytes().is_empty());
    assert_eq!(enhanced.metadata().original_len(), 0);
    assert!(!enhanced.is_truncated());
    let enhanced_payload = [0x5a; 32];
    let mut enhanced_with_payload = section_header_without_options(ByteOrder::Little, -1);
    enhanced_with_payload.extend_from_slice(&interface_without_options(ByteOrder::Little, 64));
    enhanced_with_payload.extend_from_slice(&enhanced_packet_without_options(
        ByteOrder::Little,
        0,
        0,
        &enhanced_payload,
        u32::try_from(enhanced_payload.len()).unwrap_or_default(),
    ));
    let mut payload_reader = PcapNgReader::new(Cursor::new(enhanced_with_payload))?;
    let enhanced_payload_frame = first_frame(&mut payload_reader)?;
    assert_eq!(enhanced_payload_frame.bytes(), enhanced_payload);
    assert!(payload_reader.next_packet()?.is_none());
    assert!(enhanced_reader.next_packet()?.is_none());

    let mut simple_capture = section_header_without_options(ByteOrder::Little, -1);
    simple_capture.extend_from_slice(&interface_without_options(ByteOrder::Little, 64));
    simple_capture.extend_from_slice(&simple_packet(ByteOrder::Little, &[], 0));
    let simple_payload = [0x6b; 16];
    simple_capture.extend_from_slice(&simple_packet(
        ByteOrder::Little,
        &simple_payload,
        u32::try_from(simple_payload.len()).unwrap_or_default(),
    ));
    let mut simple_reader = PcapNgReader::new(Cursor::new(simple_capture))?;
    let simple = first_frame(&mut simple_reader)?;
    assert!(simple.bytes().is_empty());
    assert_eq!(simple.metadata().original_len(), 0);
    assert!(!simple.is_truncated());
    let simple_payload_frame = simple_reader
        .next_packet()?
        .ok_or("missing simple payload frame")?;
    assert_eq!(simple_payload_frame.bytes(), simple_payload);
    assert!(simple_reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn reads_obsolete_packet_block_metadata_and_exact_lengths() -> Result<(), Box<dyn std::error::Error>>
{
    let timestamp_resolution = [9];
    let timestamp_offset = (-7_i64).to_le_bytes();
    let flags = (1_u32 | (4 << 5)).to_le_bytes();
    let frame_bytes = [0xaa, 0xbb, 0xcc];
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(
        ByteOrder::Little,
        64,
        &[(9, &timestamp_resolution), (14, &timestamp_offset)],
    ));
    let packet_block_offset = u64::try_from(capture.len())?;
    capture.extend_from_slice(&packet_block(
        ByteOrder::Little,
        0,
        2,
        0x0000_0001_0000_0002,
        &frame_bytes,
        5,
        &[(2, &flags)],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let frame = first_frame(&mut reader)?;

    assert_eq!(frame.bytes(), frame_bytes);
    assert_eq!(frame.captured_len(), frame_bytes.len());
    assert_eq!(frame.metadata().original_len(), 5);
    assert!(frame.is_truncated());
    assert_eq!(
        frame.metadata().interface(),
        InterfaceId {
            section: 0,
            index: 0,
        }
    );
    assert_eq!(frame.metadata().link_type(), LinkType::Ethernet);
    assert_eq!(
        frame.metadata().locator(),
        Some(CaptureLocator::PcapNg {
            block_offset: packet_block_offset,
            data_offset: packet_block_offset + 28,
            block_type: 2,
        })
    );
    let timestamp = frame.metadata().timestamp().ok_or("missing timestamp")?;
    assert_eq!(timestamp.ticks(), 0x0000_0001_0000_0002);
    assert_eq!(timestamp.resolution(), TimestampResolution::decimal(9)?);
    assert_eq!(timestamp.offset_seconds(), -7);
    assert_eq!(timestamp.source(), TimestampSource::CaptureFile);
    assert_eq!(frame.metadata().direction(), Direction::Inbound);
    assert_eq!(frame.metadata().fcs().length(), Some(4));
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn packet_block_uses_section_endianness_and_selected_interface()
-> Result<(), Box<dyn std::error::Error>> {
    let timestamp_resolution = [0x80 | 0x0a];
    let timestamp_offset = 12_i64.to_be_bytes();
    let mut capture = section_header(ByteOrder::Big, -1);
    capture.extend_from_slice(&interface(ByteOrder::Big, 64, &[]));
    capture.extend_from_slice(&interface(
        ByteOrder::Big,
        64,
        &[(9, &timestamp_resolution), (14, &timestamp_offset)],
    ));
    capture.extend_from_slice(&packet_block(
        ByteOrder::Big,
        1,
        u16::MAX,
        u64::MAX - 1,
        &[0x01, 0x02, 0x03, 0x04],
        4,
        &[],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let frame = first_frame(&mut reader)?;

    assert_eq!(frame.bytes(), [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        frame.metadata().interface(),
        InterfaceId {
            section: 0,
            index: 1,
        }
    );
    let timestamp = frame.metadata().timestamp().ok_or("missing timestamp")?;
    assert_eq!(timestamp.ticks(), u64::MAX - 1);
    assert_eq!(timestamp.resolution(), TimestampResolution::binary(10)?);
    assert_eq!(timestamp.offset_seconds(), 12);
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn packet_block_keeps_enhanced_only_options_unknown() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block(
        ByteOrder::Little,
        0,
        0,
        0,
        &[0xaa],
        1,
        &[(6, &[])],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xaa]);
    Ok(())
}

#[test]
fn rejects_packet_block_without_a_declared_interface() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block(ByteOrder::Little, 1, 0, 0, &[0xaa], 1, &[]));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::UnknownInterface {
            section: 0,
            index: 1
        })
    ));
    Ok(())
}

#[test]
fn rejects_packet_block_when_declared_data_exceeds_block_body()
-> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block_without_options(
        ByteOrder::Little,
        0,
        0,
        0,
        &[0xaa, 0xbb, 0xcc, 0xdd],
        5,
        5,
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InvalidBlockLength { block_type: 2, .. })
    ));
    Ok(())
}

#[test]
fn packet_block_counts_against_the_capture_record_limit() -> Result<(), Box<dyn std::error::Error>>
{
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block(ByteOrder::Little, 0, 0, 1, &[0xaa], 1, &[]));
    capture.extend_from_slice(&enhanced_packet(ByteOrder::Little, 0, 2, &[0xbb], 1, &[]));
    let limits = CaptureLimits::new(u64::try_from(capture.len())?, 1)?;

    let mut reader = PcapNgReader::with_limits(Cursor::new(capture), limits)?;
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xaa]);
    assert!(matches!(
        reader.next_packet(),
        Err(Error::RecordLimitExceeded { limit: 1 })
    ));
    Ok(())
}

#[test]
fn packet_block_drop_counts_are_retained_without_treating_unknown_as_a_number()
-> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block(ByteOrder::Little, 0, 0, 0, &[0xaa], 1, &[]));
    capture.extend_from_slice(&packet_block(ByteOrder::Little, 0, 7, 1, &[0xbb], 1, &[]));
    capture.extend_from_slice(&packet_block(
        ByteOrder::Little,
        0,
        u16::MAX,
        2,
        &[0xcc],
        1,
        &[],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xaa]);
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xbb]);
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xcc]);

    let summary = reader.collection_summary();
    assert_eq!(summary.packet_block_packets_dropped, 7);
    assert_eq!(summary.packet_blocks_with_unavailable_drop_count, 1);
    Ok(())
}

#[test]
fn zero_packet_block_drop_counts_leave_collection_loss_counters_clear()
-> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&packet_block(ByteOrder::Little, 0, 0, 0, &[0xaa], 1, &[]));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xaa]);
    let summary = reader.collection_summary();
    assert_eq!(summary.packet_block_packets_dropped, 0);
    assert_eq!(summary.packet_blocks_with_unavailable_drop_count, 0);
    Ok(())
}

#[test]
fn accepts_nonzero_packet_block_alignment_padding() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    let packet_block_offset = capture.len();
    capture.extend_from_slice(&packet_block(
        ByteOrder::Little,
        0,
        0,
        0,
        &[0xaa, 0xbb, 0xcc],
        3,
        &[],
    ));
    *capture
        .get_mut(packet_block_offset + 31)
        .ok_or("packet alignment padding is missing")? = 0x55;

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert_eq!(first_frame(&mut reader)?.bytes(), [0xaa, 0xbb, 0xcc]);
    Ok(())
}

#[test]
fn reports_packet_flags() -> Result<(), Box<dyn std::error::Error>> {
    for (raw_flags, expected_direction) in [
        (0_u32, Direction::Unknown),
        (1_u32, Direction::Inbound),
        (2_u32, Direction::Outbound),
    ] {
        let flags = raw_flags.to_le_bytes();
        let mut capture = section_header(ByteOrder::Little, -1);
        capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
        capture.extend_from_slice(&enhanced_packet(
            ByteOrder::Little,
            0,
            0,
            &[0xaa],
            1,
            &[(2, &flags)],
        ));
        let mut reader = PcapNgReader::new(Cursor::new(capture))?;
        let frame = first_frame(&mut reader)?;
        assert_eq!(frame.metadata().direction(), expected_direction);
    }
    Ok(())
}

#[test]
fn checks_packet_interface_prerequisites() -> Result<(), Box<dyn std::error::Error>> {
    let mut unknown = section_header(ByteOrder::Little, -1);
    unknown.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    unknown.extend_from_slice(&enhanced_packet(ByteOrder::Little, 1, 0, &[0xaa], 1, &[]));
    let mut unknown_reader = PcapNgReader::new(Cursor::new(unknown))?;
    assert!(matches!(
        unknown_reader.next_packet(),
        Err(Error::UnknownInterface {
            section: 0,
            index: 1
        })
    ));

    let mut without_interface = section_header(ByteOrder::Little, -1);
    without_interface.extend_from_slice(&simple_packet(ByteOrder::Little, &[0xaa], 1));
    let mut simple_reader = PcapNgReader::new(Cursor::new(without_interface))?;
    assert!(matches!(
        simple_reader.next_packet(),
        Err(Error::SimplePacketWithoutInterface)
    ));
    Ok(())
}

#[test]
fn rejects_packet_lengths_before_copy() -> Result<(), Box<dyn std::error::Error>> {
    let mut above_snaplen = section_header(ByteOrder::Little, -1);
    above_snaplen.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    let captured = [0xaa; 65];
    above_snaplen.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0,
        &captured,
        65,
        &[],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(above_snaplen))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InvalidCapturedLength {
            captured: 65,
            snaplen: 64
        })
    ));

    let mut shorter_original = section_header(ByteOrder::Little, -1);
    shorter_original.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    shorter_original.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0,
        &[0xaa, 0xbb],
        1,
        &[],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(shorter_original))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InvalidOriginalLength {
            captured: 2,
            original: 1
        })
    ));
    Ok(())
}

#[test]
fn honors_simple_packet_snaplen() -> Result<(), Box<dyn std::error::Error>> {
    let mut unlimited = section_header(ByteOrder::Little, -1);
    unlimited.extend_from_slice(&interface(ByteOrder::Little, 0, &[]));
    unlimited.extend_from_slice(&simple_packet(ByteOrder::Little, &[0xaa, 0xbb, 0xcc], 3));
    let mut unlimited_reader = PcapNgReader::new(Cursor::new(unlimited))?;
    let unlimited_frame = first_frame(&mut unlimited_reader)?;
    assert_eq!(unlimited_frame.bytes(), [0xaa, 0xbb, 0xcc]);
    assert!(!unlimited_frame.is_truncated());

    let mut truncated = section_header(ByteOrder::Little, -1);
    truncated.extend_from_slice(&interface(ByteOrder::Little, 2, &[]));
    truncated.extend_from_slice(&simple_packet(ByteOrder::Little, &[0xaa, 0xbb], 3));
    let mut truncated_reader = PcapNgReader::new(Cursor::new(truncated))?;
    let truncated_frame = first_frame(&mut truncated_reader)?;
    assert_eq!(truncated_frame.bytes(), [0xaa, 0xbb]);
    assert_eq!(truncated_frame.metadata().original_len(), 3);
    assert!(truncated_frame.is_truncated());
    Ok(())
}

#[test]
fn spb_uses_first_interface_snaplen() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    // The PCAPNG Simple Packet Block has no interface identifier. Its packet
    // belongs to the section's first Interface Description Block by definition
    capture.extend_from_slice(&interface(ByteOrder::Little, 1, &[]));
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&simple_packet(ByteOrder::Little, &[0xaa], 2));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let packet = first_frame(&mut reader)?;
    assert_eq!(packet.bytes(), [0xaa]);
    assert_eq!(packet.metadata().interface().section, 0);
    assert_eq!(packet.metadata().interface().index, 0);
    assert_eq!(packet.metadata().original_len(), 2);
    assert!(packet.is_truncated());
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn invalid_enhanced_packet_flags_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for raw_flags in [3_u32, 0x0000_1000] {
        let flags = raw_flags.to_le_bytes();
        let mut capture = section_header(ByteOrder::Little, -1);
        capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
        capture.extend_from_slice(&enhanced_packet(
            ByteOrder::Little,
            0,
            0,
            &[0xaa],
            1,
            &[(2, &flags)],
        ));
        let mut reader = PcapNgReader::new(Cursor::new(capture))?;
        assert!(matches!(
            reader.next_packet(),
            Err(Error::InvalidPacketFlags { flags: actual }) if actual == raw_flags
        ));
    }
    Ok(())
}

#[test]
fn bounds_unlimited_packet_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let length = usize::try_from(MAX_FRAME_LENGTH)
        .map_err(|error| format!("frame limit conversion failed: {error}"))?
        .saturating_add(1);
    let bytes = vec![0; length];
    let original = u32::try_from(length)
        .map_err(|error| format!("frame length conversion failed: {error}"))?;
    let malformed_flags = [0_u8; 2];
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 0, &[]));
    capture.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0,
        &bytes,
        original,
        &[(2, &malformed_flags)],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::Frame(FrameError::FrameTooLong { length: actual, .. })) if actual == length
    ));

    let exact_length = usize::try_from(MAX_FRAME_LENGTH)
        .map_err(|error| format!("exact frame limit conversion failed: {error}"))?;
    let exact_bytes = vec![0; exact_length];
    let exact_original = u32::try_from(exact_bytes.len())
        .map_err(|error| format!("exact frame length conversion failed: {error}"))?;
    let mut exact_capture = section_header(ByteOrder::Little, -1);
    exact_capture.extend_from_slice(&interface(ByteOrder::Little, 0, &[]));
    exact_capture.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0,
        &exact_bytes,
        exact_original,
        &[],
    ));
    let mut exact_reader = PcapNgReader::new(Cursor::new(exact_capture))?;
    let exact_frame = first_frame(&mut exact_reader)?;
    assert_eq!(exact_frame.captured_len(), exact_length);
    Ok(())
}

#[test]
fn packet_fcs_override_interface_state() -> Result<(), Box<dyn std::error::Error>> {
    // An EPB flags value of zero means that the packet-level FCS length is
    // unavailable, even when the interface declaration has a value
    let cases = [
        (vec![(13_u16, vec![32_u8])], Some(0_u32), FcsStatus::Unknown),
        (vec![(13_u16, vec![0_u8])], Some(0_u32), FcsStatus::Unknown),
        (vec![], Some(4_u32 << 5), FcsStatus::present(4)?),
        (
            vec![(13_u16, vec![32_u8])],
            Some(2_u32 << 5),
            FcsStatus::present(2)?,
        ),
        (vec![(13_u16, vec![32_u8])], None, FcsStatus::present(4)?),
        (
            vec![(13_u16, vec![MAX_FCS_LENGTH.saturating_mul(8)])],
            None,
            FcsStatus::present(MAX_FCS_LENGTH)?,
        ),
        (vec![(13_u16, vec![0_u8])], None, FcsStatus::Absent),
        (vec![], None, FcsStatus::Unknown),
    ];
    for order in [ByteOrder::Little, ByteOrder::Big] {
        for (raw_options, raw_flags, expected) in &cases {
            let option_values: Vec<(u16, &[u8])> = raw_options
                .iter()
                .map(|(code, value)| (*code, value.as_slice()))
                .collect();
            let mut capture = section_header(order, -1);
            capture.extend_from_slice(&interface(order, 64, &option_values));
            if let Some(flags) = raw_flags {
                let encoded_flags = match order {
                    ByteOrder::Little => flags.to_le_bytes(),
                    ByteOrder::Big => flags.to_be_bytes(),
                };
                capture.extend_from_slice(&enhanced_packet(
                    order,
                    0,
                    0,
                    &[0xaa],
                    1,
                    &[(2, &encoded_flags)],
                ));
            } else {
                capture.extend_from_slice(&enhanced_packet(order, 0, 0, &[0xaa], 1, &[]));
            }
            let mut reader = PcapNgReader::new(Cursor::new(capture))?;
            assert_eq!(first_frame(&mut reader)?.metadata().fcs(), *expected);
        }
    }
    Ok(())
}
