use l2_capture::{CaptureLocator, Direction, InterfaceId, TimestampResolution};
use l2_pcap::{CaptureSource, Error, MAX_BLOCK_LENGTH, MAX_FRAME_LENGTH, PcapNgReader};
use std::io::{self, Cursor, Read};

pub mod common;
use common::pcapng::*;

#[test]
fn reads_enhanced_packet_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let tsresol = [9];
    let tsoffset = (-7_i64).to_le_bytes();
    let epb_flags = 1_u32 | (4 << 5);
    let flags = epb_flags.to_le_bytes();
    let unknown = [0xde, 0xad, 0xbe];
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(
        ByteOrder::Little,
        128,
        &[(9, &tsresol), (14, &tsoffset), (99, &unknown)],
    ));
    let packet_block_offset = u64::try_from(capture.len())?;
    capture.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0x0000_0001_0000_0002,
        &[0xaa, 0xbb, 0xcc],
        5,
        &[(2, &flags)],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let frame = first_frame(&mut reader)?;
    assert_eq!(frame.bytes(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(frame.captured_len(), 3);
    assert!(frame.is_truncated());
    assert_eq!(
        frame.metadata().interface(),
        InterfaceId {
            section: 0,
            index: 0,
        }
    );
    assert_eq!(frame.metadata().original_len(), 5);
    assert_eq!(
        frame.metadata().locator(),
        Some(CaptureLocator::PcapNg {
            block_offset: packet_block_offset,
            data_offset: packet_block_offset + 28,
            block_type: 6,
        })
    );
    let timestamp = frame.metadata().timestamp().ok_or("missing timestamp")?;
    assert_eq!(timestamp.ticks(), 0x0000_0001_0000_0002);
    assert_eq!(timestamp.resolution(), TimestampResolution::NANOSECOND);
    assert_eq!(timestamp.offset_seconds(), -7);
    assert_eq!(frame.metadata().direction(), Direction::Inbound);
    assert_eq!(frame.metadata().vlan(), None);
    assert_eq!(frame.metadata().fcs().length(), Some(4));
    let interfaces = reader.interface_descriptions();
    assert_eq!(interfaces.len(), 1);
    let description = interfaces.first().ok_or("missing interface description")?;
    assert_eq!(description.link_type_raw(), 1);
    assert_eq!(description.timestamp_offset_seconds, -7);
    assert_eq!(description.unknown_options().len(), 1);
    let option = description
        .unknown_options()
        .first()
        .ok_or("missing unknown option")?;
    assert_eq!(option.code, 99);
    assert_eq!(option.value, unknown);
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn preserves_timestamp_and_interface_identity() -> Result<(), Box<dyn std::error::Error>> {
    let tsresol = [0x80 | 0x0a];
    let mut capture = section_header(ByteOrder::Big, -1);
    capture.extend_from_slice(&interface(ByteOrder::Big, 64, &[(9, &tsresol)]));
    capture.extend_from_slice(&enhanced_packet(
        ByteOrder::Big,
        0,
        u64::MAX - 1,
        &[0x01, 0x02, 0x03, 0x04],
        4,
        &[],
    ));
    capture.extend_from_slice(&section_header(ByteOrder::Little, -1));
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    capture.extend_from_slice(&simple_packet(ByteOrder::Little, &[0x05, 0x06], 2));

    let mut reader = CaptureSource::new(Cursor::new(capture))?;
    let first = reader.next_packet()?.ok_or("missing big-endian frame")?;
    assert_eq!(
        first.metadata().interface(),
        InterfaceId {
            section: 0,
            index: 0
        }
    );
    assert_eq!(
        first
            .metadata()
            .timestamp()
            .map(|timestamp| (timestamp.ticks(), timestamp.resolution())),
        Some((u64::MAX - 1, TimestampResolution::binary(10)?))
    );
    let second = reader
        .next_packet()?
        .ok_or("missing second-section frame")?;
    assert_eq!(second.bytes(), &[0x05, 0x06]);
    assert_eq!(
        second.metadata().interface(),
        InterfaceId {
            section: 1,
            index: 0
        }
    );
    assert_eq!(second.metadata().timestamp(), None);
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn malformed_options_trailers_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tsresol = [6];
    let mut duplicate = section_header(ByteOrder::Little, -1);
    duplicate.extend_from_slice(&interface(
        ByteOrder::Little,
        64,
        &[(9, &tsresol), (9, &tsresol)],
    ));
    assert!(
        PcapNgReader::new(Cursor::new(duplicate))?
            .next_packet()
            .is_err()
    );

    let mut bad_trailer = section_header(ByteOrder::Little, -1);
    bad_trailer.extend_from_slice(&interface(ByteOrder::Little, 64, &[]));
    let mut packet = enhanced_packet(ByteOrder::Little, 0, 0, &[0xaa, 0xbb], 2, &[]);
    let end = packet.len();
    *packet
        .get_mut(end.checked_sub(1).ok_or("empty packet block")?)
        .ok_or("packet trailer range")? = 1;
    bad_trailer.extend_from_slice(&packet);
    assert!(
        PcapNgReader::new(Cursor::new(bad_trailer))?
            .next_packet()
            .is_err()
    );
    Ok(())
}

#[test]
fn nonzero_alignment_padding_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    let mut idb = interface(ByteOrder::Little, 64, &[(99, &[0xaa])]);
    // The final unknown option has three alignment bytes before the terminator
    let terminator_start = idb.len() - 8;
    *idb.get_mut(
        terminator_start
            .checked_sub(1)
            .ok_or("missing option padding")?,
    )
    .ok_or("option padding range")? = 0x7f;
    capture.extend_from_slice(&idb);
    let mut epb = enhanced_packet(ByteOrder::Little, 0, 0, &[0xaa], 1, &[]);
    // The one-byte frame has three alignment bytes before the option list
    let frame_padding_start = epb.len() - 4 - 4 - 1;
    *epb.get_mut(frame_padding_start)
        .ok_or("frame padding range")? = 0x55;
    capture.extend_from_slice(&epb);

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    let frame = first_frame(&mut reader)?;
    assert_eq!(frame.bytes(), &[0xaa]);
    assert_eq!(
        reader
            .interface_descriptions()
            .first()
            .ok_or("missing interface")?
            .unknown_options()
            .first()
            .ok_or("missing unknown option")?
            .value,
        [0xaa]
    );
    Ok(())
}

#[test]
fn checks_block_limits_before_allocation() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    let declared = u32::try_from(MAX_BLOCK_LENGTH + 4).unwrap_or_default();
    capture.extend_from_slice(&0x8000_0001_u32.to_le_bytes());
    capture.extend_from_slice(&declared.to_le_bytes());
    // The block type and length are enough to prove the reader refuses the allocation
    let result = PcapNgReader::new(Cursor::new(capture))?.next_packet();
    assert!(matches!(result, Err(Error::BlockLengthExceeded { .. })));
    Ok(())
}

#[test]
fn repeated_interrupts_terminate_deterministically() {
    struct AlwaysInterrupted;

    impl Read for AlwaysInterrupted {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }

    let result = PcapNgReader::new(AlwaysInterrupted);
    assert!(matches!(
        result,
        Err(Error::InterruptedLimitExceeded { .. })
    ));
}

#[test]
fn rejects_invalid_section_header() -> Result<(), Box<dyn std::error::Error>> {
    let mut bad_magic = section_header(ByteOrder::Little, -1);
    bad_magic
        .get_mut(8..12)
        .ok_or("section magic range")?
        .copy_from_slice(&[0, 0, 0, 0]);
    assert!(matches!(
        PcapNgReader::new(Cursor::new(bad_magic)),
        Err(Error::InvalidByteOrderMagic { magic: 0 })
    ));

    let mut bad_version = section_header(ByteOrder::Little, -1);
    bad_version
        .get_mut(12..14)
        .ok_or("section version range")?
        .copy_from_slice(&2_u16.to_le_bytes());
    assert!(matches!(
        PcapNgReader::new(Cursor::new(bad_version)),
        Err(Error::UnsupportedPcapNgVersion { major: 2, minor: 0 })
    ));

    for (section_length, expected) in [
        (32_i64, Error::UnsupportedSectionLength { length: 32 }),
        (0, Error::UnsupportedSectionLength { length: 0 }),
        (-2, Error::InvalidSectionLength { length: -2 }),
        (-4, Error::InvalidSectionLength { length: -4 }),
        (3, Error::InvalidSectionLength { length: 3 }),
    ] {
        let result = PcapNgReader::new(Cursor::new(section_header(
            ByteOrder::Little,
            section_length,
        )));
        assert!(matches!(result, Err(error) if error.to_string() == expected.to_string()));
    }

    let non_section = block(ByteOrder::Little, 1, &[]);
    assert!(matches!(
        PcapNgReader::new(Cursor::new(non_section)),
        Err(Error::SectionHeaderRequired)
    ));

    // The minimum legal block has an eight-byte header and four-byte trailer
    let mut minimum_unknown = section_header_without_options(ByteOrder::Little, -1);
    minimum_unknown.extend_from_slice(&block(ByteOrder::Little, 0x8000_0001, &[]));
    let mut minimum_reader = PcapNgReader::new(Cursor::new(minimum_unknown))?;
    assert!(minimum_reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn preserves_snaplen_and_unknown_options() -> Result<(), Box<dyn std::error::Error>> {
    let mut accepted = section_header(ByteOrder::Little, -1);
    accepted.extend_from_slice(&interface_without_options(
        ByteOrder::Little,
        MAX_FRAME_LENGTH,
    ));
    let mut accepted_reader = PcapNgReader::new(Cursor::new(accepted))?;
    assert!(accepted_reader.next_packet()?.is_none());

    for snaplen in [0, MAX_FRAME_LENGTH + 1, u32::MAX] {
        let mut capture = section_header(ByteOrder::Little, -1);
        capture.extend_from_slice(&interface_without_options(ByteOrder::Little, snaplen));
        let mut reader = PcapNgReader::new(Cursor::new(capture))?;
        assert!(reader.next_packet()?.is_none());
        assert_eq!(
            reader
                .interface_descriptions()
                .first()
                .ok_or("missing interface description")?
                .snaplen,
            snaplen
        );
    }

    let known_value = [0x01];
    let unknown_value = [0x02];
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(
        ByteOrder::Little,
        64,
        &[(2, &known_value), (99, &unknown_value)],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet()?.is_none());
    let description = reader
        .interface_descriptions()
        .first()
        .ok_or("missing interface description")?;
    assert_eq!(description.unknown_options().len(), 1);
    assert_eq!(
        description
            .unknown_options()
            .first()
            .ok_or("missing unknown option")?
            .code,
        99
    );
    Ok(())
}
