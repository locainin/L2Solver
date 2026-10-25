use super::common::{
    ByteOrder, CaptureConfig, PacketConfig, global_header, one_packet, prefix, record_header,
    replace_bytes,
};
use l2_pcap::{CaptureReader, Error};
use std::io::Cursor;

#[test]
fn reserved_global_fields_are_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: 64,
            network: 1,
        },
        PacketConfig {
            seconds: 0,
            fraction: 0,
            bytes: &[],
            original_len: 0,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet()?.is_some());
    Ok(())
}

#[test]
fn empty_capture_valid_global_header() -> Result<(), Box<dyn std::error::Error>> {
    let capture = global_header(ByteOrder::Little, false, 64, 1);
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn truncated_global_headers_are_rejected() {
    let capture = global_header(ByteOrder::Little, false, 64, 1);
    for length in 0..capture.len() {
        let result = CaptureReader::new(Cursor::new(prefix(&capture, length)));
        assert!(
            result.is_err(),
            "global header length {length} was accepted"
        );
    }
}

#[test]
fn record_eof_distinguished_partial_header() -> Result<(), Box<dyn std::error::Error>> {
    let global = global_header(ByteOrder::Little, false, 64, 1);
    for length in 0..=16 {
        let mut capture = global.clone();
        let header = record_header(ByteOrder::Little, 1, 0, 0, 0);
        capture.extend_from_slice(prefix(&header, length));
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        if length == 0 {
            assert!(reader.next_packet()?.is_none());
        } else if length == 16 {
            assert!(reader.next_packet()?.is_some());
        } else {
            assert!(
                reader.next_packet().is_err(),
                "partial header length {length} was accepted"
            );
        }
    }
    Ok(())
}

#[test]
fn truncated_packet_payloads_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let frame = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    for length in 0..frame.len() {
        let mut capture = global_header(ByteOrder::Little, false, 64, 1);
        capture.extend_from_slice(&record_header(ByteOrder::Little, 1, 0, 6, 6));
        capture.extend_from_slice(prefix(&frame, length));
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        assert!(
            reader.next_packet().is_err(),
            "payload length {length} was accepted"
        );
    }

    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: 64,
            network: 1,
        },
        PacketConfig {
            seconds: 1,
            fraction: 0,
            bytes: &frame,
            original_len: 6,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert_eq!(
        reader.next_packet()?.ok_or("missing packet")?.bytes(),
        frame
    );
    Ok(())
}

#[test]
fn pcapng_magic_reported_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = global_header(ByteOrder::Little, false, 64, 1);
    replace_bytes(&mut capture, 0, 4, &[0x0a, 0x0d, 0x0d, 0x0a])?;
    assert!(matches!(
        CaptureReader::new(Cursor::new(capture)),
        Err(Error::UnsupportedFormat { name: "PCAPNG" })
    ));
    Ok(())
}

#[test]
fn unknown_magic_distinct_pcapng() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = global_header(ByteOrder::Little, false, 64, 1);
    replace_bytes(&mut capture, 0, 4, &[0, 0, 0, 0])?;
    assert!(matches!(
        CaptureReader::new(Cursor::new(capture)),
        Err(Error::UnsupportedMagic {
            magic: [0, 0, 0, 0]
        })
    ));
    Ok(())
}

#[test]
fn unsupported_versions_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for (major, minor) in [(1_u16, 4_u16), (2, 3), (2, 5), (3, 0)] {
        let mut capture = global_header(ByteOrder::Little, false, 64, 1);
        replace_bytes(&mut capture, 4, 6, &major.to_le_bytes())?;
        replace_bytes(&mut capture, 6, 8, &minor.to_le_bytes())?;
        assert!(CaptureReader::new(Cursor::new(capture)).is_err());
    }
    Ok(())
}

#[test]
fn link_metadata_bits_are_rejected() {
    for network in [0x0001_0001, 0x0400_0001] {
        let capture = global_header(ByteOrder::Little, false, 64, network);
        assert!(CaptureReader::new(Cursor::new(capture)).is_err());
    }
}

#[test]
fn invalid_timestamp_fractions_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    for (nanoseconds, fraction) in [(false, 1_000_000), (true, 1_000_000_000)] {
        let capture = one_packet(
            CaptureConfig {
                order: ByteOrder::Little,
                nanoseconds,
                snaplen: 64,
                network: 1,
            },
            PacketConfig {
                seconds: 1,
                fraction,
                bytes: &[],
                original_len: 0,
            },
        );
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        assert!(reader.next_packet().is_err());
    }
    Ok(())
}

#[test]
fn maximum_snaplen_frame_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let frame = vec![0xa5; usize::try_from(l2_pcap::MAX_FRAME_LENGTH)?];
    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: u32::MAX,
            network: 1,
        },
        PacketConfig {
            seconds: 1,
            fraction: 0,
            bytes: &frame,
            original_len: l2_pcap::MAX_FRAME_LENGTH,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert_eq!(
        reader.next_packet()?.ok_or("missing packet")?.bytes(),
        frame
    );
    Ok(())
}
