use super::common::{ByteOrder, CaptureConfig, PacketConfig, one_packet};
use l2_pcap::{CaptureLocator, CaptureReader, TimestampResolution};
use std::io::Cursor;

#[test]
fn reads_little_endian_microsecond_capture() -> Result<(), Box<dyn std::error::Error>> {
    let frame = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0xaa, 0xbb];
    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: 128,
            network: 1,
        },
        PacketConfig {
            seconds: 42,
            fraction: 12_345,
            bytes: &frame,
            original_len: 64,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    let packet = reader.next_packet()?.ok_or("missing packet")?;
    assert_eq!(
        packet.metadata().locator(),
        Some(CaptureLocator::ClassicPcap {
            record_offset: 24,
            data_offset: 40,
        })
    );

    assert_eq!(packet.bytes(), frame);
    assert_eq!(packet.metadata().original_len(), 64);
    assert_eq!(
        packet
            .metadata()
            .timestamp()
            .map(|timestamp| (timestamp.ticks(), timestamp.resolution())),
        Some((42 * 1_000_000 + 12_345, TimestampResolution::MICROSECOND))
    );
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn reads_big_endian_nanosecond_capture() -> Result<(), Box<dyn std::error::Error>> {
    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Big,
            nanoseconds: true,
            snaplen: u32::MAX,
            network: 1,
        },
        PacketConfig {
            seconds: u32::MAX,
            fraction: 999_999_999,
            bytes: &[],
            original_len: u32::MAX,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    let packet = reader.next_packet()?.ok_or("missing packet")?;

    assert_eq!(packet.bytes(), []);
    assert_eq!(packet.metadata().original_len(), u32::MAX);
    assert_eq!(
        packet
            .metadata()
            .timestamp()
            .map(|timestamp| (timestamp.ticks(), timestamp.resolution())),
        Some((
            u64::from(u32::MAX) * 1_000_000_000 + 999_999_999,
            TimestampResolution::NANOSECOND
        ))
    );
    Ok(())
}

#[test]
fn accepts_endian_variants_timestamp_units() -> Result<(), Box<dyn std::error::Error>> {
    for (order, nanoseconds, expected) in [
        (ByteOrder::Little, false, 7_000_u32),
        (ByteOrder::Big, false, 7_000_u32),
        (ByteOrder::Little, true, 7_u32),
        (ByteOrder::Big, true, 7_u32),
    ] {
        let capture = one_packet(
            CaptureConfig {
                order,
                nanoseconds,
                snaplen: 64,
                network: 1,
            },
            PacketConfig {
                seconds: 1,
                fraction: 7,
                bytes: &[0xaa],
                original_len: 1,
            },
        );
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        let packet = reader.next_packet()?.ok_or("missing packet")?;
        let timestamp = packet.metadata().timestamp().ok_or("missing timestamp")?;
        let nanos = if timestamp.resolution() == TimestampResolution::MICROSECOND {
            (timestamp.ticks() % 1_000_000) * 1_000
        } else if timestamp.resolution() == TimestampResolution::NANOSECOND {
            timestamp.ticks() % 1_000_000_000
        } else {
            return Err("unexpected timestamp resolution".into());
        };
        assert_eq!(nanos, u64::from(expected));
    }
    Ok(())
}
