use super::common::{
    ByteOrder, CaptureConfig, PacketConfig, global_header, one_packet, record_header,
};
#[path = "../common/pcapng_records.rs"]
mod pcapng;
use l2_pcap::{
    ABSOLUTE_MAX_INPUT_BYTES, ABSOLUTE_MAX_RECORD_COUNT, CaptureLimits, CaptureReader,
    CaptureSource, Error, MAX_FRAME_LENGTH, MAX_INPUT_BYTES, MAX_RECORD_COUNT, PcapNgReader,
};
use pcapng::{
    ByteOrder as NgByteOrder, block, enhanced_packet_without_options, interface_without_options,
    section_header_without_options,
};
use std::io::Cursor;

fn metadata_capture() -> Vec<u8> {
    let mut capture = section_header_without_options(NgByteOrder::Little, -1);
    capture.extend_from_slice(&interface_without_options(NgByteOrder::Little, u32::MAX));
    capture.extend_from_slice(&block(NgByteOrder::Little, 0x8000_0001, &[1, 2, 3, 4]));
    capture
}

fn packet_capture() -> Vec<u8> {
    let mut capture = section_header_without_options(NgByteOrder::Little, -1);
    capture.extend_from_slice(&interface_without_options(NgByteOrder::Little, 64));
    for byte in [0xaa, 0xbb] {
        capture.extend_from_slice(&enhanced_packet_without_options(
            NgByteOrder::Little,
            0,
            u64::from(byte),
            &[byte],
            1,
        ));
    }
    capture
}

#[test]
fn classic_input_limit_boundary() -> Result<(), Box<dyn std::error::Error>> {
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
            bytes: &[1, 2, 3],
            original_len: 3,
        },
    );
    let length = u64::try_from(capture.len())?;
    let exact = CaptureLimits::new(length, 1)?;
    let mut reader = CaptureReader::with_limits(Cursor::new(capture.clone()), exact)?;
    assert!(reader.next_packet()?.is_some());
    assert!(reader.next_packet()?.is_none());

    let one_short = CaptureLimits::new(length - 1, 1)?;
    let mut reader = CaptureReader::with_limits(Cursor::new(capture), one_short)?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InputLimitExceeded { attempted, limit })
            if attempted == length && limit == length - 1
    ));
    Ok(())
}

#[test]
fn configured_limits_classic_reading_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = global_header(ByteOrder::Little, false, u32::MAX, 1);
    capture.extend_from_slice(&record_header(ByteOrder::Little, 1, 0, 0, 0));
    capture.extend_from_slice(&record_header(
        ByteOrder::Little,
        1,
        0,
        MAX_FRAME_LENGTH,
        MAX_FRAME_LENGTH,
    ));
    let limits = CaptureLimits::new(u64::try_from(capture.len())?, 1)?;
    let mut reader = CaptureReader::with_limits(Cursor::new(capture), limits)?;

    assert!(reader.next_packet()?.is_some());
    assert!(matches!(
        reader.next_packet(),
        Err(Error::RecordLimitExceeded { limit: 1 })
    ));
    Ok(())
}

#[test]
fn configured_limits_unknown_blocks_eof() -> Result<(), Box<dyn std::error::Error>> {
    let capture = metadata_capture();
    let length = u64::try_from(capture.len())?;
    let exact = CaptureLimits::new(length, 0)?;
    let mut reader = PcapNgReader::with_limits(Cursor::new(capture.clone()), exact)?;
    assert!(reader.next_packet()?.is_none());
    assert_eq!(
        reader
            .interface_descriptions()
            .first()
            .ok_or("interface metadata missing")?
            .snaplen,
        u32::MAX
    );

    let one_short = CaptureLimits::new(length - 1, 0)?;
    let mut reader = PcapNgReader::with_limits(Cursor::new(capture), one_short)?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InputLimitExceeded { attempted, limit })
            if attempted == length && limit == length - 1
    ));
    Ok(())
}

#[test]
fn configured_limits_pcapng_count_boundary() -> Result<(), Box<dyn std::error::Error>> {
    for order in [NgByteOrder::Little, NgByteOrder::Big] {
        let mut capture = section_header_without_options(order, -1);
        capture.extend_from_slice(&interface_without_options(order, 64));
        let first = enhanced_packet_without_options(order, 0, 1, &[0xaa], 1);
        let second = enhanced_packet_without_options(order, 0, 2, &[0xbb], 1);
        capture.extend_from_slice(&first);
        capture.extend_from_slice(second.get(..8).ok_or("packet block header missing")?);
        let limits = CaptureLimits::new(u64::try_from(capture.len())?, 1)?;
        let mut reader = PcapNgReader::with_limits(Cursor::new(capture), limits)?;

        assert!(reader.next_packet()?.is_some());
        assert!(matches!(
            reader.next_packet(),
            Err(Error::RecordLimitExceeded { limit: 1 })
        ));
    }
    Ok(())
}

#[test]
fn source_same_small_limits_formats() -> Result<(), Box<dyn std::error::Error>> {
    let classic = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: 64,
            network: 1,
        },
        PacketConfig {
            seconds: 1,
            fraction: 0,
            bytes: &[1, 2, 3],
            original_len: 3,
        },
    );
    let classic_limits = CaptureLimits::new(u64::try_from(classic.len())?, 1)?;
    let mut classic_source = CaptureSource::with_limits(Cursor::new(classic), classic_limits)?;
    assert!(classic_source.next_packet()?.is_some());
    assert!(classic_source.next_packet()?.is_none());

    let pcapng = packet_capture();
    let pcapng_limits = CaptureLimits::new(u64::try_from(pcapng.len())?, 2)?;
    let mut pcapng_source = CaptureSource::with_limits(Cursor::new(pcapng), pcapng_limits)?;
    assert!(pcapng_source.next_packet()?.is_some());
    assert!(pcapng_source.next_packet()?.is_some());
    assert!(pcapng_source.next_packet()?.is_none());
    Ok(())
}

#[test]
fn limits_cannot_exceed_absolute_bounds() {
    assert!(CaptureLimits::new(ABSOLUTE_MAX_INPUT_BYTES + 1, 0).is_err());
}

#[test]
fn streaming_accepts_without_frame_allocations() -> Result<(), Box<dyn std::error::Error>> {
    let limits = CaptureLimits::new(10 * 1024 * 1024 * 1024, 100_000_000)?;
    assert!(CaptureLimits::STREAMING.max_input_bytes() >= limits.max_input_bytes());
    assert!(CaptureLimits::STREAMING.max_records() >= limits.max_records());
    assert_eq!(MAX_FRAME_LENGTH, 65_535);
    Ok(())
}

#[test]
fn default_streaming_profiles_documented_ceilings() {
    let defaults = CaptureLimits::default();
    assert_eq!(defaults.max_input_bytes(), MAX_INPUT_BYTES);
    assert_eq!(defaults.max_records(), MAX_RECORD_COUNT);

    assert_eq!(
        CaptureLimits::STREAMING.max_input_bytes(),
        ABSOLUTE_MAX_INPUT_BYTES
    );
    assert_eq!(
        CaptureLimits::STREAMING.max_records(),
        ABSOLUTE_MAX_RECORD_COUNT
    );
}
