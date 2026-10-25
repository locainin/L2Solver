use super::common::{
    BoundaryCapture, ByteOrder, CaptureConfig, PacketConfig, global_header, one_packet,
};
use l2_pcap::{CaptureReader, Error, MAX_FRAME_LENGTH, MAX_INPUT_BYTES, MAX_RECORD_COUNT};
use std::io::Cursor;

#[test]
fn zero_classic_snaplen_is_rejected() {
    let capture = global_header(ByteOrder::Little, false, 0, 1);
    assert!(CaptureReader::new(Cursor::new(capture)).is_err());
}

#[test]
fn classic_snaplen_supported_frame_length() -> Result<(), Box<dyn std::error::Error>> {
    for snaplen in [262_144, u32::MAX] {
        let capture = one_packet(
            CaptureConfig {
                order: ByteOrder::Little,
                nanoseconds: false,
                snaplen,
                network: 1,
            },
            PacketConfig {
                seconds: 1,
                fraction: 0,
                bytes: &[1, 2, 3],
                original_len: 3,
            },
        );
        let mut reader = CaptureReader::new(Cursor::new(capture))?;
        assert_eq!(
            reader.next_packet()?.ok_or("missing packet")?.bytes(),
            [1, 2, 3]
        );
        assert!(reader.next_packet()?.is_none());
    }
    Ok(())
}

#[test]
fn frame_ceiling_reading_oversized_payload() -> Result<(), Box<dyn std::error::Error>> {
    let captured_length = MAX_FRAME_LENGTH + 1;
    let mut capture = global_header(ByteOrder::Little, false, u32::MAX, 1);
    capture.extend_from_slice(&super::common::record_header(
        ByteOrder::Little,
        1,
        0,
        captured_length,
        captured_length,
    ));
    let mut reader = CaptureReader::new(Cursor::new(capture))?;

    assert!(matches!(
        reader.next_packet(),
        Err(Error::Frame(l2_capture::FrameError::FrameTooLong { length, max }))
            if length == usize::try_from(captured_length)?
                && max == usize::try_from(MAX_FRAME_LENGTH)?
    ));
    Ok(())
}

#[test]
fn captured_length_snaplen_rejected_early() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = global_header(ByteOrder::Little, false, 1, 1);
    capture.extend_from_slice(&super::common::record_header(ByteOrder::Little, 1, 0, 2, 2));
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet().is_err());
    Ok(())
}

#[test]
fn original_length_shorter_capture_rejected() -> Result<(), Box<dyn std::error::Error>> {
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
            bytes: &[1, 2],
            original_len: 1,
        },
    );
    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet().is_err());
    Ok(())
}

#[test]
fn record_count_limit_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = global_header(ByteOrder::Little, false, 64, 1);
    let header = super::common::record_header(ByteOrder::Little, 1, 0, 0, 0);
    for _ in 0..=MAX_RECORD_COUNT {
        capture.extend_from_slice(&header);
    }

    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    for _ in 0..MAX_RECORD_COUNT {
        assert!(reader.next_packet()?.is_some());
    }
    assert!(matches!(
        reader.next_packet(),
        Err(Error::RecordLimitExceeded { .. })
    ));
    Ok(())
}

#[test]
fn input_budget_accepts_eof_extra() -> Result<(), Box<dyn std::error::Error>> {
    // The budget divides into 4095 maximum packets and one final 4071-byte packet
    for extra_byte in [false, true] {
        let mut reader = CaptureReader::new(BoundaryCapture::new(extra_byte))?;
        for record in 0..4_096 {
            let packet = reader.next_packet()?.ok_or("missing generated packet")?;
            if record == 4_095 {
                assert_eq!(packet.bytes().len(), 4_071);
            } else {
                assert_eq!(packet.bytes().len(), usize::try_from(MAX_FRAME_LENGTH)?);
            }
        }
        if extra_byte {
            assert!(matches!(
                reader.next_packet(),
                Err(Error::InputLimitExceeded { attempted, limit })
                    if attempted == MAX_INPUT_BYTES + 1 && limit == MAX_INPUT_BYTES
            ));
        } else {
            assert!(reader.next_packet()?.is_none());
        }
    }
    Ok(())
}

#[test]
fn advertised_payload_cannot_input_budget() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = BoundaryCapture::new(true);
    // The extra byte belongs to the last declared payload instead of another record header
    source.final_captured += 1;
    let mut reader = CaptureReader::new(source)?;
    for _ in 0..4_095 {
        assert!(reader.next_packet()?.is_some());
    }
    assert!(matches!(
        reader.next_packet(),
        Err(Error::InputLimitExceeded { attempted, limit })
                    if attempted == MAX_INPUT_BYTES + 1 && limit == MAX_INPUT_BYTES
    ));
    assert!(matches!(reader.next_packet(), Err(Error::ReaderTerminated)));
    Ok(())
}
