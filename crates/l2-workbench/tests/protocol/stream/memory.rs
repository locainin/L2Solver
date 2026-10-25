use crate::{
    protocol::{
        Direction, FramingKind, LengthMeaning, MessageContext, ProtocolLimits, StreamMessageParser,
    },
    reconstruction::Origin,
};
use std::error::Error;

fn parser(framings: Vec<FramingKind>) -> Result<StreamMessageParser, Box<dyn Error>> {
    Ok(StreamMessageParser::new(
        MessageContext {
            source: "memory-test-source".into(),
            scope: "memory-test-scope".into(),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        false,
        false,
        framings,
        ProtocolLimits {
            max_message_bytes: 128,
            ..ProtocolLimits::default()
        },
    )?)
}

fn push(
    parser: &mut StreamMessageParser,
    offset: usize,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    parser.push_chunk(
        offset,
        bytes,
        &[Origin {
            packet: u32::try_from(offset + 1)?,
            frame_offset: 54,
            offset,
            length: bytes.len(),
        }],
    )?;
    Ok(())
}

fn assert_released(parser: &StreamMessageParser) {
    for candidate in &parser.candidates {
        assert!(!candidate.active);
        assert_eq!(candidate.buffer.capacity(), 0);
    }
}

#[test]
fn resource_releases_unused_candidate_capacity() -> Result<(), Box<dyn Error>> {
    let mut parser = parser(vec![FramingKind::Delimiter { byte: b'\n' }])?;
    push(&mut parser, 0, &[b'a'; 64])?;
    assert!(
        parser
            .candidates
            .iter()
            .all(|state| state.buffer.capacity() >= 64)
    );
    push(&mut parser, 64, &[b'b'; 80])?;
    assert_released(&parser);
    Ok(())
}

#[test]
fn invalid_framing_unused_candidate_capacity() -> Result<(), Box<dyn Error>> {
    let mut parser = parser(vec![FramingKind::LengthPrefix {
        offset: 64,
        width: 1,
        byte_order: crate::protocol::ByteOrder::BigEndian,
        meaning: LengthMeaning::WholeMessage,
    }])?;
    push(&mut parser, 0, &[b'a'; 64])?;
    assert!(
        parser
            .candidates
            .iter()
            .all(|state| state.buffer.capacity() >= 64)
    );
    push(&mut parser, 64, &[0])?;
    assert_released(&parser);
    Ok(())
}

#[test]
fn sequence_gap_releases_candidate_capacity() -> Result<(), Box<dyn Error>> {
    let mut parser = parser(vec![
        FramingKind::Delimiter { byte: b'\n' },
        FramingKind::FixedSize { bytes: 128 },
    ])?;
    push(&mut parser, 0, &[b'a'; 64])?;
    assert!(
        parser
            .candidates
            .iter()
            .all(|state| state.buffer.capacity() >= 64)
    );
    push(&mut parser, 67, b"z")?;
    assert_released(&parser);
    Ok(())
}
