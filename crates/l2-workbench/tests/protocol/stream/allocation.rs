use crate::protocol::{
    Direction, FramingKind, MessageContext, ProtocolError, ProtocolLimits, StreamMessageParser,
};
use crate::reconstruction::Origin;
use std::{cell::Cell, error::Error};

thread_local! {
    // Fault injection avoids exhausting the process allocator during a regression check
    static RESERVATIONS_BEFORE_FAILURE: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn check_message_reservation() -> Result<(), ProtocolError> {
    RESERVATIONS_BEFORE_FAILURE.with(|remaining| match remaining.get() {
        None => Ok(()),
        Some(0) => {
            remaining.set(None);
            Err(ProtocolError::AllocationFailed)
        }
        Some(count) => {
            remaining.set(Some(count - 1));
            Ok(())
        }
    })
}

struct ReservationFailure;

impl ReservationFailure {
    fn after(successful_reservations: usize) -> Self {
        RESERVATIONS_BEFORE_FAILURE.with(|remaining| remaining.set(Some(successful_reservations)));
        Self
    }
}

impl Drop for ReservationFailure {
    fn drop(&mut self) {
        // Keep a failed assertion from leaking a configured fault into another check
        RESERVATIONS_BEFORE_FAILURE.with(|remaining| remaining.set(None));
    }
}

fn parser() -> Result<StreamMessageParser, ProtocolError> {
    StreamMessageParser::new(
        MessageContext {
            source: "allocation-test-source".into(),
            scope: "allocation-test-scope".into(),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )
}

fn push(
    parser: &mut StreamMessageParser,
    offset: usize,
    bytes: &[u8],
) -> Result<(), ProtocolError> {
    parser.push_chunk(
        offset,
        bytes,
        &[Origin {
            packet: 1,
            frame_offset: offset,
            offset,
            length: bytes.len(),
        }],
    )
}

fn interrupted_parser() -> Result<StreamMessageParser, Box<dyn Error>> {
    let mut parser = parser()?;
    let _failure = ReservationFailure::after(1);
    // The first record commits before the next message's byte reservation fails
    assert_eq!(
        push(&mut parser, 0, b"a\nb\n"),
        Err(ProtocolError::AllocationFailed)
    );
    Ok(parser)
}

#[test]
fn interrupted_chunk_cannot_overlapping_evidence() -> Result<(), Box<dyn Error>> {
    let parser = interrupted_parser()?;
    assert!(matches!(
        parser.into_report(),
        Err(ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn interrupted_chunk_cannot_accept_input() -> Result<(), Box<dyn Error>> {
    let mut parser = interrupted_parser()?;
    assert_eq!(
        push(&mut parser, 4, b"c\n"),
        Err(ProtocolError::InvalidParserState)
    );
    Ok(())
}

#[test]
fn interrupted_chunk_checkpoint_cannot_resume() -> Result<(), Box<dyn Error>> {
    let parser = interrupted_parser()?;
    let resumed: StreamMessageParser = serde_json::from_slice(&serde_json::to_vec(&parser)?)?;
    assert!(matches!(
        resumed.into_report(),
        Err(ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn successful_chunk_validated_fast_path() -> Result<(), Box<dyn Error>> {
    let mut parser = parser()?;
    push(&mut parser, 0, b"a\nb\n")?;
    assert!(!parser.needs_validation);
    assert_eq!(parser.into_report()?.messages.len(), 2);
    Ok(())
}
