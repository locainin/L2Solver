use super::support::tcp;
use l2_capture::CapturedFrame;
use l2_workbench::reconstruction::{HandshakeStatus, Reconstructor};
use std::error::Error;

fn ack(frame: &CapturedFrame, value: u32) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame.bytes().to_vec();
    bytes
        .get_mut(42..46)
        .ok_or("missing acknowledgement field")?
        .copy_from_slice(&value.to_be_bytes());
    Ok(CapturedFrame::new(bytes, frame.metadata().clone())?)
}

#[test]
fn handshake_requires_both_acknowledgements() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &ack(&tcp(true, 900, 0x12, b"")?, 101)?)?;
    engine.observe(3, &ack(&tcp(false, 101, 0x10, b"")?, 901)?)?;
    let report = engine.finish()?;
    let handshake = &report.sessions.first().ok_or("missing episode")?.handshake;
    assert_eq!(handshake.status, HandshakeStatus::ThreeWayObserved);
    assert_eq!(
        handshake.matches.first().map(|item| (
            item.syn_packet,
            item.synack_packet,
            item.ack_packet
        )),
        Some((1, 2, Some(3)))
    );
    Ok(())
}

#[test]
fn incorrect_early_cannot_qualify_handshake() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &ack(&tcp(false, 101, 0x10, b"")?, 901)?)?;
    engine.observe(3, &ack(&tcp(true, 900, 0x12, b"")?, 102)?)?;
    let report = engine.finish()?;
    let handshake = &report.sessions.first().ok_or("missing episode")?.handshake;
    assert_eq!(handshake.status, HandshakeStatus::InitialSynOnly);
    assert_eq!(handshake.mismatched_synack_packets, vec![3]);
    assert!(handshake.matches.is_empty());
    Ok(())
}

#[test]
fn ack_responder_cannot_qualify_syn() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &ack(&tcp(true, 900, 0x10, b"")?, 101)?)?;
    let report = engine.finish()?;
    let handshake = &report.sessions.first().ok_or("missing episode")?.handshake;
    assert_eq!(handshake.status, HandshakeStatus::InitialSynOnly);
    assert!(handshake.matches.is_empty());
    Ok(())
}

#[test]
fn final_ack_expected_sequence_values() -> Result<(), Box<dyn Error>> {
    for (flags, sequence, acknowledgement) in [(0, 101, 901), (0x10, 102, 901), (0x10, 101, 902)] {
        let mut engine = Reconstructor::new();
        engine.observe(1, &tcp(false, 100, 2, b"")?)?;
        engine.observe(2, &ack(&tcp(true, 900, 0x12, b"")?, 101)?)?;
        engine.observe(
            3,
            &ack(&tcp(false, sequence, flags, b"")?, acknowledgement)?,
        )?;
        let report = engine.finish()?;
        let handshake = &report.sessions.first().ok_or("missing episode")?.handshake;
        assert_eq!(handshake.status, HandshakeStatus::SynSynAckObserved);
        assert_eq!(
            handshake.matches.first().and_then(|item| item.ack_packet),
            None
        );
    }
    Ok(())
}

#[test]
fn syn_payload_part_acknowledgement_constraints() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, u32::MAX, 2, b"ab")?)?;
    engine.observe(2, &ack(&tcp(true, 900, 0x12, b"c")?, 2)?)?;
    engine.observe(3, &ack(&tcp(false, 2, 0x10, b"")?, 902)?)?;
    let report = engine.finish()?;
    assert_eq!(
        report
            .sessions
            .first()
            .ok_or("missing episode")?
            .handshake
            .status,
        HandshakeStatus::ThreeWayObserved
    );
    Ok(())
}

#[test]
fn contradictory_syn_flags_cannot_initiator() -> Result<(), Box<dyn Error>> {
    for flags in [3, 6] {
        let mut engine = Reconstructor::new();
        engine.observe(1, &tcp(false, 100, flags, b"")?)?;
        let report = engine.finish()?;
        let session = report.sessions.first().ok_or("missing episode")?;
        assert!(session.initiator.is_none());
        assert_eq!(session.handshake.status, HandshakeStatus::NoInitialSyn);
    }
    Ok(())
}

#[test]
fn responder_close_syn_generation_ambiguity() -> Result<(), Box<dyn Error>> {
    let mut engine = Reconstructor::new();
    engine.observe(1, &tcp(false, 100, 2, b"")?)?;
    engine.observe(2, &ack(&tcp(true, 900, 0x12, b"")?, 101)?)?;
    engine.observe(3, &tcp(true, 901, 4, b"")?)?;
    engine.observe(4, &tcp(false, 100, 2, b"")?)?;
    let report = engine.finish()?;
    assert_eq!(report.sessions.len(), 2);
    assert!(
        report
            .sessions
            .iter()
            .all(|session| session.generation_ambiguous)
    );
    let later = report.sessions.last().ok_or("missing later episode")?;
    assert_eq!(later.handshake.status, HandshakeStatus::InitialSynOnly);
    assert!(later.handshake.matches.is_empty());
    Ok(())
}
