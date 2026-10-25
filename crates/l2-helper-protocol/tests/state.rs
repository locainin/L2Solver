use l2_helper_protocol::{
    ControlAction, Message, MessageKind, PeerState, ProtocolError, SessionId,
};

fn session(value: u8) -> Result<SessionId, ProtocolError> {
    SessionId::new([value; 16])
}

#[test]
fn cancellation_sequence_independent_workload_order() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(10)?;
    let mut state = PeerState::new(expected);
    state.accept(&Message::new(MessageKind::Hello, expected, 42, &[])?)?;
    let cancel = Message::new(MessageKind::Cancel, expected, 41, &[])?;
    assert_eq!(state.accept(&cancel)?, ControlAction::Cancel);
    assert_eq!(
        state.accept(&cancel),
        Err(ProtocolError::SequenceNotIncreasing)
    );
    assert_eq!(
        state.accept(&Message::new(MessageKind::Close, expected, 43, &[])?)?,
        ControlAction::Close
    );
    Ok(())
}

#[test]
fn newer_cancel_not_allocated_close() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(11)?;
    let mut state = PeerState::new(expected);
    state.accept(&Message::new(MessageKind::Hello, expected, 1, &[])?)?;
    state.accept(&Message::new(MessageKind::Cancel, expected, 3, &[])?)?;
    let close = Message::new(MessageKind::Close, expected, 2, &[])?;
    assert_eq!(state.accept(&close)?, ControlAction::Close);
    assert_eq!(
        state.accept(&close),
        Err(ProtocolError::SequenceNotIncreasing)
    );
    Ok(())
}

#[test]
fn enforces_handshake_and_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(1)?;
    let mut state = PeerState::new(expected);
    let receive = Message::new(MessageKind::ReceiveNext, expected, 1, &[])?;
    assert_eq!(
        state.accept(&receive),
        Err(ProtocolError::HandshakeRequired)
    );

    let hello = Message::new(MessageKind::Hello, expected, 1, &[])?;
    assert_eq!(state.accept(&hello)?, ControlAction::HandshakeAccepted);
    assert_eq!(
        state.accept(&hello),
        Err(ProtocolError::SequenceNotIncreasing)
    );

    let receive = Message::new(MessageKind::ReceiveNext, expected, 2, &[])?;
    assert_eq!(state.accept(&receive)?, ControlAction::ReceiveNext);
    Ok(())
}

#[test]
fn rejects_wrong_session_cancels_work() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(1)?;
    let mut state = PeerState::new(expected);
    let wrong = Message::new(MessageKind::Hello, session(2)?, 1, &[])?;
    assert_eq!(state.accept(&wrong), Err(ProtocolError::SessionMismatch));

    let hello = Message::new(MessageKind::Hello, expected, 1, &[])?;
    state.accept(&hello)?;
    let cancel = Message::new(MessageKind::Cancel, expected, 2, &[])?;
    assert_eq!(state.accept(&cancel)?, ControlAction::Cancel);
    let receive = Message::new(MessageKind::ReceiveNext, expected, 3, &[])?;
    assert_eq!(state.accept(&receive), Err(ProtocolError::SessionStopping));

    let repeated_cancel = Message::new(MessageKind::Cancel, expected, 4, &[])?;
    assert_eq!(state.accept(&repeated_cancel)?, ControlAction::Cancel);
    let close = Message::new(MessageKind::Close, expected, 5, &[])?;
    assert_eq!(state.accept(&close)?, ControlAction::Close);
    Ok(())
}

#[test]
fn accepts_cancellation_before_handshake() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(4)?;
    let mut state = PeerState::new(expected);
    let cancel = Message::new(MessageKind::Cancel, expected, 1, &[])?;
    assert_eq!(state.accept(&cancel)?, ControlAction::Cancel);

    let receive = Message::new(MessageKind::ReceiveNext, expected, 2, &[])?;
    assert_eq!(state.accept(&receive), Err(ProtocolError::SessionStopping));
    Ok(())
}

#[test]
fn closes_session_idempotently() -> Result<(), Box<dyn std::error::Error>> {
    let expected = session(7)?;
    let mut state = PeerState::new(expected);
    let hello = Message::new(MessageKind::Hello, expected, 1, &[])?;
    state.accept(&hello)?;
    let close = Message::new(MessageKind::Close, expected, 2, &[])?;
    assert_eq!(state.accept(&close)?, ControlAction::Close);
    let close_again = Message::new(MessageKind::Close, expected, 3, &[])?;
    assert_eq!(state.accept(&close_again)?, ControlAction::Close);
    let open = Message::new(MessageKind::OpenReceive, expected, 4, &[0; 24])?;
    assert_eq!(state.accept(&open), Err(ProtocolError::SessionClosed));
    Ok(())
}
