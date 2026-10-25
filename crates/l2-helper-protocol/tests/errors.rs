use l2_helper_protocol::{MessageKind, ProtocolError};

#[test]
fn protocol_errors_actionable_text() {
    // The error text is the operator-facing explanation for a rejected IPC message
    let cases = [
        (ProtocolError::BadMagic, "invalid helper protocol magic"),
        (
            ProtocolError::UnsupportedVersion(2),
            "unsupported helper protocol version 2",
        ),
        (
            ProtocolError::UnknownMessageKind(99),
            "unknown helper protocol message kind 99",
        ),
        (
            ProtocolError::ZeroSequence,
            "message sequence must be nonzero",
        ),
        (
            ProtocolError::ZeroSession,
            "helper session ID must not be all zeroes",
        ),
        (
            ProtocolError::InputTooShort {
                needed: 40,
                available: 3,
            },
            "helper protocol input needs 40 bytes, only 3 available",
        ),
        (
            ProtocolError::OutputTooShort {
                needed: 40,
                available: 3,
            },
            "helper protocol output needs 40 bytes, only 3 available",
        ),
        (
            ProtocolError::LengthOverflow,
            "helper protocol length overflowed",
        ),
        (
            ProtocolError::TrailingBytes,
            "helper protocol message has trailing bytes",
        ),
        (
            ProtocolError::InvalidPayloadLength {
                kind: MessageKind::OpenReceive,
                length: 23,
            },
            "open-receive payload has invalid length 23",
        ),
        (
            ProtocolError::InvalidInterfaceBinding,
            "interface binding identity is incomplete",
        ),
        (
            ProtocolError::HandshakeRequired,
            "helper handshake is required",
        ),
        (
            ProtocolError::SequenceNotIncreasing,
            "message sequence did not increase",
        ),
        (
            ProtocolError::SessionMismatch,
            "helper session does not match",
        ),
        (ProtocolError::SessionStopping, "helper session is stopping"),
        (ProtocolError::SessionClosed, "helper session is closed"),
        (
            ProtocolError::UnexpectedMessageKind(MessageKind::Hello),
            "message kind hello is invalid in the current state",
        ),
        (
            ProtocolError::InternalEncodingInvariant,
            "helper protocol encoding invariant failed",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}
