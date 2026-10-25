use core::fmt;

use crate::MessageKind;

// Failures are explicit so the privileged peer never guesses at malformed input
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    BadMagic,
    UnsupportedVersion(u16),
    UnknownMessageKind(u16),
    ZeroSession,
    ZeroSequence,
    InputTooShort { needed: usize, available: usize },
    OutputTooShort { needed: usize, available: usize },
    LengthOverflow,
    TrailingBytes,
    InvalidPayloadLength { kind: MessageKind, length: usize },
    InvalidInterfaceBinding,
    HandshakeRequired,
    SequenceNotIncreasing,
    SessionMismatch,
    SessionStopping,
    SessionClosed,
    UnexpectedMessageKind(MessageKind),
    InternalEncodingInvariant,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("invalid helper protocol magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported helper protocol version {version}")
            }
            Self::UnknownMessageKind(kind) => {
                write!(formatter, "unknown helper protocol message kind {kind}")
            }
            Self::ZeroSession => formatter.write_str("helper session ID must not be all zeroes"),
            Self::ZeroSequence => formatter.write_str("message sequence must be nonzero"),
            Self::InputTooShort { needed, available } => write!(
                formatter,
                "helper protocol input needs {needed} bytes, only {available} available"
            ),
            Self::OutputTooShort { needed, available } => write!(
                formatter,
                "helper protocol output needs {needed} bytes, only {available} available"
            ),
            Self::LengthOverflow => formatter.write_str("helper protocol length overflowed"),
            Self::TrailingBytes => {
                formatter.write_str("helper protocol message has trailing bytes")
            }
            Self::InvalidPayloadLength { kind, length } => {
                write!(formatter, "{kind} payload has invalid length {length}")
            }
            Self::InvalidInterfaceBinding => {
                formatter.write_str("interface binding identity is incomplete")
            }
            Self::HandshakeRequired => formatter.write_str("helper handshake is required"),
            Self::SequenceNotIncreasing => formatter.write_str("message sequence did not increase"),
            Self::SessionMismatch => formatter.write_str("helper session does not match"),
            Self::SessionStopping => formatter.write_str("helper session is stopping"),
            Self::SessionClosed => formatter.write_str("helper session is closed"),
            Self::UnexpectedMessageKind(kind) => {
                write!(
                    formatter,
                    "message kind {kind} is invalid in the current state"
                )
            }
            Self::InternalEncodingInvariant => {
                formatter.write_str("helper protocol encoding invariant failed")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}
