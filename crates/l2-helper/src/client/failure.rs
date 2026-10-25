use std::io;

use crate::{HelperError, ProtocolError, ReplyError, TransportError};

// Retain the first exchange failure so cancellation callers receive the same result
#[derive(Debug)]
pub(super) enum RequestFailure {
    Transport(TransportError),
    Protocol(ProtocolError),
    Reply(ReplyError),
    InvalidRequest(&'static str),
    ReplyTimeout,
    SessionStopping,
    SessionClosed,
    SessionPoisoned,
}

impl RequestFailure {
    pub(super) fn to_helper_error(&self) -> HelperError {
        match self {
            Self::Transport(error) => HelperError::Transport(copy_transport_error(error)),
            Self::Protocol(error) => HelperError::Protocol(*error),
            Self::Reply(error) => HelperError::Reply(*error),
            Self::InvalidRequest(message) => HelperError::InvalidRequest(message),
            Self::ReplyTimeout => HelperError::ReplyTimeout,
            Self::SessionStopping => HelperError::SessionStopping,
            Self::SessionClosed => HelperError::SessionClosed,
            Self::SessionPoisoned => HelperError::SessionPoisoned,
        }
    }
}

impl From<TransportError> for RequestFailure {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<ProtocolError> for RequestFailure {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<ReplyError> for RequestFailure {
    fn from(error: ReplyError) -> Self {
        Self::Reply(error)
    }
}

fn copy_transport_error(error: &TransportError) -> TransportError {
    match error {
        TransportError::MessageTooLarge { length, maximum } => TransportError::MessageTooLarge {
            length: *length,
            maximum: *maximum,
        },
        TransportError::WouldBlock => TransportError::WouldBlock,
        TransportError::PeerClosed => TransportError::PeerClosed,
        TransportError::WrongSocketType(kind) => TransportError::WrongSocketType(*kind),
        TransportError::AliasedChannels => TransportError::AliasedChannels,
        TransportError::PartialSend { sent, expected } => TransportError::PartialSend {
            sent: *sent,
            expected: *expected,
        },
        TransportError::Io(error) => {
            // Preserve errno for OS failures and the diagnostic for other I/O failures
            let copy = error.raw_os_error().map_or_else(
                || io::Error::new(error.kind(), error.to_string()),
                io::Error::from_raw_os_error,
            );
            TransportError::Io(copy)
        }
    }
}
