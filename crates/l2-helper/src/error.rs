use std::{fmt, io};

use l2_helper_protocol::{InterfaceBindingRequest, ProtocolError};

use crate::transport::{PeerIdentity, SocketType};

/// Errors produced while checking the immutable capture identity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// The request did not match the descriptor retained by the helper
    Mismatch {
        /// Binding supplied by the frontend
        requested: InterfaceBindingRequest,
        /// Binding recorded when the receive source was installed
        held: InterfaceBindingRequest,
    },
    /// The receive backend could no longer prove the retained identity
    IdentityLost,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { requested, held } => write!(
                formatter,
                "requested binding {requested:?} does not match held binding {held:?}"
            ),
            Self::IdentityLost => formatter.write_str("receive binding identity was lost"),
        }
    }
}

impl std::error::Error for BindingError {}

/// Errors reported by a receive backend
#[derive(Debug)]
pub enum HelperError {
    /// The local transport failed
    Transport(TransportError),
    /// The request failed protocol validation
    Protocol(ProtocolError),
    /// The response failed response-wire validation
    Reply(ReplyError),
    /// The connected peer did not match the launcher's expected identity
    UnauthorizedPeer {
        /// Identity recorded by the kernel
        expected: PeerIdentity,
        /// Identity allowed by the helper configuration
        actual: PeerIdentity,
    },
    /// The receive descriptor no longer has the expected interface binding
    Binding(BindingError),
    /// A receive request arrived before a matching open operation
    ReceiveNotOpen,
    /// A request was sent on the ordinary channel even though cancellation has
    /// its own channel
    CancellationRequiresControlChannel,
    /// The frontend sent a request that is valid on neither channel
    InvalidRequest(&'static str),
    /// The helper's immutable session budget was exhausted
    Budget(crate::BudgetError),
    /// The peer reported exhaustion without identifying which budget limit was reached
    RemoteBudgetExhausted,
    /// The frontend disappeared before a normal close
    FrontendClosed,
    /// The dedicated control channel failed
    ControlChannelClosed,
    /// A malformed request was received and the session was failed closed
    MalformedIpc(ProtocolError),
    /// A backend returned an ordinary I/O or implementation error
    Backend(io::Error),
    /// A helper worker thread could not be joined
    WorkerPanicked,
    /// A cancellation request is pending and new workload is revoked
    SessionStopping,
    /// The helper session completed a valid close
    SessionClosed,
    /// Cancellation or an untrusted reply made the workload stream unusable
    SessionPoisoned,
    /// The frontend waited longer than the hard reply deadline
    ReplyTimeout,
}

impl fmt::Display for HelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "helper transport failed: {error}"),
            Self::Protocol(error) => write!(formatter, "helper request failed: {error}"),
            Self::Reply(error) => write!(formatter, "helper reply failed: {error}"),
            Self::UnauthorizedPeer { expected, actual } => write!(
                formatter,
                "helper peer {actual} does not match expected peer {expected}"
            ),
            Self::Binding(error) => write!(formatter, "helper binding failed: {error}"),
            Self::ReceiveNotOpen => formatter.write_str("receive requested before capture open"),
            Self::CancellationRequiresControlChannel => {
                formatter.write_str("cancellation must use the helper's dedicated control channel")
            }
            Self::InvalidRequest(message) => write!(formatter, "invalid helper request: {message}"),
            Self::Budget(error) => write!(formatter, "helper session budget exhausted: {error}"),
            Self::RemoteBudgetExhausted => {
                formatter.write_str("helper session budget exhausted (limit not specified by peer)")
            }
            Self::FrontendClosed => {
                formatter.write_str("helper frontend closed the request channel")
            }
            Self::ControlChannelClosed => formatter.write_str("helper control channel failed"),
            Self::MalformedIpc(error) => write!(formatter, "malformed helper IPC: {error}"),
            Self::Backend(error) => write!(formatter, "receive backend failed: {error}"),
            Self::WorkerPanicked => formatter.write_str("helper control worker panicked"),
            Self::SessionStopping => {
                formatter.write_str("helper session is stopping and rejects new workload")
            }
            Self::SessionClosed => formatter.write_str("helper session is closed"),
            Self::SessionPoisoned => formatter
                .write_str("helper session is unusable after cancellation or an untrusted reply"),
            Self::ReplyTimeout => formatter.write_str("helper reply deadline elapsed"),
        }
    }
}

impl std::error::Error for HelperError {}

impl From<TransportError> for HelperError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<ProtocolError> for HelperError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<ReplyError> for HelperError {
    fn from(error: ReplyError) -> Self {
        Self::Reply(error)
    }
}

impl From<crate::BudgetError> for HelperError {
    fn from(error: crate::BudgetError) -> Self {
        Self::Budget(error)
    }
}

/// Errors emitted while decoding or encoding a helper reply
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyError {
    /// The reply header did not contain the expected magic
    BadMagic,
    /// The reply version is not supported
    UnsupportedVersion(u16),
    /// The reply kind is not defined
    UnknownKind(u16),
    /// The reply session was all zeroes
    ZeroSession,
    /// The reply sequence was zero
    ZeroSequence,
    /// The reply payload length was not present in the input
    InputTooShort { needed: usize, available: usize },
    /// The reply destination could not hold the encoded result
    OutputTooShort { needed: usize, available: usize },
    /// The reply payload exceeded the hard IPC limit
    MessageTooLarge { length: usize, maximum: usize },
    /// Bytes followed a complete reply
    TrailingBytes,
    /// The selected reply kind carried the wrong payload shape
    InvalidPayload,
    /// A checked arithmetic operation overflowed
    LengthOverflow,
}

impl fmt::Display for ReplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => formatter.write_str("invalid helper reply magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported helper reply version {version}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown helper reply kind {kind}"),
            Self::ZeroSession => formatter.write_str("helper reply session must not be zero"),
            Self::ZeroSequence => formatter.write_str("helper reply sequence must not be zero"),
            Self::InputTooShort { needed, available } => write!(
                formatter,
                "helper reply needs {needed} bytes, only {available} available"
            ),
            Self::OutputTooShort { needed, available } => write!(
                formatter,
                "helper reply output needs {needed} bytes, only {available} available"
            ),
            Self::MessageTooLarge { length, maximum } => write!(
                formatter,
                "helper reply has {length} bytes, maximum is {maximum}"
            ),
            Self::TrailingBytes => formatter.write_str("helper reply has trailing bytes"),
            Self::InvalidPayload => formatter.write_str("helper reply payload is invalid"),
            Self::LengthOverflow => formatter.write_str("helper reply length overflowed"),
        }
    }
}

impl std::error::Error for ReplyError {}

/// Errors emitted by the local sequenced-packet transport
#[derive(Debug)]
pub enum TransportError {
    /// An IPC record was larger than the fixed receive buffer
    MessageTooLarge { length: usize, maximum: usize },
    /// A nonblocking operation would wait for the peer or queue
    WouldBlock,
    /// The connected peer closed its endpoint
    PeerClosed,
    /// A socket did not have the required `SOCK_SEQPACKET` type
    WrongSocketType(SocketType),
    /// The data and control descriptors refer to the same kernel socket
    AliasedChannels,
    /// A send operation was unexpectedly partial
    PartialSend { sent: usize, expected: usize },
    /// The underlying operating system rejected the operation
    Io(io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge { length, maximum } => write!(
                formatter,
                "helper IPC record has {length} bytes, maximum is {maximum}"
            ),
            Self::WouldBlock => formatter.write_str("helper IPC queue is full or not ready"),
            Self::PeerClosed => formatter.write_str("helper IPC peer closed"),
            Self::WrongSocketType(socket_type) => {
                write!(
                    formatter,
                    "helper IPC requires SOCK_SEQPACKET, got {socket_type:?}"
                )
            }
            Self::AliasedChannels => {
                formatter.write_str("helper IPC data and control channels must be distinct")
            }
            Self::PartialSend { sent, expected } => {
                write!(formatter, "helper IPC sent {sent} of {expected} bytes")
            }
            Self::Io(error) => write!(formatter, "helper IPC operating-system error: {error}"),
        }
    }
}

impl std::error::Error for TransportError {}
