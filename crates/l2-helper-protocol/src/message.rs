use core::fmt;

use crate::ProtocolError;

pub const PROTOCOL_VERSION: u16 = 1;

// The session identifier binds every request to one helper instance
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Construct a session identity that can distinguish one helper launch
    ///
    /// # Errors
    /// Rejects the all-zero value reserved as an invalid session marker
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            return Err(ProtocolError::ZeroSession);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

// Message numbers are stable wire values and contain no transmit authority
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Hello,
    OpenReceive,
    ReceiveNext,
    Cancel,
    Close,
}

impl MessageKind {
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Hello => 1,
            Self::OpenReceive => 2,
            Self::ReceiveNext => 3,
            Self::Cancel => 4,
            Self::Close => 5,
        }
    }

    pub(crate) const fn from_wire(value: u16) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::OpenReceive),
            3 => Ok(Self::ReceiveNext),
            4 => Ok(Self::Cancel),
            5 => Ok(Self::Close),
            other => Err(ProtocolError::UnknownMessageKind(other)),
        }
    }

    pub(crate) const fn required_payload_length(self) -> usize {
        match self {
            Self::OpenReceive => crate::InterfaceBindingRequest::ENCODED_LENGTH,
            Self::Hello | Self::ReceiveNext | Self::Cancel | Self::Close => 0,
        }
    }
}

impl fmt::Display for MessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Hello => "hello",
            Self::OpenReceive => "open-receive",
            Self::ReceiveNext => "receive-next",
            Self::Cancel => "cancel",
            Self::Close => "close",
        };
        formatter.write_str(name)
    }
}

// Payload bytes borrow the bounded IPC input and require no parser allocation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    kind: MessageKind,
    session: SessionId,
    sequence: u64,
    payload: &'a [u8],
}

impl<'a> Message<'a> {
    /// Creates a validated helper protocol message
    ///
    /// # Errors
    ///
    /// Returns an error for sequence zero or a payload length that does not
    /// match the selected message kind
    pub const fn new(
        kind: MessageKind,
        session: SessionId,
        sequence: u64,
        payload: &'a [u8],
    ) -> Result<Self, ProtocolError> {
        if sequence == 0 {
            return Err(ProtocolError::ZeroSequence);
        }
        let required = kind.required_payload_length();
        if payload.len() != required {
            return Err(ProtocolError::InvalidPayloadLength {
                kind,
                length: payload.len(),
            });
        }
        Ok(Self {
            kind,
            session,
            sequence,
            payload,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}
