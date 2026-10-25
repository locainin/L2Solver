use l2_helper_protocol::SessionId;

use crate::ReplyError;

const MAGIC: [u8; 4] = *b"L2HA";
const VERSION: u16 = 1;
const VERSION_OFFSET: usize = 4;
const KIND_OFFSET: usize = 6;
const LENGTH_OFFSET: usize = 8;
const SESSION_OFFSET: usize = 12;
const SEQUENCE_OFFSET: usize = 28;

/// Fixed response header size
pub const RESPONSE_HEADER_LENGTH: usize = 36;

/// Absolute IPC record limit, including a reply header
pub const MAX_IPC_BYTES: usize = 64 * 1024;

/// Maximum frame bytes that can fit in one bounded helper reply
pub const MAX_FRAME_BYTES: usize = MAX_IPC_BYTES - RESPONSE_HEADER_LENGTH;

/// Stable helper response categories
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HelperReplyKind {
    /// Handshake or receive-open succeeded
    Ready = 1,
    /// One frame was returned
    Frame = 2,
    /// The receive queue currently has no frame
    Empty = 3,
    /// Cancellation was accepted on the dedicated control channel
    Cancelled = 4,
    /// The helper accepted a close request
    Closed = 5,
    /// The helper rejected a request; payload is a [`ReplyErrorCode`]
    Error = 6,
}

impl HelperReplyKind {
    const fn from_wire(value: u16) -> Result<Self, ReplyError> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Frame),
            3 => Ok(Self::Empty),
            4 => Ok(Self::Cancelled),
            5 => Ok(Self::Closed),
            6 => Ok(Self::Error),
            other => Err(ReplyError::UnknownKind(other)),
        }
    }

    fn requires_frame(self) -> bool {
        self == Self::Frame
    }
}

/// Small stable error code sent in an error reply payload
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReplyErrorCode {
    /// Request framing or protocol state was invalid
    Protocol = 1,
    /// Peer credentials did not match the configured identity
    UnauthorizedPeer = 2,
    /// Requested interface binding did not match the held descriptor
    BindingMismatch = 3,
    /// The helper budget stopped the session
    Budget = 4,
    /// Backend identity or receive operation failed
    Backend = 5,
    /// The frontend could not accept a bounded response
    QueueSaturated = 6,
    /// Cancellation arrived on the ordinary data channel
    ControlChannelRequired = 7,
    /// Receive was requested before open
    ReceiveNotOpen = 8,
}

impl ReplyErrorCode {
    const fn from_wire(value: u16) -> Result<Self, ReplyError> {
        match value {
            1 => Ok(Self::Protocol),
            2 => Ok(Self::UnauthorizedPeer),
            3 => Ok(Self::BindingMismatch),
            4 => Ok(Self::Budget),
            5 => Ok(Self::Backend),
            6 => Ok(Self::QueueSaturated),
            7 => Ok(Self::ControlChannelRequired),
            8 => Ok(Self::ReceiveNotOpen),
            _ => Err(ReplyError::InvalidPayload),
        }
    }
}

/// Borrowed helper response before it is copied to a frontend-owned value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperReply<'a> {
    kind: HelperReplyKind,
    session: SessionId,
    sequence: u64,
    payload: &'a [u8],
}

impl<'a> HelperReply<'a> {
    /// Construct a validated empty reply
    ///
    /// # Errors
    /// Returns [`ReplyError::InvalidPayload`] for a frame or error kind
    pub fn empty(
        kind: HelperReplyKind,
        session: SessionId,
        sequence: u64,
    ) -> Result<Self, ReplyError> {
        Self::new(kind, session, sequence, &[])
    }

    /// Construct a validated frame reply
    ///
    /// # Errors
    /// Returns [`ReplyError::MessageTooLarge`] when the frame cannot fit in one
    /// bounded IPC record
    pub fn frame(session: SessionId, sequence: u64, payload: &'a [u8]) -> Result<Self, ReplyError> {
        Self::new(HelperReplyKind::Frame, session, sequence, payload)
    }

    /// Construct a validated error reply
    ///
    /// # Errors
    /// Returns an error when the supplied session or sequence is invalid
    pub fn error(
        session: SessionId,
        sequence: u64,
        code: ReplyErrorCode,
    ) -> Result<Self, ReplyError> {
        Self::new(
            HelperReplyKind::Error,
            session,
            sequence,
            error_payload(code),
        )
    }

    /// Construct a reply after validating its wire-shape invariants
    ///
    /// # Errors
    /// Returns an error for a zero sequence, an oversized frame, or an invalid
    /// payload shape
    pub fn new(
        kind: HelperReplyKind,
        session: SessionId,
        sequence: u64,
        payload: &'a [u8],
    ) -> Result<Self, ReplyError> {
        if sequence == 0 {
            return Err(ReplyError::ZeroSequence);
        }
        if kind.requires_frame() {
            if payload.len() > MAX_FRAME_BYTES {
                return Err(ReplyError::MessageTooLarge {
                    length: payload.len(),
                    maximum: MAX_FRAME_BYTES,
                });
            }
        } else if kind == HelperReplyKind::Error {
            if payload.len() != 2 {
                return Err(ReplyError::InvalidPayload);
            }
            let bytes: [u8; 2] = payload.try_into().map_err(|_| ReplyError::InvalidPayload)?;
            ReplyErrorCode::from_wire(u16::from_be_bytes(bytes))?;
        } else if !payload.is_empty() {
            return Err(ReplyError::InvalidPayload);
        }
        Ok(Self {
            kind,
            session,
            sequence,
            payload,
        })
    }

    /// Return the reply category
    #[must_use]
    pub const fn kind(self) -> HelperReplyKind {
        self.kind
    }

    /// Return the session identity echoed by the helper
    #[must_use]
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// Return the request sequence echoed by the helper
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return frame or error payload bytes
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    /// Copy a decoded reply into frontend-owned storage
    #[must_use]
    pub fn into_owned(self) -> HelperReplyOwned {
        HelperReplyOwned {
            kind: self.kind,
            session: self.session,
            sequence: self.sequence,
            payload: self.payload.to_vec(),
        }
    }

    /// Decode one complete reply record
    ///
    /// # Errors
    /// Returns an error for malformed header fields, invalid payload shape,
    /// truncation, or trailing bytes
    pub fn decode(input: &'a [u8]) -> Result<Self, ReplyError> {
        if input.len() < RESPONSE_HEADER_LENGTH {
            return Err(ReplyError::InputTooShort {
                needed: RESPONSE_HEADER_LENGTH,
                available: input.len(),
            });
        }
        if input.get(..4) != Some(&MAGIC) {
            return Err(ReplyError::BadMagic);
        }
        let version = read_u16(input, VERSION_OFFSET)?;
        if version != VERSION {
            return Err(ReplyError::UnsupportedVersion(version));
        }
        let kind = HelperReplyKind::from_wire(read_u16(input, KIND_OFFSET)?)?;
        let payload_length = usize::try_from(read_u32(input, LENGTH_OFFSET)?)
            .map_err(|_| ReplyError::LengthOverflow)?;
        let total_length = RESPONSE_HEADER_LENGTH
            .checked_add(payload_length)
            .ok_or(ReplyError::LengthOverflow)?;
        if total_length > MAX_IPC_BYTES {
            return Err(ReplyError::MessageTooLarge {
                length: total_length,
                maximum: MAX_IPC_BYTES,
            });
        }
        if input.len() < total_length {
            return Err(ReplyError::InputTooShort {
                needed: total_length,
                available: input.len(),
            });
        }
        if input.len() > total_length {
            return Err(ReplyError::TrailingBytes);
        }
        let session_bytes =
            input
                .get(SESSION_OFFSET..SEQUENCE_OFFSET)
                .ok_or(ReplyError::InputTooShort {
                    needed: SEQUENCE_OFFSET,
                    available: input.len(),
                })?;
        let session = SessionId::new(
            session_bytes
                .try_into()
                .map_err(|_| ReplyError::LengthOverflow)?,
        )
        .map_err(|error| match error {
            l2_helper_protocol::ProtocolError::ZeroSession => ReplyError::ZeroSession,
            _ => ReplyError::InvalidPayload,
        })?;
        let sequence = read_u64(input, SEQUENCE_OFFSET)?;
        let payload =
            input
                .get(RESPONSE_HEADER_LENGTH..total_length)
                .ok_or(ReplyError::InputTooShort {
                    needed: total_length,
                    available: input.len(),
                })?;
        Self::new(kind, session, sequence, payload)
    }
}

/// Frontend-owned helper response that does not borrow a transport receive buffer
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperReplyOwned {
    kind: HelperReplyKind,
    session: SessionId,
    sequence: u64,
    payload: Vec<u8>,
}

impl HelperReplyOwned {
    // Transfer frame storage to the client without copying its bytes again
    pub(crate) fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Return the reply category
    #[must_use]
    pub const fn kind(&self) -> HelperReplyKind {
        self.kind
    }

    /// Return the echoed session identity
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Return the echoed request sequence
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the owned frame or error payload
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Encode one complete reply without partially modifying the destination
///
/// # Errors
/// Returns an error when the destination is too small or the reply exceeds the
/// absolute record limit
pub fn encode_reply(reply: &HelperReply<'_>, destination: &mut [u8]) -> Result<usize, ReplyError> {
    let payload_length = reply.payload.len();
    let total_length = RESPONSE_HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or(ReplyError::LengthOverflow)?;
    if total_length > MAX_IPC_BYTES {
        return Err(ReplyError::MessageTooLarge {
            length: total_length,
            maximum: MAX_IPC_BYTES,
        });
    }
    if destination.len() < total_length {
        return Err(ReplyError::OutputTooShort {
            needed: total_length,
            available: destination.len(),
        });
    }
    let available = destination.len();
    let output = destination
        .get_mut(..total_length)
        .ok_or(ReplyError::OutputTooShort {
            needed: total_length,
            available,
        })?;
    output
        .get_mut(..4)
        .ok_or(ReplyError::LengthOverflow)?
        .copy_from_slice(&MAGIC);
    write_u16(output, VERSION_OFFSET, VERSION)?;
    write_u16(output, KIND_OFFSET, reply.kind as u16)?;
    write_u32(
        output,
        LENGTH_OFFSET,
        u32::try_from(payload_length).map_err(|_| ReplyError::LengthOverflow)?,
    )?;
    let session = output
        .get_mut(SESSION_OFFSET..SEQUENCE_OFFSET)
        .ok_or(ReplyError::LengthOverflow)?;
    session.copy_from_slice(&reply.session.bytes());
    write_u64(output, SEQUENCE_OFFSET, reply.sequence)?;
    output
        .get_mut(RESPONSE_HEADER_LENGTH..total_length)
        .ok_or(ReplyError::LengthOverflow)?
        .copy_from_slice(reply.payload);
    Ok(total_length)
}

/// Decode one complete helper reply record
///
/// # Errors
/// Returns an error for malformed, truncated, oversized, or trailing input
pub fn decode_reply(input: &[u8]) -> Result<HelperReply<'_>, ReplyError> {
    HelperReply::decode(input)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, ReplyError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(ReplyError::InputTooShort {
            needed: offset + 2,
            available: input.len(),
        })?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| ReplyError::LengthOverflow)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ReplyError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(ReplyError::InputTooShort {
            needed: offset + 4,
            available: input.len(),
        })?;
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| ReplyError::LengthOverflow)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, ReplyError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(ReplyError::InputTooShort {
            needed: offset + 8,
            available: input.len(),
        })?;
    let sequence = u64::from_be_bytes(bytes.try_into().map_err(|_| ReplyError::LengthOverflow)?);
    if sequence == 0 {
        return Err(ReplyError::ZeroSequence);
    }
    Ok(sequence)
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), ReplyError> {
    let bytes = output
        .get_mut(offset..offset + 2)
        .ok_or(ReplyError::LengthOverflow)?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), ReplyError> {
    let bytes = output
        .get_mut(offset..offset + 4)
        .ok_or(ReplyError::LengthOverflow)?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), ReplyError> {
    let bytes = output
        .get_mut(offset..offset + 8)
        .ok_or(ReplyError::LengthOverflow)?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

const fn error_payload(code: ReplyErrorCode) -> &'static [u8] {
    // Static payloads keep error construction allocation-free and avoid borrowing a temporary
    match code {
        ReplyErrorCode::Protocol => &[0, 1],
        ReplyErrorCode::UnauthorizedPeer => &[0, 2],
        ReplyErrorCode::BindingMismatch => &[0, 3],
        ReplyErrorCode::Budget => &[0, 4],
        ReplyErrorCode::Backend => &[0, 5],
        ReplyErrorCode::QueueSaturated => &[0, 6],
        ReplyErrorCode::ControlChannelRequired => &[0, 7],
        ReplyErrorCode::ReceiveNotOpen => &[0, 8],
    }
}
