use crate::bytes::{read_array, write_at};
use crate::message::PROTOCOL_VERSION;
use crate::{Message, MessageKind, ProtocolError, SessionId};

const MAGIC: [u8; 4] = *b"L2HP";
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const KIND_OFFSET: usize = 6;
const LENGTH_OFFSET: usize = 8;
const SESSION_OFFSET: usize = 12;
const SEQUENCE_OFFSET: usize = 28;

pub const HEADER_LENGTH: usize = 36;
pub const MAX_MESSAGE_LENGTH: usize =
    HEADER_LENGTH + crate::InterfaceBindingRequest::ENCODED_LENGTH;

/// Decodes one complete helper protocol message
///
/// # Errors
///
/// Returns an error for malformed, unsupported, truncated, or trailing input
pub fn decode(input: &[u8]) -> Result<Message<'_>, ProtocolError> {
    if input.len() < HEADER_LENGTH {
        return Err(ProtocolError::InputTooShort {
            needed: HEADER_LENGTH,
            available: input.len(),
        });
    }

    let magic = read_array::<4>(input, MAGIC_OFFSET)?;
    if magic != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = u16::from_be_bytes(read_array::<2>(input, VERSION_OFFSET)?);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = MessageKind::from_wire(u16::from_be_bytes(read_array::<2>(input, KIND_OFFSET)?))?;
    let wire_length = u32::from_be_bytes(read_array::<4>(input, LENGTH_OFFSET)?);
    let payload_length = usize::try_from(wire_length).map_err(|_| ProtocolError::LengthOverflow)?;
    if payload_length != kind.required_payload_length() {
        return Err(ProtocolError::InvalidPayloadLength {
            kind,
            length: payload_length,
        });
    }
    let total_length = HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or(ProtocolError::LengthOverflow)?;

    if input.len() < total_length {
        return Err(ProtocolError::InputTooShort {
            needed: total_length,
            available: input.len(),
        });
    }
    if input.len() > total_length {
        return Err(ProtocolError::TrailingBytes);
    }

    let session = SessionId::new(read_array::<16>(input, SESSION_OFFSET)?)?;
    let sequence = u64::from_be_bytes(read_array::<8>(input, SEQUENCE_OFFSET)?);
    let payload = input
        .get(HEADER_LENGTH..total_length)
        .ok_or(ProtocolError::InternalEncodingInvariant)?;
    Message::new(kind, session, sequence, payload)
}

/// Encodes one complete helper protocol message without partial output
///
/// # Errors
///
/// Returns an error when the encoded size cannot be represented or the output
/// buffer is too small
pub fn encode(message: &Message<'_>, destination: &mut [u8]) -> Result<usize, ProtocolError> {
    let payload_length = message.payload().len();
    let wire_length = u32::try_from(payload_length).map_err(|_| ProtocolError::LengthOverflow)?;
    let total_length = HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or(ProtocolError::LengthOverflow)?;
    if destination.len() < total_length {
        return Err(ProtocolError::OutputTooShort {
            needed: total_length,
            available: destination.len(),
        });
    }

    // Build the header away from the caller's buffer so failures remain atomic
    let mut header = [0_u8; HEADER_LENGTH];
    write_at(&mut header, MAGIC_OFFSET, &MAGIC)?;
    write_at(&mut header, VERSION_OFFSET, &PROTOCOL_VERSION.to_be_bytes())?;
    write_at(
        &mut header,
        KIND_OFFSET,
        &message.kind().wire_value().to_be_bytes(),
    )?;
    write_at(&mut header, LENGTH_OFFSET, &wire_length.to_be_bytes())?;
    write_at(&mut header, SESSION_OFFSET, &message.session().bytes())?;
    write_at(
        &mut header,
        SEQUENCE_OFFSET,
        &message.sequence().to_be_bytes(),
    )?;

    let output = destination
        .get_mut(..total_length)
        .ok_or(ProtocolError::InternalEncodingInvariant)?;
    let (output_header, output_payload) = output
        .split_at_mut_checked(HEADER_LENGTH)
        .ok_or(ProtocolError::InternalEncodingInvariant)?;
    output_header.copy_from_slice(&header);
    output_payload.copy_from_slice(message.payload());
    Ok(total_length)
}
