//! Canonical Ethernet II and IEEE 802.3 frame encoding

use crate::error::EncodeError;
use crate::ethernet::{EthernetFrame, FrameField};
use crate::vlan::VlanTag;
use crate::{
    ETHERTYPE_MIN, LENGTH_FIELD_MAX, MAX_FRAME_LEN, MAX_VLAN_TAGS, TPID_8021AD, TPID_8021Q,
};

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;

/// Return the number of bytes the frame would occupy after encoding
///
/// The model is validated before the length is returned. This keeps callers
/// from allocating for a frame that the encoder would later reject
///
/// # Errors
///
/// Returns [`EncodeError`] when a field, VLAN tag, payload length, or bounded
/// frame length is invalid
pub fn encoded_len(frame: &EthernetFrame<'_>) -> Result<usize, EncodeError> {
    validate_frame(frame)?;

    let tags_length = frame
        .vlan_tags
        .len()
        .checked_mul(VLAN_TAG_LEN)
        .ok_or(EncodeError::LengthOverflow)?;
    let payload_length = frame
        .payload
        .len()
        .checked_add(frame.padding.len())
        .ok_or(EncodeError::LengthOverflow)?;
    let length = ETHERNET_HEADER_LEN
        .checked_add(tags_length)
        .and_then(|length| length.checked_add(payload_length))
        .ok_or(EncodeError::LengthOverflow)?;

    if length > MAX_FRAME_LEN {
        return Err(EncodeError::FrameTooLong {
            length,
            max: MAX_FRAME_LEN,
        });
    }
    Ok(length)
}

/// Encode one frame into a caller-provided buffer
///
/// Validation and the complete output-size check happen before the first byte
/// is written. A short buffer therefore remains unchanged
///
/// # Errors
///
/// Returns [`EncodeError`] for an invalid frame or an output buffer that cannot
/// hold the complete frame
pub fn encode(frame: &EthernetFrame<'_>, destination: &mut [u8]) -> Result<usize, EncodeError> {
    let length = encoded_len(frame)?;
    if destination.len() < length {
        return Err(EncodeError::BufferTooShort {
            needed: length,
            available: destination.len(),
        });
    }

    // The length check above makes this sub-slice exact and keeps writes local
    let Some(output) = destination.get_mut(..length) else {
        return Err(EncodeError::BufferTooShort {
            needed: length,
            available: destination.len(),
        });
    };
    let mut offset = 0usize;
    write_bytes(output, &mut offset, &frame.destination)?;
    write_bytes(output, &mut offset, &frame.source)?;

    // Each tag keeps its original TPID and TCI bits in the same nesting order
    for tag in &frame.vlan_tags {
        write_tag(output, &mut offset, *tag)?;
    }

    let field = match frame.field {
        FrameField::EtherType(value) | FrameField::Length(value) => value.to_be_bytes(),
    };
    write_bytes(output, &mut offset, &field)?;
    write_bytes(output, &mut offset, frame.payload)?;
    write_bytes(output, &mut offset, frame.padding)?;

    // `encoded_len` and each checked write establish this invariant
    debug_assert_eq!(offset, length);
    Ok(length)
}

fn validate_frame(frame: &EthernetFrame<'_>) -> Result<(), EncodeError> {
    if frame.vlan_tags.len() > MAX_VLAN_TAGS {
        return Err(EncodeError::TooManyVlanTags { max: MAX_VLAN_TAGS });
    }

    for (index, tag) in frame.vlan_tags.iter().enumerate() {
        if !matches!(tag.tpid, TPID_8021Q | TPID_8021AD) {
            return Err(EncodeError::UnsupportedVlanTpid {
                index,
                tpid: tag.tpid,
            });
        }
    }

    match frame.field {
        FrameField::EtherType(value) => {
            if matches!(value, TPID_8021Q | TPID_8021AD) {
                return Err(EncodeError::VlanTpidAsFinalType { value });
            }
            if value < ETHERTYPE_MIN {
                return Err(EncodeError::ReservedField { value });
            }
        }
        FrameField::Length(value) => {
            if value > LENGTH_FIELD_MAX {
                return Err(EncodeError::ReservedField { value });
            }
            if usize::from(value) != frame.payload.len() {
                return Err(EncodeError::LengthMismatch {
                    declared: value,
                    payload: frame.payload.len(),
                });
            }
        }
    }
    Ok(())
}

fn write_tag(destination: &mut [u8], offset: &mut usize, tag: VlanTag) -> Result<(), EncodeError> {
    write_bytes(destination, offset, &tag.tpid.to_be_bytes())?;
    write_bytes(destination, offset, &tag.tci.to_be_bytes())
}

fn write_bytes(
    destination: &mut [u8],
    offset: &mut usize,
    source: &[u8],
) -> Result<(), EncodeError> {
    let end = offset
        .checked_add(source.len())
        .ok_or(EncodeError::LengthOverflow)?;
    let Some(output) = destination.get_mut(*offset..end) else {
        return Err(EncodeError::BufferTooShort {
            needed: end,
            available: destination.len(),
        });
    };
    output.copy_from_slice(source);
    *offset = end;
    Ok(())
}
