//! Canonical LLDP data-unit encoding

use crate::semantic::validate_semantics;
use crate::{EncodeError, LldpFrame, MAX_FRAME_LEN, MAX_TLVS, Validity};

const END_TLV_LEN: usize = 2;
const TLV_HEADER_LEN: usize = 2;
const MAX_TLV_VALUE_LEN: usize = 0x01ff;

/// Return the number of bytes needed for a canonical LLDP data unit
///
/// The End TLV and retained post-End padding are included in the result. The
/// model is checked before a caller can use the length for an allocation
///
/// # Errors
///
/// Returns [`EncodeError`] when semantic validity, TLV bounds, or the overall
/// LLDP data-unit budget is violated
pub fn lldp_encoded_len(frame: &LldpFrame<'_>) -> Result<usize, EncodeError> {
    validate_tlvs(frame)?;

    let mut length = END_TLV_LEN;
    for tlv in &frame.tlvs {
        let tlv_length = TLV_HEADER_LEN
            .checked_add(tlv.value.len())
            .ok_or(EncodeError::LengthOverflow)?;
        length = length
            .checked_add(tlv_length)
            .ok_or(EncodeError::LengthOverflow)?;
    }
    length = length
        .checked_add(frame.padding.len())
        .ok_or(EncodeError::LengthOverflow)?;

    if length > MAX_FRAME_LEN {
        return Err(EncodeError::FrameTooLong {
            length,
            max: MAX_FRAME_LEN,
        });
    }
    Ok(length)
}

/// Encode a canonical LLDP data unit into a caller-provided buffer
///
/// The complete model and destination size are checked before any output byte
/// is written. Unknown optional TLVs and post-End padding retain their order
/// and exact bytes
///
/// # Errors
///
/// Returns [`EncodeError`] when the model is invalid or the output buffer is
/// too short
pub fn encode_lldp(frame: &LldpFrame<'_>, destination: &mut [u8]) -> Result<usize, EncodeError> {
    let length = lldp_encoded_len(frame)?;
    if destination.len() < length {
        return Err(EncodeError::BufferTooShort {
            needed: length,
            available: destination.len(),
        });
    }

    // The capacity check makes this exact sub-slice safe for all following writes
    let Some(output) = destination.get_mut(..length) else {
        return Err(EncodeError::BufferTooShort {
            needed: length,
            available: destination.len(),
        });
    };
    let mut offset = 0usize;
    for tlv in &frame.tlvs {
        let length = u16::try_from(tlv.value.len()).map_err(|_| EncodeError::TlvValueTooLong {
            kind: tlv.kind,
            length: tlv.value.len(),
            max: MAX_TLV_VALUE_LEN,
        })?;
        // The seven-bit type occupies the upper seven bits and the checked
        // value length occupies the lower nine bits, so addition is exact
        let header = (u16::from(tlv.kind) * 0x0200 + length).to_be_bytes();
        write_bytes(output, &mut offset, &header)?;
        write_bytes(output, &mut offset, tlv.value)?;
    }
    write_bytes(output, &mut offset, &[0, 0])?;
    write_bytes(output, &mut offset, frame.padding)?;

    // Length validation and checked writes establish this invariant
    debug_assert_eq!(offset, length);
    Ok(length)
}

fn validate_tlvs(frame: &LldpFrame<'_>) -> Result<(), EncodeError> {
    if frame.tlvs.len() > MAX_TLVS {
        return Err(EncodeError::TooManyTlvs { max: MAX_TLVS });
    }

    for tlv in &frame.tlvs {
        if tlv.kind == 0 || tlv.kind > 0x7f {
            return Err(EncodeError::InvalidTlvKind { kind: tlv.kind });
        }
        if tlv.value.len() > MAX_TLV_VALUE_LEN {
            return Err(EncodeError::TlvValueTooLong {
                kind: tlv.kind,
                length: tlv.value.len(),
                max: MAX_TLV_VALUE_LEN,
            });
        }
    }

    // Recompute validity from public TLV fields so a forged `Validity::Valid`
    // marker cannot bypass mandatory-field checks
    if frame.validity != Validity::Valid || validate_semantics(&frame.tlvs) != Validity::Valid {
        return Err(EncodeError::InvalidSemantic);
    }
    Ok(())
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
