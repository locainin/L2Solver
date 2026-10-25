//! Bounds-checked LLDP TLV framing

use crate::semantic::validate_semantics;
use crate::{DecodeError, LldpFrame, MAX_FRAME_LEN, MAX_TLVS, Tlv};

/// Decode one raw LLDP data unit without performing I/O
///
/// The input starts at the first two-byte LLDP TLV header. Ethernet, VLAN and
/// LLC/SNAP headers belong to the caller. The decoder accepts unknown TLV
/// types, duplicate optional TLVs and arbitrary post-End padding. Structural
/// errors are returned for bounds violations; mandatory semantic violations are
/// represented by [`crate::Validity::Invalid`] in the returned frame
/// Semantic validation is intentionally limited to the mandatory TLV order,
/// identifier subtype and length rules, and the TTL length; optional and
/// organization-specific fields remain opaque
///
/// # Errors
///
/// Returns [`DecodeError`] when the input exceeds the byte or TLV budget, a
/// header or value is truncated, the End TLV is missing, or its length is not
/// zero
pub fn decode_lldp(input: &[u8]) -> Result<LldpFrame<'_>, DecodeError> {
    // Reject oversized input before allocating the output vector
    if input.len() > MAX_FRAME_LEN {
        return Err(DecodeError::FrameTooLong {
            length: input.len(),
            max: MAX_FRAME_LEN,
        });
    }

    let mut offset = 0usize;
    let mut remaining = input;
    let mut tlvs = Vec::new();

    // End is consumed as a delimiter and never exposed as a normal TLV
    loop {
        let Some((header, body)) = remaining.split_first_chunk::<2>() else {
            // No bytes left means a complete TLV sequence without its delimiter
            if remaining.is_empty() {
                return Err(DecodeError::MissingEnd { offset });
            }
            return Err(DecodeError::TruncatedHeader {
                offset,
                available: remaining.len(),
            });
        };

        // The array pattern is exact, so both header bytes are always present
        let [type_byte, length_byte] = *header;
        let kind = type_byte >> 1;
        let length = usize::from(u16::from_be_bytes([type_byte & 1, length_byte]));

        // End is a structural delimiter and must never consume a value
        if kind == 0 {
            if length != 0 {
                return Err(DecodeError::NonZeroEndLength { offset, length });
            }
            return Ok(LldpFrame {
                validity: validate_semantics(&tlvs),
                tlvs,
                padding: body,
            });
        }

        // Keep the retained vector bounded even for zero-length TLVs
        if tlvs.len() >= MAX_TLVS {
            return Err(DecodeError::TooManyTlvs { max: MAX_TLVS });
        }

        let Some((value, next)) = body.split_at_checked(length) else {
            return Err(DecodeError::TruncatedValue {
                offset,
                kind,
                declared: length,
                available: body.len(),
            });
        };

        // Store only borrowed slices so decoding cannot copy attacker-controlled data
        tlvs.push(Tlv {
            kind,
            value,
            offset,
        });
        remaining = next;
        offset += 2 + length;
    }
}
