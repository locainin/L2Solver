//! Framing, checksum, and selected identity semantics for CDP over Ethernet

use super::{CdpError, CdpField, CdpFrame, CdpLimits, MAX_CDP_BYTES};

const HEADER_BYTES: usize = 4;
const DEVICE_ID: u16 = 1;
const PORT_ID: u16 = 3;

/// Decode one CDP packet beginning at its version byte
///
/// The caller removes Ethernet and LLC/SNAP framing first. Unknown TLVs stay
/// opaque, while device and port IDs must each appear exactly once and be
/// nonempty. The caller chooses the identity size and TLV count limits
///
/// # Errors
/// Returns a framing, checksum, supported-version, identity, or limit error
pub fn decode_cdp(input: &[u8], limits: CdpLimits) -> Result<CdpFrame<'_>, CdpError> {
    if input.len() > MAX_CDP_BYTES {
        return Err(CdpError::FrameTooLong {
            length: input.len(),
            max: MAX_CDP_BYTES,
        });
    }
    let Some((header, remaining)) = input.split_first_chunk::<HEADER_BYTES>() else {
        return Err(CdpError::TruncatedHeader {
            available: input.len(),
        });
    };
    let [version, hold_seconds, _, _] = *header;
    if !matches!(version, 1 | 2) {
        return Err(CdpError::UnsupportedVersion { version });
    }
    if !checksum_valid(input) {
        return Err(CdpError::InvalidChecksum);
    }
    let (device, port, tlv_count) = decode_identities(remaining, limits)?;
    Ok(CdpFrame {
        version,
        hold_seconds,
        device,
        port,
        tlv_count,
    })
}

fn decode_identities(
    mut remaining: &[u8],
    limits: CdpLimits,
) -> Result<(CdpField<'_>, CdpField<'_>, usize), CdpError> {
    let mut device = None;
    let mut port = None;
    let mut count = 0;
    let mut offset = HEADER_BYTES;
    while !remaining.is_empty() {
        if count >= limits.max_tlvs {
            return Err(CdpError::TooManyTlvs {
                max: limits.max_tlvs,
            });
        }
        let (kind, field, next) = decode_tlv(remaining, offset)?;
        record_identity(kind, field, limits, &mut device, &mut port)?;
        offset += remaining.len() - next.len();
        remaining = next;
        count += 1;
    }
    Ok((
        device.ok_or(CdpError::MissingIdentity { kind: DEVICE_ID })?,
        port.ok_or(CdpError::MissingIdentity { kind: PORT_ID })?,
        count,
    ))
}

fn decode_tlv(input: &[u8], offset: usize) -> Result<(u16, CdpField<'_>, &[u8]), CdpError> {
    let Some((header, body)) = input.split_first_chunk::<HEADER_BYTES>() else {
        return Err(CdpError::TruncatedTlvHeader {
            offset,
            available: input.len(),
        });
    };
    let [type_high, type_low, length_high, length_low] = *header;
    let kind = u16::from_be_bytes([type_high, type_low]);
    let length = usize::from(u16::from_be_bytes([length_high, length_low]));
    let Some(value_length) = length.checked_sub(HEADER_BYTES) else {
        return Err(CdpError::InvalidTlvLength { offset, length });
    };
    let Some((value, next)) = body.split_at_checked(value_length) else {
        return Err(CdpError::TruncatedTlvValue {
            offset,
            declared: value_length,
            available: body.len(),
        });
    };
    Ok((
        kind,
        CdpField {
            value,
            offset: offset + HEADER_BYTES,
        },
        next,
    ))
}

const fn record_identity<'a>(
    kind: u16,
    field: CdpField<'a>,
    limits: CdpLimits,
    device: &mut Option<CdpField<'a>>,
    port: &mut Option<CdpField<'a>>,
) -> Result<(), CdpError> {
    // Unknown TLVs are bounded by framing but do not claim an identity
    let slot = match kind {
        DEVICE_ID => device,
        PORT_ID => port,
        _ => return Ok(()),
    };
    if slot.is_some() {
        return Err(CdpError::DuplicateIdentity { kind });
    }
    if field.value.is_empty() || field.value.len() > limits.max_identity_bytes {
        return Err(CdpError::InvalidIdentity {
            kind,
            length: field.value.len(),
            max: limits.max_identity_bytes,
        });
    }
    *slot = Some(field);
    Ok(())
}

fn checksum_valid(input: &[u8]) -> bool {
    let mut pairs = input.chunks_exact(2);
    let mut sum = 0_u32;
    for pair in &mut pairs {
        if let [high, low] = *pair {
            sum += u32::from(u16::from_be_bytes([high, low]));
        }
    }
    if let [last] = pairs.remainder() {
        // The CDP odd-byte rule sign-extends the final octet before reduction
        sum += if *last >= 0x80 {
            0xff00 | u32::from(*last - 1)
        } else {
            u32::from(*last)
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}
