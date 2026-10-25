use crate::error::{DecodeContext, DecodeError};
use crate::ethernet::{EthernetFrame, FrameField};
use crate::vlan::VlanTag;
use crate::{
    ETHERTYPE_MIN, LENGTH_FIELD_MAX, MAX_FRAME_LEN, MAX_VLAN_TAGS, TPID_8021AD, TPID_8021Q,
};

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;

/// Decode one bounded Ethernet frame without touching sockets or global state
///
/// # Errors
///
/// Returns [`DecodeError`] when the input is too long, truncated, reserved, or
/// declares more payload or VLAN data than the bounded decoder can accept
pub fn decode(input: &[u8]) -> Result<EthernetFrame<'_>, DecodeError> {
    // Reject oversized captures before reading any fields or allocating tag storage
    if input.len() > MAX_FRAME_LEN {
        return Err(DecodeError::FrameTooLong {
            length: input.len(),
            max: MAX_FRAME_LEN,
        });
    }

    // The fixed header contains both MAC addresses and the first type or length field
    let Some((header, remainder)) = input.split_first_chunk::<ETHERNET_HEADER_LEN>() else {
        return Err(DecodeError::Truncated {
            context: DecodeContext::EthernetHeader,
            needed: ETHERNET_HEADER_LEN,
            available: input.len(),
        });
    };
    let [
        d0,
        d1,
        d2,
        d3,
        d4,
        d5,
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        field0,
        field1,
    ] = *header;
    let destination = [d0, d1, d2, d3, d4, d5];
    let source = [s0, s1, s2, s3, s4, s5];
    let field_value = u16::from_be_bytes([field0, field1]);
    let (field_value, remainder, vlan_tags) = decode_vlan_tags(field_value, remainder)?;

    // IEEE reserves the gap between maximum length and minimum EtherType
    let field = match field_value {
        0..=LENGTH_FIELD_MAX => FrameField::Length(field_value),
        1_501..=1_535 => return Err(DecodeError::ReservedField { value: field_value }),
        ETHERTYPE_MIN..=u16::MAX => FrameField::EtherType(field_value),
    };

    // Ethernet II has no payload length, so every remaining byte is protocol data
    let empty_padding: &[u8] = &[];
    let (payload, padding) = match field {
        FrameField::EtherType(_) => (remainder, empty_padding),
        FrameField::Length(declared) => {
            let declared = usize::from(declared);
            let Some((payload, padding)) = remainder.split_at_checked(declared) else {
                return Err(DecodeError::PayloadTruncated {
                    declared,
                    available: remainder.len(),
                });
            };
            (payload, padding)
        }
    };

    Ok(EthernetFrame {
        destination,
        source,
        vlan_tags,
        payload,
        padding,
        field,
    })
}

fn decode_vlan_tags(
    mut field_value: u16,
    mut remainder: &[u8],
) -> Result<(u16, &[u8], Vec<VlanTag>), DecodeError> {
    let mut vlan_tags = Vec::new();

    // Each supported TPID is followed by TCI and the next type or length field
    while matches!(field_value, TPID_8021Q | TPID_8021AD) {
        if vlan_tags.len() >= MAX_VLAN_TAGS {
            return Err(DecodeError::TooManyVlanTags { max: MAX_VLAN_TAGS });
        }

        // The TPID was already consumed as the current field
        if remainder.len() < 2 {
            return Err(DecodeError::Truncated {
                context: DecodeContext::VlanTag,
                needed: VLAN_TAG_LEN,
                available: remainder.len() + 2,
            });
        }

        // A complete tag also carries the inner type or length field
        let Some((tag, after_tag)) = remainder.split_first_chunk::<VLAN_TAG_LEN>() else {
            return Err(DecodeError::Truncated {
                context: DecodeContext::TypeLengthField,
                needed: 2,
                available: remainder.len() - 2,
            });
        };
        let [tci0, tci1, next_field0, next_field1] = *tag;
        vlan_tags.push(VlanTag {
            tpid: field_value,
            tci: u16::from_be_bytes([tci0, tci1]),
        });
        field_value = u16::from_be_bytes([next_field0, next_field1]);
        remainder = after_tag;
    }
    Ok((field_value, remainder, vlan_tags))
}
