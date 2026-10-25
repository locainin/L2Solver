//! Interface Description Block decoding for PCAPNG.

use l2_capture::{InterfaceId, LinkType, TimestampResolution};

use crate::{
    Error,
    header::ByteOrder,
    pcapng_blocks::{
        BLOCK_TRAILER_LENGTH, INTERFACE_DESCRIPTION_BLOCK, INTERFACE_DESCRIPTION_MIN_LENGTH,
        read_u16, read_u32,
    },
    pcapng_model::{InterfaceDescription, PcapNgOption},
    pcapng_options::{OptionScope, is_known_option, parse_options},
};

/// Decode one Interface Description Block and retain unknown options
pub fn parse_interface(
    bytes: &[u8],
    order: ByteOrder,
    id: InterfaceId,
) -> Result<InterfaceDescription, Error> {
    if bytes.len() < INTERFACE_DESCRIPTION_MIN_LENGTH {
        return Err(Error::InvalidBlockLength {
            block_type: INTERFACE_DESCRIPTION_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }

    let link_type = LinkType::from_raw(read_u16(bytes, 8, order)?);
    let snaplen = read_u32(bytes, 12, order)?;
    let body_end = bytes
        .len()
        .checked_sub(BLOCK_TRAILER_LENGTH)
        .ok_or_else(|| Error::InvalidBlockLength {
            block_type: INTERFACE_DESCRIPTION_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        })?;
    let options = parse_options(
        INTERFACE_DESCRIPTION_BLOCK,
        bytes.get(16..body_end).ok_or(Error::InvalidHeaderLayout)?,
        OptionScope::Interface,
        order,
    )?;
    let mut description = InterfaceDescription {
        id,
        link_type,
        snaplen,
        timestamp_resolution: TimestampResolution::MICROSECOND,
        timestamp_offset_seconds: 0,
        fcs_length: None,
        linux_interface: None,
        unknown_options: Vec::new(),
    };
    for option in options {
        apply_option(&mut description, option, order)?;
    }
    Ok(description)
}

fn apply_option(
    description: &mut InterfaceDescription,
    option: PcapNgOption,
    order: ByteOrder,
) -> Result<(), Error> {
    match option.code {
        3 => {
            description.linux_interface = crate::pcapng_linux_identity::decode(&option.value)?;
        }
        9 => {
            let value = single_byte(&option)?;
            description.timestamp_resolution = if value & 0x80 == 0 {
                TimestampResolution::decimal(value & 0x7f)
            } else {
                TimestampResolution::binary(value & 0x7f)
            }
            .map_err(Error::from)?;
        }
        13 => {
            let bits = single_byte(&option)?;
            description.fcs_length = if bits == 0 {
                Some(0)
            } else if bits % 8 == 0 {
                Some(bits / 8)
            } else {
                return Err(Error::UnsupportedFcsLength { bits });
            };
        }
        14 => {
            let value = option.value.get(..8).ok_or(Error::InvalidOptionLength {
                block_type: INTERFACE_DESCRIPTION_BLOCK,
                code: option.code,
                length: option.value.len(),
                expected: Some(8),
                minimum: None,
            })?;
            let bytes: [u8; 8] = value.try_into().map_err(|_| Error::InvalidHeaderLayout)?;
            description.timestamp_offset_seconds = match order {
                ByteOrder::Little => i64::from_le_bytes(bytes),
                ByteOrder::Big => i64::from_be_bytes(bytes),
            };
        }
        code if !is_known_option(code, OptionScope::Interface) => {
            description.unknown_options.push(option);
        }
        _ => {
            // Known options without canonical metadata were already validated
        }
    }
    Ok(())
}

fn single_byte(option: &PcapNgOption) -> Result<u8, Error> {
    option
        .value
        .first()
        .copied()
        .ok_or(Error::InvalidOptionLength {
            block_type: INTERFACE_DESCRIPTION_BLOCK,
            code: option.code,
            length: option.value.len(),
            expected: Some(1),
            minimum: None,
        })
}
