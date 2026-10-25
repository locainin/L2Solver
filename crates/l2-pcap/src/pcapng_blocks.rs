//! PCAPNG block framing and section validation.

use std::io::Read;

use crate::{
    Error, MAX_BLOCK_LENGTH,
    header::{ByteOrder, decode_u16, decode_u32},
    pcapng_options::{OptionScope, parse_options},
    reader::{read_chunk, read_exact_counted},
};

pub const SECTION_HEADER_BLOCK: u32 = 0x0a0d_0d0a;
pub const INTERFACE_DESCRIPTION_BLOCK: u32 = 1;
pub const PACKET_BLOCK: u32 = 2;
pub const SIMPLE_PACKET_BLOCK: u32 = 3;
pub const ENHANCED_PACKET_BLOCK: u32 = 6;
pub const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
pub const GENERAL_HEADER_LENGTH: usize = 8;
pub const SECTION_PREFIX_LENGTH: usize = 12;
pub const SECTION_HEADER_MIN_LENGTH: usize = 28;
pub const INTERFACE_DESCRIPTION_MIN_LENGTH: usize = 20;
pub const PACKET_BLOCK_MIN_LENGTH: usize = 32;
pub const ENHANCED_PACKET_MIN_LENGTH: usize = 32;
pub const SIMPLE_PACKET_MIN_LENGTH: usize = 16;
pub const BLOCK_TRAILER_LENGTH: usize = 4;

#[derive(Clone, Copy)]
pub struct Block {
    pub block_type: u32,
    pub order: ByteOrder,
}

/// Validate the fixed section header and its option list before use.
pub fn parse_section_header(
    bytes: &[u8],
    order: ByteOrder,
) -> Result<Option<crate::CollectionReport>, Error> {
    if bytes.len() < SECTION_HEADER_MIN_LENGTH {
        return Err(Error::InvalidBlockLength {
            block_type: SECTION_HEADER_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        });
    }
    let byte_order_magic = read_u32(bytes, 8, order)?;
    if byte_order_magic != BYTE_ORDER_MAGIC {
        return Err(Error::InvalidByteOrderMagic {
            magic: byte_order_magic,
        });
    }
    let major = read_u16(bytes, 12, order)?;
    let minor = read_u16(bytes, 14, order)?;
    if major != 1 || !matches!(minor, 0 | 2) {
        return Err(Error::UnsupportedPcapNgVersion { major, minor });
    }
    let section_length = read_i64(bytes, 16, order)?;
    if section_length == -1 {
        // An unspecified section length is the streamable form handled by this reader
    } else if section_length < 0 || section_length % 4 != 0 {
        return Err(Error::InvalidSectionLength {
            length: section_length,
        });
    } else {
        // Finite sections require a separate section-boundary accounting mode
        return Err(Error::UnsupportedSectionLength {
            length: section_length,
        });
    }
    let body_end = bytes
        .len()
        .checked_sub(BLOCK_TRAILER_LENGTH)
        .ok_or_else(|| Error::InvalidBlockLength {
            block_type: SECTION_HEADER_BLOCK,
            length: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        })?;
    let options = parse_options(
        SECTION_HEADER_BLOCK,
        bytes.get(24..body_end).ok_or(Error::InvalidHeaderLayout)?,
        OptionScope::Section,
        order,
    )?;
    let mut report = None;
    for option in options {
        if option.code == 1
            && let Some(value) = crate::pcapng_collection::decode(&option.value)?
            && report.replace(value).is_some()
        {
            return Err(Error::InvalidCollectionReport);
        }
    }
    Ok(report)
}

pub fn read_u16(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<u16, Error> {
    let source = bytes
        .get(offset..offset + 2)
        .ok_or(Error::InvalidHeaderLayout)?;
    let value: [u8; 2] = source.try_into().map_err(|_| Error::InvalidHeaderLayout)?;
    Ok(decode_u16(value, order))
}

pub fn read_u32(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<u32, Error> {
    let source = bytes
        .get(offset..offset + 4)
        .ok_or(Error::InvalidHeaderLayout)?;
    let value: [u8; 4] = source.try_into().map_err(|_| Error::InvalidHeaderLayout)?;
    Ok(decode_u32(value, order))
}

pub fn read_i64(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<i64, Error> {
    let source = bytes
        .get(offset..offset + 8)
        .ok_or(Error::InvalidHeaderLayout)?;
    let value: [u8; 8] = source.try_into().map_err(|_| Error::InvalidHeaderLayout)?;
    Ok(match order {
        ByteOrder::Little => i64::from_le_bytes(value),
        ByteOrder::Big => i64::from_be_bytes(value),
    })
}

/// Header information decoded before a block body is allocated
#[derive(Clone, Copy)]
struct BlockHeader {
    header: [u8; GENERAL_HEADER_LENGTH],
    order: ByteOrder,
    prefix_length: usize,
    declared_length: u32,
    block_type: u32,
}

/// Read one complete block while checking its size before allocation
pub fn read_block<R: Read>(
    reader: &mut R,
    input_bytes: &mut u64,
    current_order: Option<ByteOrder>,
    max_input_bytes: u64,
    record_limit: Option<(u32, u32)>,
) -> Result<Option<(Block, Vec<u8>)>, Error> {
    let Some(block_header) =
        read_block_header(reader, input_bytes, current_order, max_input_bytes)?
    else {
        return Ok(None);
    };
    let BlockHeader {
        header,
        order,
        prefix_length,
        declared_length,
        block_type,
    } = block_header;
    if let Some((records_read, limit)) = record_limit
        && matches!(
            block_type,
            PACKET_BLOCK | ENHANCED_PACKET_BLOCK | SIMPLE_PACKET_BLOCK
        )
        && records_read >= limit
    {
        return Err(Error::RecordLimitExceeded { limit });
    }
    let declared_length_usize =
        usize::try_from(declared_length).map_err(|_| Error::LengthOverflow {
            length: declared_length,
        })?;
    let remaining = declared_length_usize - prefix_length;
    let attempted = input_bytes
        .checked_add(u64::try_from(remaining).unwrap_or(u64::MAX))
        .ok_or(Error::InputLimitExceeded {
            attempted: u64::MAX,
            limit: max_input_bytes,
        })?;
    if attempted > max_input_bytes {
        return Err(Error::InputLimitExceeded {
            attempted,
            limit: max_input_bytes,
        });
    }

    let mut bytes = Vec::with_capacity(declared_length_usize);
    bytes.extend_from_slice(&header);
    if prefix_length == SECTION_PREFIX_LENGTH {
        // The magic was read separately to identify the section byte order
        let magic = match order {
            ByteOrder::Little => BYTE_ORDER_MAGIC.to_le_bytes(),
            ByteOrder::Big => BYTE_ORDER_MAGIC.to_be_bytes(),
        };
        bytes.extend_from_slice(&magic);
    }
    let mut body = vec![0; remaining];
    read_exact_counted(
        reader,
        &mut body,
        input_bytes,
        "PCAPNG block body",
        max_input_bytes,
    )?;
    bytes.extend_from_slice(&body);
    let trailing = read_u32(&bytes, bytes.len() - BLOCK_TRAILER_LENGTH, order)?;
    if trailing != declared_length {
        return Err(Error::BlockLengthMismatch {
            block_type,
            declared: declared_length,
            trailing,
        });
    }
    Ok(Some((Block { block_type, order }, bytes)))
}

fn read_block_header<R: Read>(
    reader: &mut R,
    input_bytes: &mut u64,
    current_order: Option<ByteOrder>,
    max_input_bytes: u64,
) -> Result<Option<BlockHeader>, Error> {
    let Some(header) = read_header_bytes(reader, input_bytes, max_input_bytes)? else {
        return Ok(None);
    };
    let is_section_header = header[..4] == SECTION_HEADER_BLOCK.to_be_bytes();
    let (order, prefix_length, declared_length) = if is_section_header {
        let mut magic = [0; 4];
        read_exact_counted(
            reader,
            &mut magic,
            input_bytes,
            "PCAPNG byte-order magic",
            max_input_bytes,
        )?;
        let order = match magic {
            [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::Big,
            _ => {
                return Err(Error::InvalidByteOrderMagic {
                    magic: u32::from_be_bytes(magic),
                });
            }
        };
        let declared_length = decode_u32(
            header[4..8]
                .try_into()
                .map_err(|_| Error::InvalidHeaderLayout)?,
            order,
        );
        (order, SECTION_PREFIX_LENGTH, declared_length)
    } else {
        let order = current_order.ok_or(Error::SectionHeaderRequired)?;
        let declared_length = decode_u32(
            header[4..8]
                .try_into()
                .map_err(|_| Error::InvalidHeaderLayout)?,
            order,
        );
        (order, GENERAL_HEADER_LENGTH, declared_length)
    };
    let block_type = if is_section_header {
        SECTION_HEADER_BLOCK
    } else {
        decode_u32(
            header[..4]
                .try_into()
                .map_err(|_| Error::InvalidHeaderLayout)?,
            order,
        )
    };
    validate_block_length(block_type, declared_length)?;
    Ok(Some(BlockHeader {
        header,
        order,
        prefix_length,
        declared_length,
        block_type,
    }))
}

fn read_header_bytes<R: Read>(
    reader: &mut R,
    input_bytes: &mut u64,
    max_input_bytes: u64,
) -> Result<Option<[u8; GENERAL_HEADER_LENGTH]>, Error> {
    let mut header = [0; GENERAL_HEADER_LENGTH];
    let mut received = 0;
    while received < GENERAL_HEADER_LENGTH {
        // Keep the total input budget authoritative even when a reader returns
        // more bytes than the remaining header slice can hold
        let remaining_budget = max_input_bytes.saturating_sub(*input_bytes);
        if remaining_budget == 0 {
            let mut probe = [0; 1];
            let read = read_chunk(reader, &mut probe)?;
            if read == 0 {
                if received == 0 {
                    return Ok(None);
                }
                return Err(Error::UnexpectedEof {
                    section: "PCAPNG block header",
                    expected: GENERAL_HEADER_LENGTH,
                    received,
                });
            }
            return Err(Error::InputLimitExceeded {
                attempted: max_input_bytes.saturating_add(1),
                limit: max_input_bytes,
            });
        }
        let budget = usize::try_from(remaining_budget).unwrap_or(usize::MAX);
        let requested = (GENERAL_HEADER_LENGTH - received).min(budget);
        let destination = header
            .get_mut(received..received + requested)
            .ok_or(Error::InvalidHeaderLayout)?;
        let read = read_chunk(reader, destination)?;
        if read == 0 {
            if received == 0 {
                return Ok(None);
            }
            return Err(Error::UnexpectedEof {
                section: "PCAPNG block header",
                expected: GENERAL_HEADER_LENGTH,
                received,
            });
        }
        *input_bytes = input_bytes
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(Error::InputLimitExceeded {
                attempted: u64::MAX,
                limit: max_input_bytes,
            })?;
        received += read;
    }
    Ok(Some(header))
}

fn validate_block_length(block_type: u32, length: u32) -> Result<(), Error> {
    if length < 12 {
        return Err(Error::InvalidBlockLength { block_type, length });
    }
    if !length.is_multiple_of(4) {
        return Err(Error::BlockLengthNotAligned { block_type, length });
    }
    if usize::try_from(length).unwrap_or(usize::MAX) > MAX_BLOCK_LENGTH {
        return Err(Error::BlockLengthExceeded {
            block_type,
            length,
            limit: MAX_BLOCK_LENGTH,
        });
    }
    Ok(())
}
