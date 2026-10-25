//! Classic PCAP global and per-record header decoding

use crate::{Error, LinkType};

pub const GLOBAL_HEADER_LENGTH: usize = 24;
pub const RECORD_HEADER_LENGTH: usize = 16;

#[derive(Clone, Copy)]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
pub struct GlobalHeader {
    pub byte_order: ByteOrder,
    pub nanosecond_timestamps: bool,
    pub link_type: LinkType,
    pub snaplen: u32,
}

pub fn field<const LENGTH: usize>(bytes: &[u8], offset: usize) -> Result<[u8; LENGTH], Error> {
    let Some(source) = bytes
        .get(offset..)
        .and_then(|remaining| remaining.get(..LENGTH))
    else {
        return Err(Error::InvalidHeaderLayout);
    };
    let mut value = [0; LENGTH];
    value.copy_from_slice(source);
    Ok(value)
}

pub const fn decode_u16(bytes: [u8; 2], byte_order: ByteOrder) -> u16 {
    match byte_order {
        ByteOrder::Little => u16::from_le_bytes(bytes),
        ByteOrder::Big => u16::from_be_bytes(bytes),
    }
}

pub const fn decode_u32(bytes: [u8; 4], byte_order: ByteOrder) -> u32 {
    match byte_order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

pub fn parse_global_header(bytes: &[u8; GLOBAL_HEADER_LENGTH]) -> Result<GlobalHeader, Error> {
    let magic = field::<4>(bytes, 0)?;
    let (byte_order, nanosecond_timestamps) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (ByteOrder::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (ByteOrder::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (ByteOrder::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (ByteOrder::Big, true),
        [0x0a, 0x0d, 0x0d, 0x0a] => return Err(Error::UnsupportedFormat { name: "PCAPNG" }),
        _ => return Err(Error::UnsupportedMagic { magic }),
    };

    let major = decode_u16(field::<2>(bytes, 4)?, byte_order);
    let minor = decode_u16(field::<2>(bytes, 6)?, byte_order);
    if major != 2 || minor != 4 {
        return Err(Error::UnsupportedVersion { major, minor });
    }

    // Reserved words are deliberately ignored as required by the savefile specification
    let snaplen = decode_u32(field::<4>(bytes, 16)?, byte_order);
    if snaplen == 0 {
        return Err(Error::InvalidSnaplen { snaplen });
    }

    let network = decode_u32(field::<4>(bytes, 20)?, byte_order);
    if network >> 16 != 0 {
        return Err(Error::UnsupportedLinkMetadata { value: network });
    }
    let link_type = u16::try_from(network & u32::from(u16::MAX))
        .map_err(|_| Error::LengthOverflow { length: network })?;
    let link_type = LinkType::from_raw(link_type);

    Ok(GlobalHeader {
        byte_order,
        nanosecond_timestamps,
        link_type,
        snaplen,
    })
}
