//! Bounded TCP and UDP envelopes without stream or application interpretation

use crate::bytes::{read_u8, read_u16, read_u32, take};
use serde::Serialize;

/// Literal transport header fields from a complete, unfragmented IP envelope
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportHeader {
    Udp,
    Tcp {
        sequence: u32,
        acknowledgement: u32,
        /// The eight-bit flags byte, without interpreting connection state
        flags: u8,
    },
}

/// Byte ranges borrowed from the declared IP envelope, excluding Ethernet padding
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPacket<'a> {
    pub ports: (u16, u16),
    pub header: TransportHeader,
    /// Zero-based offset from the beginning of the IP header
    pub payload_offset: usize,
    pub payload: &'a [u8],
    /// Bytes after the UDP length but inside IP; always empty for TCP
    pub trailing_bytes: &'a [u8],
}

pub fn parse(protocol: u8, ip: &[u8], offset: usize) -> Option<TransportPacket<'_>> {
    let body = ip.get(offset..)?;
    let (header, header_len, total_len) = match protocol {
        17 => {
            take(body, 0, 8)?;
            let total_len = usize::from(read_u16(body, 4)?);
            (TransportHeader::Udp, 8, total_len)
        }
        6 => {
            take(body, 0, 20)?;
            let header_len = usize::from(read_u8(body, 12)? >> 4) * 4;
            if header_len < 20 {
                return None;
            }
            let header = TransportHeader::Tcp {
                sequence: read_u32(body, 4)?,
                acknowledgement: read_u32(body, 8)?,
                flags: read_u8(body, 13)?,
            };
            (header, header_len, body.len())
        }
        _ => return None,
    };
    // This checked slice also rejects undersized UDP lengths and overlong transport headers
    Some(TransportPacket {
        ports: (read_u16(body, 0)?, read_u16(body, 2)?),
        header,
        payload_offset: offset + header_len,
        payload: body.get(header_len..total_len)?,
        trailing_bytes: body.get(total_len..)?,
    })
}
