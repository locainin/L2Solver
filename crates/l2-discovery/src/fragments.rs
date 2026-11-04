//! Literal fragment offsets and payload bounds, without choosing a datagram generation

use crate::{
    MAX_IPV6_EXTENSION_HEADERS, NetworkAddress, TransportPacket,
    bytes::{read_u16, read_u32},
    ip, ipv6, transport,
};
use l2_core::{EthernetFrame, FrameField};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug)]
pub struct FragmentPacket<'a> {
    pub family: IpFamily,
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub identification: u32,
    /// IPv4 protocol or the next-header value carried by the IPv6 fragment header
    pub protocol: u8,
    pub offset: usize,
    pub more: bool,
    pub payload_offset: usize,
    pub declared_payload_length: usize,
    pub payload: &'a [u8],
    pub captured_complete: bool,
}

/// Read supported fragment metadata while keeping truncated payload prefixes explicit
#[must_use]
pub fn fragment_packet<'a>(frame: &EthernetFrame<'a>) -> Option<FragmentPacket<'a>> {
    let FrameField::EtherType(protocol) = frame.field else {
        return None;
    };
    fragment_packet_from_payload(protocol, frame.payload)
}

/// Read fragment facts from a protocol identifier and bounded IP payload
///
/// The identifier must have `EtherType` semantics for this link-layer format
#[must_use]
pub fn fragment_packet_from_payload(protocol: u16, payload: &[u8]) -> Option<FragmentPacket<'_>> {
    let (family, header, identification, protocol, offset, more, payload_offset) = match protocol {
        0x0800 => {
            let header = ip::ipv4_header(payload)?;
            if !header.fragmented {
                return None;
            }
            let flags = read_u16(payload, 6)?;
            let start = header.header_len;
            let protocol = header.protocol;
            (
                IpFamily::V4,
                header,
                u32::from(read_u16(payload, 4)?),
                protocol,
                usize::from(flags & 0x1fff) * 8,
                flags & 0x2000 != 0,
                start,
            )
        }
        0x86dd => ipv6_fragment(payload)?,
        _ => return None,
    };
    let declared_payload_length = header.total_len.checked_sub(payload_offset)?;
    let end = header.total_len.min(payload.len());
    Some(FragmentPacket {
        family,
        source: header.source,
        destination: header.destination,
        identification,
        protocol,
        offset,
        more,
        payload_offset,
        declared_payload_length,
        payload: payload.get(payload_offset..end)?,
        captured_complete: payload.len() >= header.total_len,
    })
}

fn ipv6_fragment(bytes: &[u8]) -> Option<(IpFamily, ip::IpHeader, u32, u8, usize, bool, usize)> {
    let header = ip::ipv6_header(bytes)?;
    let mut protocol = header.protocol;
    let mut offset = 40;
    for _ in 0..MAX_IPV6_EXTENSION_HEADERS {
        if !matches!(protocol, 0 | 43 | 44 | 51 | 60) {
            return None;
        }
        let (following, length, fragmented) =
            ipv6::extension_span(bytes, protocol, offset, header.total_len.min(bytes.len()))?;
        if protocol == 44 {
            if !fragmented {
                return None;
            }
            let flags = read_u16(bytes, offset + 2)?;
            let identification = read_u32(bytes, offset + 4)?;
            return Some((
                IpFamily::V6,
                header,
                identification,
                following,
                usize::from(flags & 0xfff8),
                flags & 1 != 0,
                offset + length,
            ));
        }
        protocol = following;
        offset += length;
    }
    None
}

/// Decode a uniquely reconstructed payload through the same transport parser as IP packets
#[must_use]
pub fn fragment_transport(
    family: IpFamily,
    mut protocol: u8,
    bytes: &[u8],
) -> Option<TransportPacket<'_>> {
    let mut offset = 0;
    if family == IpFamily::V6 {
        let mut count = 0;
        while matches!(protocol, 0 | 43 | 51 | 60) {
            if count == MAX_IPV6_EXTENSION_HEADERS {
                return None;
            }
            let (following, length, _) =
                ipv6::extension_span(bytes, protocol, offset, bytes.len())?;
            protocol = following;
            offset += length;
            count += 1;
        }
        // Nested fragment headers require a separate interpretation, never recursive guessing
        if protocol == 44 {
            return None;
        }
    }
    transport::parse(protocol, bytes, offset)
}
