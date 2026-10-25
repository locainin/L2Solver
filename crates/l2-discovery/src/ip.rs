//! Shared IP length boundaries and literal endpoint observations

use crate::{
    MAX_IPV6_EXTENSION_HEADERS, NetworkAddress, TransportPacket,
    bytes::{read_u8, read_u16, take},
    ipv6, transport,
};
use l2_core::{EthernetFrame, FrameField};

/// Structurally bounded IP headers, without authentication or checksum validation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpPacket<'a> {
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    /// IPv4 protocol or the last IPv6 next-header value safely reached
    pub protocol: u8,
    /// Complete TCP or UDP envelopes, absent for fragments or unknown layouts
    pub transport: Option<TransportPacket<'a>>,
    pub fragmented: bool,
    pub declared_len: usize,
    /// Captured bytes outside the declared IP length, which may include padding or FCS
    pub trailing_bytes: &'a [u8],
}

impl IpPacket<'_> {
    /// Return ports only when a complete supported transport header was bounded
    #[must_use]
    pub const fn ports(self) -> Option<(u16, u16)> {
        match self.transport {
            Some(transport) => Some(transport.ports),
            None => None,
        }
    }
}

/// Structurally bounded IP header facts, which do not imply a captured transport body
///
/// IPv6 extensions are traversed only while their declared and captured bounds fit
pub struct IpHeader {
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub header_len: usize,
    pub total_len: usize,
    pub protocol: u8,
    pub fragmented: bool,
}

pub fn ipv4_header(packet: &[u8]) -> Option<IpHeader> {
    let version_and_ihl = read_u8(packet, 0)?;
    if version_and_ihl >> 4 != 4 || version_and_ihl & 0x0f < 5 {
        return None;
    }
    let header_len = usize::from(version_and_ihl & 0x0f) * 4;
    take(packet, 0, header_len)?;
    let total_len = usize::from(read_u16(packet, 2)?);
    if total_len < header_len {
        return None;
    }
    let flags_and_offset = read_u16(packet, 6)?;
    // The reserved flag is required to be zero in the supported IPv4 header layout
    if flags_and_offset & 0x8000 != 0 {
        return None;
    }
    Some(IpHeader {
        source: NetworkAddress::Ipv4(take(packet, 12, 4)?.try_into().ok()?),
        destination: NetworkAddress::Ipv4(take(packet, 16, 4)?.try_into().ok()?),
        header_len,
        total_len,
        protocol: read_u8(packet, 9)?,
        // Both the more-fragments bit and a nonzero offset prevent port interpretation
        fragmented: flags_and_offset & 0x3fff != 0,
    })
}

pub fn ipv6_header(packet: &[u8]) -> Option<IpHeader> {
    if read_u8(packet, 0)? >> 4 != 6 {
        return None;
    }
    take(packet, 0, 40)?;
    Some(IpHeader {
        source: NetworkAddress::Ipv6(take(packet, 8, 16)?.try_into().ok()?),
        destination: NetworkAddress::Ipv6(take(packet, 24, 16)?.try_into().ok()?),
        header_len: 40,
        total_len: 40 + usize::from(read_u16(packet, 4)?),
        protocol: read_u8(packet, 6)?,
        fragmented: false,
    })
}

/// Read supported IP header facts even when the declared body is not captured
///
/// Base headers, options, and traversed extensions must be present. Unsupported
/// jumbograms or invalid header bounds return no observation. No payload is exposed
#[must_use]
pub fn ip_header(frame: &EthernetFrame<'_>) -> Option<IpHeader> {
    let mut header = match frame.field {
        FrameField::EtherType(0x0800) => ipv4_header(frame.payload)?,
        FrameField::EtherType(0x86dd) => ipv6_header(frame.payload)?,
        _ => return None,
    };
    // A zero-length IPv6 packet with a hop-by-hop header may be a jumbogram
    if matches!(header.source, NetworkAddress::Ipv6(_)) {
        if header.total_len == 40 && header.protocol != 59 {
            return None;
        }
        walk_ipv6(frame.payload, &mut header)?;
    }
    Some(header)
}

/// Read complete IP envelopes without interpreting application payload or intent
///
/// Unsupported jumbograms, incomplete envelopes, and invalid extension bounds
/// return no observation. Source and destination addresses remain header claims
#[must_use]
pub fn ip_packet<'a>(frame: &EthernetFrame<'a>) -> Option<IpPacket<'a>> {
    let header = ip_header(frame)?;
    let bytes = frame.payload.get(..header.total_len)?;
    let transport = if header.fragmented {
        None
    } else {
        transport::parse(header.protocol, bytes, header.header_len)
    };
    Some(IpPacket {
        source: header.source,
        destination: header.destination,
        protocol: header.protocol,
        transport,
        fragmented: header.fragmented,
        declared_len: header.total_len,
        trailing_bytes: frame.payload.get(header.total_len..)?,
    })
}

fn walk_ipv6(packet: &[u8], header: &mut IpHeader) -> Option<()> {
    let mut count = 0;
    while matches!(header.protocol, 0 | 43 | 44 | 51 | 60) {
        if count == MAX_IPV6_EXTENSION_HEADERS {
            return None;
        }
        // A complete extension can identify the next protocol even when later body bytes are missing
        let available_end = header.total_len.min(packet.len());
        let (following, length, fragmented) =
            ipv6::extension_span(packet, header.protocol, header.header_len, available_end)?;
        header.protocol = following;
        header.header_len += length;
        header.fragmented |= fragmented;
        count += 1;
        // A fragment body may start halfway through another header
        if fragmented {
            break;
        }
    }
    Some(())
}
