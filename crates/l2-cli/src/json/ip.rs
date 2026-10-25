//! Serialize bounded payload locations without copying or replacing raw evidence

use l2_discovery::dns::{self, DnsDecoding};
use l2_discovery::{IpPacket, NetworkAddress, TransportHeader, TransportPacket};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct IpRecord {
    source: NetworkAddress,
    destination: NetworkAddress,
    protocol: u8,
    fragmented: bool,
    declared_len: usize,
    transport: Option<TransportRecord>,
}

#[derive(Serialize)]
struct TransportRecord {
    ports: (u16, u16),
    header: TransportHeader,
    payload: ByteRange,
    trailing: Option<ByteRange>,
    dns: Option<DnsDecoding>,
}

#[derive(Serialize)]
struct ByteRange {
    offset: usize,
    length: usize,
}

pub(super) fn record(ip: IpPacket<'_>, frame_offset: usize) -> IpRecord {
    let dns = dns::udp_message(ip);
    IpRecord {
        source: ip.source,
        destination: ip.destination,
        protocol: ip.protocol,
        fragmented: ip.fragmented,
        declared_len: ip.declared_len,
        transport: ip
            .transport
            .map(|packet| transport(packet, frame_offset, dns)),
    }
}

fn transport(
    packet: TransportPacket<'_>,
    frame_offset: usize,
    dns: Option<DnsDecoding>,
) -> TransportRecord {
    // The parser already bounded these offsets inside the declared IP envelope
    let payload_offset = frame_offset + packet.payload_offset;
    TransportRecord {
        ports: packet.ports,
        header: packet.header,
        payload: ByteRange {
            offset: payload_offset,
            length: packet.payload.len(),
        },
        trailing: (!packet.trailing_bytes.is_empty()).then_some(ByteRange {
            offset: payload_offset + packet.payload.len(),
            length: packet.trailing_bytes.len(),
        }),
        dns,
    }
}
