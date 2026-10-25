use crate::{
    Fingerprint, FingerprintStatus,
    bytes::{read_u16, take},
    dhcp, hsrp, igmp, ip, udp, vrrp,
};

const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_IGMP: u8 = 2;
const IP_PROTOCOL_VRRP: u8 = 112;

/// Fingerprint bounded IPv4 control and LAN service traffic
pub fn fingerprint(packet: &[u8]) -> Option<Fingerprint> {
    let header = ip::ipv4_header(packet)?;
    let header_len = header.header_len;
    let total_len = header.total_len;
    if header.fragmented {
        // Upper-layer ports cannot be trusted until all fragments are reassembled
        return None;
    }
    let ip_protocol = header.protocol;
    if ip_protocol == IP_PROTOCOL_IGMP {
        let available_end = packet.len().min(total_len);
        let body_len = available_end.checked_sub(header_len)?;
        return Some(igmp::fingerprint(
            take(packet, header_len, body_len)?,
            total_len > packet.len(),
        ));
    }
    if ip_protocol == IP_PROTOCOL_VRRP {
        let available_end = packet.len().min(total_len);
        let body_len = available_end.checked_sub(header_len)?;
        return Some(vrrp::fingerprint(
            take(packet, header_len, body_len)?,
            vrrp::IpFamily::V4,
            total_len > packet.len(),
        ));
    }
    if ip_protocol != IP_PROTOCOL_UDP {
        return None;
    }

    let available_end = packet.len().min(total_len);
    let protocol = udp::fingerprint(
        packet,
        header_len,
        available_end,
        total_len,
        total_len > packet.len(),
        udp::AddressFamily::Ipv4,
    )?;
    if protocol.status != FingerprintStatus::Observed {
        return Some(protocol);
    }
    match protocol.protocol {
        crate::Protocol::Dhcp | crate::Protocol::Hsrp => {
            let udp_len =
                read_u16(take(packet, header_len, udp::UDP_HEADER_LEN)?, 4).map(usize::from)?;
            let body_len = udp_len.checked_sub(udp::UDP_HEADER_LEN)?;
            let body_offset = header_len + udp::UDP_HEADER_LEN;
            let body = take(packet, body_offset, body_len)?;
            Some(if matches!(protocol.protocol, crate::Protocol::Dhcp) {
                dhcp::fingerprint(body)
            } else {
                hsrp::fingerprint(body)
            })
        }
        _ => Some(protocol),
    }
}
