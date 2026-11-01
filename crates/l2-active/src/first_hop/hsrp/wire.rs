//! Recognize and check the RFC 2281 fixed-header profile

use std::net::Ipv4Addr;

use l2_core::{EthernetFrame, FrameField};
use l2_onpath::MacAddress;
use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};

use crate::validate_ipv4_target;

use super::{HsrpAdvertisement, HsrpEvidence, HsrpMalformed, HsrpOpcode, HsrpState};

const DESTINATION_MAC: [u8; 6] = [1, 0, 0x5e, 0, 0, 2];
const DESTINATION_IP: [u8; 4] = [224, 0, 0, 2];
const HSRP_PORT: u16 = 1985;
const UDP_HEADER_LEN: usize = 8;
const HSRP_HEADER_LEN: usize = 20;

pub(super) fn classify(bytes: &[u8], selected: Option<u8>) -> Option<HsrpEvidence> {
    let frame = l2_core::decode(bytes).ok()?;
    if !candidate(&frame, selected) {
        return None;
    }
    Some(match decode(&frame) {
        Ok(evidence) => evidence,
        Err(reason) => HsrpEvidence::Malformed(reason),
    })
}

fn candidate(frame: &EthernetFrame<'_>, selected: Option<u8>) -> bool {
    let ip = frame.payload;
    if frame.field != FrameField::EtherType(0x0800)
        || !frame.vlan_tags.is_empty()
        || frame.destination != DESTINATION_MAC
        || ip.get(9) != Some(&17)
        || ip.get(16..20) != Some(&DESTINATION_IP)
    {
        return false;
    }
    // Selection uses only bytes within the declared IP and UDP envelopes
    let Some(first) = ip.first() else {
        return false;
    };
    let header_len = usize::from(first & 0x0f) * 4;
    let Some(length) = ip.get(2..4).and_then(|b| <[u8; 2]>::try_from(b).ok()) else {
        return false;
    };
    let total_len = usize::from(u16::from_be_bytes(length));
    if header_len < 20 || total_len < header_len + 4 {
        return false;
    }
    let end = total_len.min(ip.len());
    let Some(udp) = ip.get(header_len..end) else {
        return false;
    };
    let port = HSRP_PORT.to_be_bytes();
    if udp.get(..2) != Some(port.as_slice()) || udp.get(2..4) != Some(port.as_slice()) {
        return false;
    }
    let Some(group) = selected else {
        return true;
    };
    // Fragments and other versions do not expose a trustworthy v1 group field
    if ip
        .get(6..8)
        .and_then(|flags| <[u8; 2]>::try_from(flags).ok())
        .is_none_or(|flags| u16::from_be_bytes(flags) & 0x3fff != 0)
    {
        return false;
    }
    let Some(length) = udp.get(4..6).and_then(|b| <[u8; 2]>::try_from(b).ok()) else {
        return false;
    };
    let udp_len = usize::from(u16::from_be_bytes(length));
    if udp_len < UDP_HEADER_LEN + 7 {
        return false;
    }
    udp.get(UDP_HEADER_LEN) == Some(&0) && udp.get(UDP_HEADER_LEN + 6) == Some(&group)
}

fn decode(frame: &EthernetFrame<'_>) -> Result<HsrpEvidence, HsrpMalformed> {
    let source_mac = MacAddress::new(frame.source).map_err(|_| HsrpMalformed::SourceMac)?;
    let header = l2_discovery::ip_header(frame).ok_or(HsrpMalformed::Ipv4)?;
    if header.fragmented {
        return Err(HsrpMalformed::Ipv4);
    }
    // Ignore captured link padding beyond the declared IPv4 datagram
    let packet = frame
        .payload
        .get(..header.total_len)
        .ok_or(HsrpMalformed::Ipv4)?;
    let ip = Ipv4Packet::new_checked(packet).map_err(|_| HsrpMalformed::Ipv4)?;
    if ip.hop_limit() != 1 || !ip.verify_checksum() || validate_ipv4_target(ip.src_addr()).is_err()
    {
        return Err(HsrpMalformed::Ipv4);
    }
    let payload = ip.payload();
    let udp = UdpPacket::new_checked(payload).map_err(|_| HsrpMalformed::Udp)?;
    if udp.src_port() != HSRP_PORT
        || udp.dst_port() != HSRP_PORT
        || usize::from(udp.len()) != payload.len()
        || !udp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
        )
    {
        return Err(HsrpMalformed::Udp);
    }
    message(&ip, &udp, source_mac)
}

fn message(
    ip: &Ipv4Packet<&[u8]>,
    udp: &UdpPacket<&[u8]>,
    source_mac: MacAddress,
) -> Result<HsrpEvidence, HsrpMalformed> {
    // A zero UDP checksum is allowed by IPv4 but is never treated as authentication
    let body = udp.payload();
    let version = body.first().copied().ok_or(HsrpMalformed::Protocol)?;
    if version != 0 {
        return Ok(HsrpEvidence::UnsupportedVersion(version));
    }
    let (fixed, _) = body
        .split_first_chunk::<HSRP_HEADER_LEN>()
        .ok_or(HsrpMalformed::Protocol)?;
    // Authentication octets are intentionally not interpreted or retained separately
    let [
        _,
        opcode,
        state,
        hello,
        hold,
        priority,
        group,
        reserved,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
        a,
        b,
        c,
        d,
    ] = *fixed;
    let opcode = match opcode {
        0 => HsrpOpcode::Hello,
        1 => HsrpOpcode::Coup,
        2 => HsrpOpcode::Resign,
        _ => return Err(HsrpMalformed::Protocol),
    };
    let state = match state {
        0 => HsrpState::Initial,
        1 => HsrpState::Learn,
        2 => HsrpState::Listen,
        4 => HsrpState::Speak,
        8 => HsrpState::Standby,
        16 => HsrpState::Active,
        _ => return Err(HsrpMalformed::Protocol),
    };
    if reserved != 0 || (opcode == HsrpOpcode::Hello && hold <= hello) {
        return Err(HsrpMalformed::Protocol);
    }
    Ok(HsrpEvidence::Advertisement(HsrpAdvertisement {
        source_mac,
        source_ip: ip.src_addr(),
        virtual_ip: Ipv4Addr::new(a, b, c, d),
        opcode,
        state,
        group,
        priority,
        hello_seconds: hello,
        hold_seconds: hold,
        udp_checksum_present: udp.checksum() != 0,
    }))
}
