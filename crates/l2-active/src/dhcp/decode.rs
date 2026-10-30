//! Decode only source-scoped, structurally checked DHCP offers

use std::{net::Ipv4Addr, num::NonZeroU32};

use l2_core::FrameField;
use l2_onpath::MacAddress;
use smoltcp::wire::{
    ArpHardware, DhcpOpCode, DhcpPacket, IpAddress, IpProtocol, Ipv4Packet, UdpPacket,
};

use crate::validate_ipv4_target;

use super::options;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Offer {
    pub server: Ipv4Addr,
    pub address: Ipv4Addr,
    pub lease_seconds: u32,
    pub source_mac: MacAddress,
    pub source_ip: Ipv4Addr,
    pub relay_ip: Ipv4Addr,
    pub udp_checksum_present: bool,
}

pub(super) fn offer(frame: &[u8], source: MacAddress, transaction: NonZeroU32) -> Option<Offer> {
    let (source_mac, payload) = ethernet(frame, source)?;
    let ip = ipv4(payload)?;
    let udp = udp(&ip)?;
    let payload = udp.payload();
    let dhcp = dhcp(payload, source, transaction)?;
    let address = dhcp.your_ip();
    let (server, lease_seconds) = options::offer(payload)?;
    validate_addresses(server, address, ip.dst_addr())?;
    Some(Offer {
        server,
        address,
        lease_seconds,
        source_mac,
        source_ip: ip.src_addr(),
        relay_ip: dhcp.relay_agent_ip(),
        udp_checksum_present: udp.checksum() != 0,
    })
}

fn ethernet(frame: &[u8], source: MacAddress) -> Option<(MacAddress, &[u8])> {
    let frame = l2_core::decode(frame).ok()?;
    if frame.field != FrameField::EtherType(0x0800)
        || !frame.vlan_tags.is_empty()
        || (frame.destination != source.bytes() && frame.destination != [0xff; 6])
    {
        return None;
    }
    Some((MacAddress::new(frame.source).ok()?, frame.payload))
}

fn ipv4(payload: &[u8]) -> Option<Ipv4Packet<&[u8]>> {
    let ip = Ipv4Packet::new_checked(payload).ok()?;
    if ip.version() != 4
        || ip.next_header() != IpProtocol::Udp
        || !unfragmented(payload, &ip)
        || !ip.verify_checksum()
        || validate_ipv4_target(ip.src_addr()).is_err()
    {
        return None;
    }
    Some(ip)
}

// smoltcp exposes fragment flags but not the reserved IPv4 flag
fn unfragmented(payload: &[u8], ip: &Ipv4Packet<&[u8]>) -> bool {
    payload.get(6).is_some_and(|flags| flags & 0x80 == 0)
        && !ip.more_frags()
        && ip.frag_offset() == 0
}

// The destination is either limited broadcast or the address being offered
fn validate_addresses(server: Ipv4Addr, address: Ipv4Addr, destination: Ipv4Addr) -> Option<()> {
    validate_ipv4_target(server).ok()?;
    validate_ipv4_target(address).ok()?;
    if destination != Ipv4Addr::BROADCAST && destination != address {
        return None;
    }
    Some(())
}

fn udp<'a>(ip: &Ipv4Packet<&'a [u8]>) -> Option<UdpPacket<&'a [u8]>> {
    let payload = ip.payload();
    let udp = UdpPacket::new_checked(payload).ok()?;
    if udp.src_port() != 67
        || udp.dst_port() != 68
        || usize::from(udp.len()) != payload.len()
        || !udp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
        )
    {
        return None;
    }
    Some(udp)
}

fn dhcp(payload: &[u8], source: MacAddress, transaction: NonZeroU32) -> Option<DhcpPacket<&[u8]>> {
    let packet = DhcpPacket::new_checked(payload).ok()?;
    if packet.opcode() != DhcpOpCode::Reply
        || packet.hardware_type() != ArpHardware::Ethernet
        || packet.hardware_len() != 6
        || packet.magic_number() != 0x6382_5363
        || packet.transaction_id() != transaction.get()
        || packet.client_hardware_address().0 != source.bytes()
    {
        return None;
    }
    Some(packet)
}
