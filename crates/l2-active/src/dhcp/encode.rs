//! Encode one complete broadcast DHCP discovery frame

use std::{net::Ipv4Addr, num::NonZeroU32};

use l2_core::{EthernetFrame, FrameField};
use l2_onpath::MacAddress;
use smoltcp::wire::{
    DhcpMessageType, DhcpPacket, DhcpRepr, EthernetAddress, IpAddress, IpProtocol, Ipv4Packet,
    UdpPacket,
};

use super::DhcpError;

const DHCP_LEN: usize = 300;
const UDP_LEN: usize = 8 + DHCP_LEN;
const IPV4_LEN: usize = 20 + UDP_LEN;
pub(super) const FRAME_LEN: usize = 14 + IPV4_LEN;

pub(super) fn discover(
    source: MacAddress,
    transaction: NonZeroU32,
) -> Result<[u8; FRAME_LEN], DhcpError> {
    let payload = dhcp_payload(source, transaction)?;
    let udp = udp_datagram(&payload)?;
    let ip = ipv4_datagram(&udp)?;
    let ethernet = EthernetFrame {
        destination: [0xff; 6],
        source: source.bytes(),
        vlan_tags: Vec::new(),
        field: FrameField::EtherType(0x0800),
        payload: &ip,
        padding: &[],
    };
    let mut frame = [0; FRAME_LEN];
    l2_core::encode(&ethernet, &mut frame).map_err(|_| DhcpError::Encoding)?;
    Ok(frame)
}

fn dhcp_payload(source: MacAddress, transaction: NonZeroU32) -> Result<[u8; DHCP_LEN], DhcpError> {
    let mut payload = [0_u8; DHCP_LEN];
    let mut packet =
        DhcpPacket::new_checked(payload.as_mut_slice()).map_err(|_| DhcpError::Encoding)?;
    let representation = DhcpRepr {
        message_type: DhcpMessageType::Discover,
        transaction_id: transaction.get(),
        secs: 0,
        client_hardware_address: EthernetAddress(source.bytes()),
        client_ip: Ipv4Addr::UNSPECIFIED,
        your_ip: Ipv4Addr::UNSPECIFIED,
        server_ip: Ipv4Addr::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested_ip: None,
        client_identifier: None,
        server_identifier: None,
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: None,
        renew_duration: None,
        rebind_duration: None,
        additional_options: &[],
    };
    representation
        .emit(&mut packet)
        .map_err(|_| DhcpError::Encoding)?;
    Ok(payload)
}

fn udp_datagram(payload: &[u8; DHCP_LEN]) -> Result<[u8; UDP_LEN], DhcpError> {
    let mut bytes = [0_u8; UDP_LEN];
    // Set the length before checked construction so all payload access is bounded
    bytes
        .get_mut(4..6)
        .ok_or(DhcpError::Encoding)?
        .copy_from_slice(
            &u16::try_from(UDP_LEN)
                .map_err(|_| DhcpError::Encoding)?
                .to_be_bytes(),
        );
    let mut packet =
        UdpPacket::new_checked(bytes.as_mut_slice()).map_err(|_| DhcpError::Encoding)?;
    packet.set_src_port(68);
    packet.set_dst_port(67);
    packet.payload_mut().copy_from_slice(payload);
    packet.fill_checksum(
        &IpAddress::Ipv4(Ipv4Addr::UNSPECIFIED),
        &IpAddress::Ipv4(Ipv4Addr::BROADCAST),
    );
    Ok(bytes)
}

fn ipv4_datagram(udp: &[u8; UDP_LEN]) -> Result<[u8; IPV4_LEN], DhcpError> {
    let mut bytes = [0_u8; IPV4_LEN];
    // The checked IPv4 wrapper requires an established header and total length
    *bytes.first_mut().ok_or(DhcpError::Encoding)? = 0x45;
    bytes
        .get_mut(2..4)
        .ok_or(DhcpError::Encoding)?
        .copy_from_slice(
            &u16::try_from(IPV4_LEN)
                .map_err(|_| DhcpError::Encoding)?
                .to_be_bytes(),
        );
    let mut packet =
        Ipv4Packet::new_checked(bytes.as_mut_slice()).map_err(|_| DhcpError::Encoding)?;
    packet.set_hop_limit(64);
    packet.set_next_header(IpProtocol::Udp);
    packet.set_src_addr(Ipv4Addr::UNSPECIFIED);
    packet.set_dst_addr(Ipv4Addr::BROADCAST);
    packet.payload_mut().copy_from_slice(udp);
    packet.fill_checksum();
    Ok(bytes)
}
