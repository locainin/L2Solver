//! Identity extraction runs only after structural fingerprint validation

use crate::{
    Fingerprint, FingerprintStatus, IdentityRole, NetworkAddress, Protocol, ProtocolIdentity, arp,
    bytes::{read_u8, read_u16, take},
};
use l2_core::{EthernetFrame, FrameField};

const IPV4_SOURCE_OFFSET: usize = 12;
const IPV6_SOURCE_OFFSET: usize = 8;

pub fn extract(frame: &EthernetFrame<'_>, fingerprint: Fingerprint) -> Option<ProtocolIdentity> {
    if fingerprint.status != FingerprintStatus::Observed {
        return None;
    }
    match fingerprint.protocol {
        Protocol::Arp => arp(frame),
        Protocol::Dhcp => Some(ipv4(frame, IdentityRole::DhcpClient)),
        Protocol::Hsrp => Some(ipv4(frame, IdentityRole::FirstHopRouter)),
        Protocol::Vrrp => ip_first_hop(frame),
        Protocol::Ipv6Ra => Some(ipv6(frame, IdentityRole::Ipv6Router)),
        Protocol::Ipv6Nd => Some(ipv6(frame, IdentityRole::Ipv6Neighbor)),
        Protocol::Mld => Some(ipv6(frame, IdentityRole::MulticastParticipant)),
        Protocol::Igmp | Protocol::Netbios => Some(ipv4(frame, IdentityRole::MulticastParticipant)),
        Protocol::Mdns | Protocol::Ssdp => ip_multicast(frame),
        Protocol::Dhcpv6 => Some(ipv6(frame, IdentityRole::Dhcpv6Participant)),
        Protocol::Eapol => Some(outer(frame, IdentityRole::AccessControlParticipant)),
        Protocol::Lacp | Protocol::Pagp => Some(outer(frame, IdentityRole::AggregationParticipant)),
        Protocol::Macsec | Protocol::Mka => {
            Some(outer(frame, IdentityRole::LinkSecurityParticipant))
        }
        Protocol::Cdp
        | Protocol::Dtp
        | Protocol::Vtp
        | Protocol::PvstPlus
        | Protocol::CiscoSnap
        | Protocol::Lldp
        | Protocol::Stp => Some(outer(frame, IdentityRole::ControlPlaneParticipant)),
    }
}

fn ip_first_hop(frame: &EthernetFrame<'_>) -> Option<ProtocolIdentity> {
    match frame.field {
        FrameField::EtherType(0x0800) => Some(ipv4(frame, IdentityRole::FirstHopRouter)),
        FrameField::EtherType(0x86dd) => Some(ipv6(frame, IdentityRole::FirstHopRouter)),
        FrameField::EtherType(_) | FrameField::Length(_) => None,
    }
}

fn ip_multicast(frame: &EthernetFrame<'_>) -> Option<ProtocolIdentity> {
    match frame.field {
        FrameField::EtherType(0x0800) => Some(ipv4(frame, IdentityRole::MulticastParticipant)),
        FrameField::EtherType(0x86dd) => Some(ipv6(frame, IdentityRole::MulticastParticipant)),
        FrameField::EtherType(_) | FrameField::Length(_) => None,
    }
}

fn arp(frame: &EthernetFrame<'_>) -> Option<ProtocolIdentity> {
    let packet = arp::ethernet_ipv4(frame.payload)?;
    let address = packet
        .is_binding_claim()
        .then_some(NetworkAddress::Ipv4(packet.sender_ip));
    Some(ProtocolIdentity {
        // Probes ask about a target address and do not claim the all-zero sender address
        role: if packet.operation == 1 && packet.sender_ip == [0; 4] {
            IdentityRole::AddressProbe
        } else {
            IdentityRole::AddressClaim
        },
        source_mac: frame.source,
        claimed_mac: Some(packet.sender_mac),
        address,
    })
}

fn ipv4(frame: &EthernetFrame<'_>, default_role: IdentityRole) -> ProtocolIdentity {
    let address = read_array::<4>(frame.payload, IPV4_SOURCE_OFFSET)
        .filter(|octets| *octets != [0; 4])
        .map(NetworkAddress::Ipv4);
    let role = if default_role == IdentityRole::DhcpClient {
        dhcp_role(frame.payload).unwrap_or(default_role)
    } else {
        default_role
    };
    ProtocolIdentity {
        role,
        source_mac: frame.source,
        claimed_mac: None,
        address,
    }
}

fn dhcp_role(packet: &[u8]) -> Option<IdentityRole> {
    let header_words = read_u8(packet, 0)? & 0x0f;
    let header_length = usize::from(header_words).checked_mul(4)?;
    let source_port = read_u16(packet, header_length)?;
    match source_port {
        67 => Some(IdentityRole::DhcpServer),
        _ => None,
    }
}

fn ipv6(frame: &EthernetFrame<'_>, role: IdentityRole) -> ProtocolIdentity {
    ProtocolIdentity {
        role,
        source_mac: frame.source,
        claimed_mac: None,
        address: read_array::<16>(frame.payload, IPV6_SOURCE_OFFSET)
            .filter(|octets| *octets != [0; 16])
            .map(NetworkAddress::Ipv6),
    }
}

const fn outer(frame: &EthernetFrame<'_>, role: IdentityRole) -> ProtocolIdentity {
    ProtocolIdentity {
        role,
        source_mac: frame.source,
        claimed_mac: None,
        address: None,
    }
}

fn read_array<const LENGTH: usize>(input: &[u8], offset: usize) -> Option<[u8; LENGTH]> {
    take(input, offset, LENGTH)?.try_into().ok()
}
