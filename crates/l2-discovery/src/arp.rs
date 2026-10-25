use crate::{
    Fingerprint, Protocol,
    bytes::{read_u8, read_u16, take},
};
use l2_core::{EthernetFrame, FrameField};

const ARP_FIXED_HEADER_LEN: usize = 8;

/// Literal Ethernet/IPv4 ARP fields, including address probes and mismatched MACs
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    /// Whether the sender fields can take part in a unicast binding comparison
    #[must_use]
    pub fn is_binding_claim(self) -> bool {
        let [mac_first, ..] = self.sender_mac;
        let [ip_first, ..] = self.sender_ip;
        self.sender_mac != [0; 6]
            && mac_first & 1 == 0
            && self.sender_ip != [0; 4]
            && ip_first < 224
    }
}

/// Read the supported ARP layout without treating its claims as authenticated bindings
#[must_use]
pub fn arp_packet(frame: &EthernetFrame<'_>) -> Option<ArpPacket> {
    if frame.field != FrameField::EtherType(0x0806) {
        return None;
    }
    ethernet_ipv4(frame.payload)
}

pub fn ethernet_ipv4(payload: &[u8]) -> Option<ArpPacket> {
    if read_u16(payload, 0) != Some(1)
        || read_u16(payload, 2) != Some(0x0800)
        || read_u8(payload, 4) != Some(6)
        || read_u8(payload, 5) != Some(4)
        || !matches!(read_u16(payload, 6), Some(1 | 2))
    {
        return None;
    }
    Some(ArpPacket {
        operation: read_u16(payload, 6)?,
        sender_mac: take(payload, 8, 6)?.try_into().ok()?,
        sender_ip: take(payload, 14, 4)?.try_into().ok()?,
        target_mac: take(payload, 18, 6)?.try_into().ok()?,
        target_ip: take(payload, 24, 4)?.try_into().ok()?,
    })
}

/// Check the ARP fixed header and variable hardware/protocol address section
pub fn fingerprint(payload: &[u8]) -> Fingerprint {
    if payload.len() < ARP_FIXED_HEADER_LEN {
        return Fingerprint::truncated(Protocol::Arp);
    }
    let Some(hardware_len) = read_u8(payload, 4).map(usize::from) else {
        return Fingerprint::truncated(Protocol::Arp);
    };
    let Some(protocol_len) = read_u8(payload, 5).map(usize::from) else {
        return Fingerprint::truncated(Protocol::Arp);
    };
    if hardware_len == 0 || protocol_len == 0 {
        return Fingerprint::malformed(Protocol::Arp);
    }

    let Some(address_bytes) = hardware_len
        .checked_add(protocol_len)
        .and_then(|length| length.checked_mul(2))
    else {
        return Fingerprint::malformed(Protocol::Arp);
    };
    let Some(required) = ARP_FIXED_HEADER_LEN.checked_add(address_bytes) else {
        return Fingerprint::malformed(Protocol::Arp);
    };
    if payload.len() < required {
        return Fingerprint::truncated(Protocol::Arp);
    }
    Fingerprint::observed(Protocol::Arp)
}
