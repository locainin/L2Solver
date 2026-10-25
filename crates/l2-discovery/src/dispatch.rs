use l2_core::{EthernetFrame, FrameField};

use crate::{Discovery, Fingerprint, arp, eapol, identity, ipv4, ipv6, macsec, slow, snap};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_EAPOL: u16 = 0x888e;
const ETHERTYPE_SLOW: u16 = 0x8809;
const ETHERTYPE_MACSEC: u16 = 0x88e5;

/// Fingerprint one decoded Ethernet frame without retaining packet state
#[must_use]
pub fn fingerprint(frame: &EthernetFrame<'_>) -> Option<Fingerprint> {
    match frame.field {
        FrameField::EtherType(ETHERTYPE_EAPOL) => Some(eapol::fingerprint(frame.payload)),
        FrameField::EtherType(ETHERTYPE_SLOW) => slow::fingerprint(frame.payload),
        FrameField::EtherType(ETHERTYPE_MACSEC) => Some(macsec::fingerprint(frame.payload)),
        FrameField::EtherType(ETHERTYPE_ARP) => Some(arp::fingerprint(frame.payload)),
        FrameField::EtherType(ETHERTYPE_IPV4) => ipv4::fingerprint(frame.payload),
        FrameField::EtherType(ETHERTYPE_IPV6) => ipv6::fingerprint(frame.payload),
        // Cisco control protocols use 802.2 LLC/SNAP inside a length frame
        FrameField::Length(_) => snap::fingerprint(frame.payload),
        // LLDP and STP are parsed by l2-codecs and deliberately stay there
        FrameField::EtherType(_) => None,
    }
}

/// Discover a protocol fingerprint and identity facts valid for its status
#[must_use]
pub fn discover(frame: &EthernetFrame<'_>) -> Option<Discovery> {
    let fingerprint = fingerprint(frame)?;
    Some(Discovery {
        fingerprint,
        identity: identity::extract(frame, fingerprint),
    })
}
