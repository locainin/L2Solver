//! Bounded passive fingerprints for common Layer-2 and LAN control traffic
//!
//! This crate only examines an already decoded [`l2_core::EthernetFrame`]. It
//! borrows all packet data, keeps no observation state, and has no transmit or
//! interface authority. LLDP and STP remain owned by `l2-codecs`; their enum
//! values exist so a caller can merge inventories from both decoders.

#![forbid(unsafe_code)]

mod arp;
mod bytes;
mod dhcp;
mod dispatch;
pub mod dns;
mod eapol;
mod fragments;
mod hsrp;
mod identity;
mod igmp;
mod ip;
mod ipv4;
mod ipv6;
mod macsec;
mod mka;
mod mld;
mod model;
mod slow;
mod snap;
mod transport;
mod udp;
mod vrrp;

pub use arp::{ArpPacket, arp_packet};
pub use dispatch::{discover, fingerprint};
pub use fragments::{FragmentPacket, IpFamily, fragment_packet, fragment_transport};
pub use ip::{IpHeader, IpPacket, ip_header, ip_packet};
pub use model::{
    Discovery, Fingerprint, FingerprintStatus, IdentityRole, NetworkAddress, Protocol,
    ProtocolIdentity,
};
pub use transport::{TransportHeader, TransportPacket};

/// Maximum number of IPv6 extension headers traversed for one packet
///
/// The parser stops before inspecting a ninth extension header. This keeps a
/// hostile extension chain from turning one captured frame into unbounded work.
pub const MAX_IPV6_EXTENSION_HEADERS: usize = 8;
