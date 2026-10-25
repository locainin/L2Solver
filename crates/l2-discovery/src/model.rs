use core::fmt;

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A protocol family that can be represented in a unified passive inventory
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Protocol {
    #[serde(rename = "eapol")]
    Eapol,
    #[serde(rename = "lacp")]
    Lacp,
    #[serde(rename = "macsec")]
    Macsec,
    #[serde(rename = "mka")]
    Mka,
    #[serde(rename = "arp")]
    Arp,
    #[serde(rename = "dhcp")]
    Dhcp,
    #[serde(rename = "hsrp")]
    Hsrp,
    #[serde(rename = "vrrp")]
    Vrrp,
    #[serde(rename = "ipv6_ra")]
    Ipv6Ra,
    #[serde(rename = "ipv6_nd")]
    Ipv6Nd,
    #[serde(rename = "mld")]
    Mld,
    #[serde(rename = "igmp")]
    Igmp,
    #[serde(rename = "mdns")]
    Mdns,
    #[serde(rename = "ssdp")]
    Ssdp,
    #[serde(rename = "netbios")]
    Netbios,
    #[serde(rename = "dhcpv6")]
    Dhcpv6,
    #[serde(rename = "cdp")]
    Cdp,
    #[serde(rename = "dtp")]
    Dtp,
    #[serde(rename = "vtp")]
    Vtp,
    #[serde(rename = "pagp")]
    Pagp,
    #[serde(rename = "pvst_plus")]
    PvstPlus,
    #[serde(rename = "cisco_snap")]
    CiscoSnap,
    #[serde(rename = "lldp")]
    Lldp,
    #[serde(rename = "stp")]
    Stp,
}

impl Protocol {
    /// Stable operator-facing protocol name
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eapol => "EAPOL",
            Self::Lacp => "LACP",
            Self::Macsec => "MACsec",
            Self::Mka => "MKA",
            Self::Arp => "ARP",
            Self::Dhcp => "DHCP",
            Self::Hsrp => "HSRP",
            Self::Vrrp => "VRRP",
            Self::Ipv6Ra => "IPv6 RA",
            Self::Ipv6Nd => "IPv6 ND",
            Self::Mld => "MLD",
            Self::Igmp => "IGMP",
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP",
            Self::Netbios => "NetBIOS",
            Self::Dhcpv6 => "DHCPv6",
            Self::Cdp => "CDP",
            Self::Dtp => "DTP",
            Self::Vtp => "VTP",
            Self::Pagp => "PAgP",
            Self::PvstPlus => "PVST+",
            Self::CiscoSnap => "Cisco SNAP",
            Self::Lldp => "LLDP",
            Self::Stp => "STP",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Structural result for a protocol whose identifying framing was present
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum FingerprintStatus {
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "malformed")]
    Malformed,
    #[serde(rename = "truncated")]
    Truncated,
    #[serde(rename = "unsupported")]
    Unsupported,
}

impl FingerprintStatus {
    /// Stable operator-facing status name
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Malformed => "malformed",
            Self::Truncated => "truncated",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for FingerprintStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stateless result from inspecting one decoded Ethernet frame
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Fingerprint {
    pub protocol: Protocol,
    pub status: FingerprintStatus,
}

/// Network address retained from a validated protocol envelope
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "family", content = "octets", rename_all = "snake_case")]
pub enum NetworkAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(octets) => Ipv4Addr::from(*octets).fmt(formatter),
            Self::Ipv6(octets) => Ipv6Addr::from(*octets).fmt(formatter),
        }
    }
}

/// Conservative role inferred directly from one validated protocol envelope
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    AccessControlParticipant,
    AddressClaim,
    AddressProbe,
    AggregationParticipant,
    ControlPlaneParticipant,
    DhcpClient,
    DhcpServer,
    Dhcpv6Participant,
    FirstHopRouter,
    Ipv6Neighbor,
    Ipv6Router,
    LinkSecurityParticipant,
    MulticastParticipant,
}

impl IdentityRole {
    /// Stable operator-facing role label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessControlParticipant => "access-control participant",
            Self::AddressClaim => "address claim",
            Self::AddressProbe => "address probe",
            Self::AggregationParticipant => "aggregation participant",
            Self::ControlPlaneParticipant => "control-plane participant",
            Self::DhcpClient => "DHCP client",
            Self::DhcpServer => "DHCP server",
            Self::Dhcpv6Participant => "DHCPv6 participant",
            Self::FirstHopRouter => "first-hop router participant",
            Self::Ipv6Neighbor => "IPv6 neighbor-discovery participant",
            Self::Ipv6Router => "IPv6 router",
            Self::LinkSecurityParticipant => "link-security participant",
            Self::MulticastParticipant => "multicast participant",
        }
    }
}

impl fmt::Display for IdentityRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded identity material associated with one observed protocol frame
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProtocolIdentity {
    pub role: IdentityRole,
    /// Ethernet source that actually carried the frame
    pub source_mac: [u8; 6],
    /// Protocol-claimed hardware address when distinct evidence exists
    pub claimed_mac: Option<[u8; 6]>,
    /// Protocol or IP envelope address claimed by the source
    pub address: Option<NetworkAddress>,
}

/// Fingerprint plus identity facts that are safe to retain from that status
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Discovery {
    pub fingerprint: Fingerprint,
    pub identity: Option<ProtocolIdentity>,
}

impl Fingerprint {
    pub(super) const fn observed(protocol: Protocol) -> Self {
        Self {
            protocol,
            status: FingerprintStatus::Observed,
        }
    }

    pub(super) const fn malformed(protocol: Protocol) -> Self {
        Self {
            protocol,
            status: FingerprintStatus::Malformed,
        }
    }

    pub(super) const fn truncated(protocol: Protocol) -> Self {
        Self {
            protocol,
            status: FingerprintStatus::Truncated,
        }
    }

    pub(super) const fn unsupported(protocol: Protocol) -> Self {
        Self {
            protocol,
            status: FingerprintStatus::Unsupported,
        }
    }
}
