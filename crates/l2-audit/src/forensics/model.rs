use l2_capture::{CaptureMetadata, InterfaceId};
use l2_core::EthernetFrame;
use l2_discovery::NetworkAddress;
use serde::Serialize;

/// Capture-local scope, retaining auxiliary VLAN data separately from in-band tags
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ForensicScope {
    pub section: u32,
    pub interface: u32,
    /// Outer-to-inner (TPID, VID) pairs; PCP and DEI do not change membership keys
    /// VID zero remains separate because the native VLAN cannot be inferred
    pub vlan_ids: Vec<(u16, u16)>,
    /// A separate (TPID, VID) source claim, never merged into the captured tag stack
    pub vlan_aux: Option<(u16, u16)>,
}

impl ForensicScope {
    /// Derive capture-local membership without treating priority bits as VLAN identity
    #[must_use]
    pub fn new(metadata: &CaptureMetadata, frame: &EthernetFrame<'_>) -> Self {
        Self::from_parts(
            metadata.interface(),
            frame.vlan_tags.iter().map(|tag| (tag.tpid, tag.tci)),
            metadata.vlan().map(|tag| (tag.tpid, tag.tci)),
        )
    }

    pub(crate) fn from_parts(
        source: InterfaceId,
        tags: impl Iterator<Item = (u16, u16)>,
        auxiliary: Option<(u16, u16)>,
    ) -> Self {
        Self {
            section: source.section,
            interface: source.index,
            vlan_ids: tags.map(|(tpid, tci)| (tpid, tci & 0x0fff)).collect(),
            vlan_aux: auxiliary.map(|(tpid, tci)| (tpid, tci & 0x0fff)),
        }
    }

    pub(crate) fn supports_binding_comparison(&self) -> bool {
        // Reserved VID 4095 cannot identify a valid VLAN membership
        !self
            .vlan_ids
            .iter()
            .chain(self.vlan_aux.iter())
            .any(|(_, vid)| *vid == 4095)
    }
}

/// Directional header co-occurrence at a capture point, not device ownership or delivery
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IpCommunication {
    pub scope: ForensicScope,
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub source_mac: String,
    pub destination_mac: String,
    pub protocol: u8,
    pub ports: Option<(u16, u16)>,
    pub fragmented: bool,
    pub frames: u64,
    /// First supporting record; repeated frames contribute counts rather than new identities
    pub packet: u64,
}

/// ARP wire fields, including probes and Ethernet/ARP source differences
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArpObservation {
    pub scope: ForensicScope,
    pub source_mac: String,
    pub operation: u16,
    pub sender_mac: String,
    pub sender_address: NetworkAddress,
    pub target_mac: String,
    pub target_address: NetworkAddress,
    pub frames: u64,
    pub packet: u64,
}

/// Two different ARP sender-MAC claims in capture record order
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArpBindingChange {
    pub scope: ForensicScope,
    pub address: NetworkAddress,
    pub previous_mac: String,
    pub claimed_mac: String,
    pub previous_packet: u64,
    pub packet: u64,
    /// First later record with matching IP and Ethernet destinations before a new claim
    /// This records a sequence correlation, not a cache update or causal relationship
    pub followup_packet: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrailingProtocol {
    Ipv4,
    Ipv6,
    Udp,
    Arp,
    Ieee8023,
}

/// Nonzero bytes after an explicit length boundary
/// Ranges outside IP require source-declared absent FCS; internal UDP ranges do not
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrailingData {
    pub scope: ForensicScope,
    pub protocol: TrailingProtocol,
    pub packet: u64,
    /// Zero-based captured-frame byte offset, with the following length defining the range
    pub offset: usize,
    pub length: usize,
    pub nonzero_bytes: usize,
}

/// Bounded literal observations, kept separate from policy failures and severity scores
#[derive(Debug, Serialize)]
pub struct ForensicReport {
    pub communications: Vec<IpCommunication>,
    pub arp_observations: Vec<ArpObservation>,
    pub arp_changes: Vec<ArpBindingChange>,
    pub trailing_data: Vec<TrailingData>,
    pub dns_observations: Vec<super::DnsObservation>,
    pub dns_matches: Vec<super::DnsResponseMatch>,
    pub dns_address_uses: Vec<super::DnsAddressUse>,
    /// Complete unfragmented UDP payloads selected by source or destination port 53
    pub dns_candidates_seen: u64,
    pub dns_messages_parsed: u64,
    /// Complete decoded Ethernet frames carrying an IPv4 or IPv6 `EtherType`
    pub ip_frames_seen: u64,
    /// Frames whose complete IP length and supported extension boundaries were read
    pub ip_frames_parsed: u64,
    /// Explicit trailing ranges left unchecked because FCS was not declared absent
    pub trailer_frames_unchecked: u64,
    pub limitations: &'static [&'static str],
}

pub(super) const LIMITATIONS: &[&str] = &[
    "Evidence describes capture record order and does not establish ownership, delivery, cause, or intent",
    "IP and Ethernet addresses are header claims at the capture point; routing, proxies, and spoofed fields can explain pairings",
    "IP and transport checksums, DNS authenticity, and endpoint processing are not validated",
    "Nonzero bytes after a declared length may be ordinary padding; FCS absence is a source declaration",
    "Missing, dropped, unsupported, or omitted records cannot establish absence of an event",
    "DNS matches describe retained outstanding queries; collisions stay ambiguous and unique matches consume their query",
    "DNS address uses describe later destination co-occurrence; TTL validity, resolver caching, application use, and causality are unresolved",
];
