//! Serialized observations retain capture-source scope and evidence references

use l2_discovery::{FingerprintStatus, IdentityRole, NetworkAddress, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{CheckPlan, CoverageEntry, CoverageMetric, Exposure, NetworkModel, PortRoleInference};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Potential,
    Inconclusive,
    NotApplicable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub check_id: String,
    pub verdict: Verdict,
    pub severity: Severity,
    pub title: String,
    pub expected: String,
    pub observed: String,
    pub evidence_packets: Vec<u64>,
    pub source_interfaces: Vec<String>,
    pub remediation: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VlanObservation {
    pub tags: Vec<(u16, u16)>,
    pub packet: u64,
}

/// A standards-valid VLAN identifier that cannot represent priority tags or reserved VID 4095
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NonZeroVid(u16);
impl NonZeroVid {
    /// Construct an ordinary VLAN identifier in the inclusive range 1 through 4094
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if value > 0 && value < 4095 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the ordinary VLAN identifier
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Meaning of the twelve-bit VID field without treating priority tags as VLAN membership
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Vid {
    PriorityTagged,
    Vlan(NonZeroVid),
    Reserved,
}

impl VlanObservation {
    /// VID meanings in captured outer-to-inner order
    pub fn vids(&self) -> impl Iterator<Item = Vid> + '_ {
        self.tags.iter().map(|(_, tci)| match tci & 0x0fff {
            0 => Vid::PriorityTagged,
            4095 => Vid::Reserved,
            // Masking above makes every remaining value a valid ordinary VID
            value => Vid::Vlan(NonZeroVid(value)),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Neighbor {
    pub chassis_id: Vec<u8>,
    pub port_id: Vec<u8>,
    pub system_name: Vec<u8>,
    pub packet: u64,
}

/// The complete bridge identifier carried by an STP or RSTP BPDU
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeIdentity {
    /// The four priority bits retained in their wire position
    pub priority: u16,
    /// The twelve-bit system identifier extension
    pub system_id_extension: u16,
    /// The bridge MAC address in canonical colon-separated form
    pub mac: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StpObservation {
    pub root: BridgeIdentity,
    pub version: String,
    pub packet: u64,
    pub frames: u64,
}

/// One bounded passive protocol fingerprint and its first supporting packet
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolObservation {
    pub protocol: Protocol,
    pub status: FingerprintStatus,
    pub frames: u64,
    pub packet: u64,
}

/// One de-duplicated protocol identity claim scoped to a capture interface
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolIdentityObservation {
    pub protocol: Protocol,
    pub role: IdentityRole,
    /// Ethernet source that carried the observed claim
    pub source_mac: String,
    /// Protocol-claimed hardware address when the protocol carries one
    pub claimed_mac: Option<String>,
    pub address: Option<NetworkAddress>,
    /// Captured tag stack that scopes this identity claim
    pub vlan_tags: Vec<(u16, u16)>,
    /// Raw auxiliary (TPID, TCI) kept distinct from the captured tag stack
    pub vlan_aux: Option<(u16, u16)>,
    pub frames: u64,
    pub packet: u64,
}

#[derive(Debug, Serialize)]
pub struct InterfaceObservation {
    pub section: u32,
    pub index: u32,
    pub frames: u64,
    pub macs: Vec<String>,
    pub vlans: Vec<VlanObservation>,
    pub untagged_packet: Option<u64>,
    pub neighbors: Vec<Neighbor>,
    pub protocols: Vec<ProtocolObservation>,
    pub identities: Vec<ProtocolIdentityObservation>,
    pub stp_frames: u64,
    pub stp_packet: Option<u64>,
    pub stp: Vec<StpObservation>,
}

#[derive(Debug, Default, Serialize)]
pub struct Quality {
    pub frames: u64,
    pub malformed: u64,
    pub invalid: u64,
    pub truncated: u64,
    pub dropped: u64,
    pub unsupported_stp: u64,
    pub unsupported_fingerprints: u64,
    pub unsupported_link_types: u64,
    pub incomplete: bool,
}

/// One bounded assessment resource whose configured ceiling was reached
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLimit {
    EvidenceReferences,
    EmbeddedPackets,
    EmbeddedBytes,
    MacFacts,
    VlanContexts,
    Neighbors,
    ProtocolIdentities,
    StpTransitions,
    ForensicRecords,
    DnsMessages,
}

/// Resource ceilings reached while retaining a usable partial assessment
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResourceLimitStatus {
    reached: BTreeSet<ResourceLimit>,
}
impl ResourceLimitStatus {
    /// Mark one resource ceiling as reached
    pub fn mark(&mut self, resource: ResourceLimit) {
        self.reached.insert(resource);
    }

    /// Whether one resource ceiling was reached
    #[must_use]
    pub fn is_reached(&self, resource: ResourceLimit) -> bool {
        self.reached.contains(&resource)
    }

    /// Return all reached ceilings in deterministic order
    #[must_use]
    pub const fn reached(&self) -> &BTreeSet<ResourceLimit> {
        &self.reached
    }

    /// Whether an authoritative inventory or evidence reference was omitted
    #[must_use]
    pub fn collection_incomplete(&self) -> bool {
        self.reached.iter().any(|resource| {
            matches!(
                resource,
                ResourceLimit::EvidenceReferences
                    | ResourceLimit::MacFacts
                    | ResourceLimit::VlanContexts
                    | ResourceLimit::Neighbors
                    | ResourceLimit::ProtocolIdentities
                    | ResourceLimit::StpTransitions
                    | ResourceLimit::ForensicRecords
                    | ResourceLimit::DnsMessages
            )
        })
    }
}
impl Quality {
    /// Whether the collected sample has no reported integrity or loss indicators
    #[must_use]
    pub const fn clean(&self) -> bool {
        self.unsupported_stp == 0
            && self.unsupported_fingerprints == 0
            && self.unsupported_link_types == 0
            && self.malformed == 0
            && self.invalid == 0
            && self.truncated == 0
            && self.dropped == 0
            && !self.incomplete
    }
}

/// Stable identity and capture provenance for a packet referenced by inventory or findings
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceRef {
    pub sequence: u64,
    pub section: u32,
    pub interface: u32,
    pub captured_len: usize,
    pub original_len: u32,
    pub sha256: String,
    pub locator: EvidenceLocator,
    pub timestamp_ticks: Option<u64>,
    pub timestamp_radix: Option<u8>,
    pub timestamp_exponent: Option<u8>,
    pub timestamp_offset_seconds: Option<i64>,
    pub timestamp_source: Option<String>,
    pub direction: String,
    pub fcs: String,
    pub vlan_aux: Option<(u16, u16)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_interface: Option<LinuxInterfaceEvidence>,
}

/// Linux kernel objects that supplied one live evidence packet
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LinuxInterfaceEvidence {
    /// Device number containing the network namespace object
    pub namespace_device: u64,
    /// Inode number of the network namespace object
    pub namespace_inode: u64,
    /// Device number containing the retained sysfs interface object
    pub interface_device: u64,
    /// Inode number of the retained sysfs interface object
    pub interface_inode: u64,
    /// Kernel interface index bound to the capture socket
    pub ifindex: u32,
}

/// Logical source location for bounded evidence rereads
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceLocator {
    ClassicPcap {
        record_offset: u64,
        data_offset: u64,
    },
    PcapNg {
        block_offset: u64,
        data_offset: u64,
        block_type: u32,
    },
    Unavailable,
}

/// Bounded raw bytes embedded for immediate review
#[derive(Debug, Serialize)]
pub struct PacketEvidence {
    pub sequence: u64,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool_version: String,
    pub assessment_profile: crate::AssessmentProfile,
    pub policy: crate::Policy,
    pub interfaces: Vec<InterfaceObservation>,
    pub network_model: NetworkModel,
    pub forensics: crate::ForensicReport,
    pub port_roles: Vec<PortRoleInference>,
    pub exposures: Vec<Exposure>,
    pub findings: Vec<Finding>,
    pub coverage: Vec<CoverageEntry>,
    pub coverage_summary: Vec<CoverageMetric>,
    pub plan: CheckPlan,
    pub quality: Quality,
    pub resource_limits: ResourceLimitStatus,
    pub evidence_refs: Vec<EvidenceRef>,
    pub evidence: Vec<PacketEvidence>,
}
impl Report {
    /// Whether capture and resource accounting support a complete passive assessment
    #[must_use]
    pub fn collection_complete(&self) -> bool {
        self.quality.frames != 0
            && self.quality.clean()
            && !self.resource_limits.collection_incomplete()
            && self.forensics.ip_frames_seen == self.forensics.ip_frames_parsed
            && self.forensics.dns_candidates_seen == self.forensics.dns_messages_parsed
    }
}
