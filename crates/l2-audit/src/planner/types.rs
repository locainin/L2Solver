//! Public planner data types and their stable serialization shape

use crate::assessment::CoverageStatus;
use l2_discovery::Protocol;
use serde::Serialize;
use std::{fmt, time::Duration};

/// How aggressively the planner promotes active checks without passive evidence
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentProfile {
    /// Recommend active checks only after their protocol is observed
    #[default]
    Opportunistic,
    /// Combine observations with policy and inferred port roles
    Standard,
    /// Plan every check relevant to the available capture scope
    Full,
}

impl AssessmentProfile {
    /// Return the stable operator-facing profile name
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opportunistic => "opportunistic",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

/// Semantic role of one prerequisite in applicability decisions
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementKind {
    Capability,
    Policy,
    Applicability,
    DiscoveryHint,
}

/// A local facility needed before a check can be run
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// A source can receive and decode passive traffic
    PassiveCapture,
    /// A controlled endpoint can transmit probes
    ActiveTransmit,
    /// A controlled endpoint can complete an authentication exchange
    AuthenticatedEndpoint,
    /// A probe can exercise protocol state and observe the result
    StatefulProbe,
    /// A probe is explicitly authorized for disruptive behavior
    DisruptiveProbe,
}

/// The operational risk tier assigned to a check
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Passive,
    SafeActive,
    Stateful,
    Disruptive,
}

/// Security domain used to summarize assessment coverage
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    AccessControl,
    Aggregation,
    ArpProtection,
    BroadcastHygiene,
    DhcpProtection,
    FirstHopRedundancy,
    Ipv6Protection,
    LinkSecurity,
    Multicast,
    NeighborDiscovery,
    Resilience,
    Segmentation,
    SpanningTree,
    Trunking,
    Vlan,
}

impl CheckCategory {
    /// Stable operator-facing category name
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessControl => "Access control",
            Self::Aggregation => "Link aggregation",
            Self::ArpProtection => "ARP protections",
            Self::BroadcastHygiene => "Broadcast hygiene",
            Self::DhcpProtection => "DHCP protections",
            Self::FirstHopRedundancy => "First-hop redundancy",
            Self::Ipv6Protection => "IPv6 protections",
            Self::LinkSecurity => "Link security",
            Self::Multicast => "Multicast controls",
            Self::NeighborDiscovery => "Neighbor discovery",
            Self::Resilience => "Resource controls",
            Self::Segmentation => "Segmentation",
            Self::SpanningTree => "Spanning tree",
            Self::Trunking => "Trunking",
            Self::Vlan => "VLAN policy",
        }
    }
}

impl fmt::Display for CheckCategory {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(self.as_str())
    }
}

/// Cleanup required after a check has finished
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupPolicy {
    None,
    BestEffort,
    Required,
    Verified,
}

/// A field or observation required by a check
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Requirement {
    /// A protocol fingerprint must have been observed
    Observed(Protocol),
    /// A protocol observation increases relevance but is not always required
    DiscoveryHint(Protocol),
    /// A policy field must have been supplied
    Policy(PolicyRequirement),
    /// A local capability must be available
    Capability(Capability),
    /// At least this many controlled agents must be present
    AgentsAtLeast(usize),
    /// A capture must exist for the check's scope
    Capture,
    /// A root-bearing STP advertisement must be available for comparison
    StpRootAdvertisement,
}

impl Requirement {
    /// Return the planner semantics carried by this requirement
    #[must_use]
    pub const fn kind(self) -> RequirementKind {
        match self {
            Self::Capability(_) | Self::AgentsAtLeast(_) => RequirementKind::Capability,
            Self::Policy(_) => RequirementKind::Policy,
            Self::DiscoveryHint(_) => RequirementKind::DiscoveryHint,
            Self::Observed(_) | Self::Capture | Self::StpRootAdvertisement => {
                RequirementKind::Applicability
            }
        }
    }
}

/// Policy fields that make a passive assertion meaningful
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRequirement {
    AllowedVlans,
    Dot1xRequired,
    LldpVisibility,
    PriorityTaggedFrames,
    StpEndpointVisibility,
    UntaggedFrames,
    MaximumVlanDepth,
    ExpectedStpRoot,
    ProtocolPolicy,
    SegmentationPaths,
}

impl PolicyRequirement {
    /// Return the stable bit used while aggregating policy coverage
    pub(super) const fn mask(self) -> u16 {
        match self {
            Self::AllowedVlans => 1,
            Self::Dot1xRequired => 1 << 1,
            Self::LldpVisibility => 1 << 2,
            Self::PriorityTaggedFrames => 1 << 3,
            Self::StpEndpointVisibility => 1 << 4,
            Self::UntaggedFrames => 1 << 5,
            Self::MaximumVlanDepth => 1 << 6,
            Self::ExpectedStpRoot => 1 << 7,
            Self::ProtocolPolicy => 1 << 8,
            Self::SegmentationPaths => 1 << 9,
        }
    }
}

/// A stable descriptor in the bounded check catalog
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CheckDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub category: CheckCategory,
    pub prerequisites: &'static [Requirement],
    pub risk: RiskClass,
    pub required_agents: usize,
    pub packet_budget: u64,
    pub byte_budget: u64,
    #[serde(serialize_with = "serialize_duration_millis")]
    pub duration_budget: Duration,
    pub cleanup: CleanupPolicy,
}

/// A catalog check with its passive applicability and current coverage
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanEntry {
    pub check_id: String,
    pub title: String,
    pub category: CheckCategory,
    pub risk: RiskClass,
    pub required_agents: usize,
    pub packet_budget: u64,
    pub byte_budget: u64,
    #[serde(serialize_with = "serialize_duration_millis")]
    pub duration_budget: Duration,
    pub cleanup: CleanupPolicy,
    /// Applicability is based on observed scope and explicit policy
    pub applicable: bool,
    pub coverage: CoverageStatus,
    pub reason: String,
    pub missing_requirements: Vec<String>,
    /// Safe active and stateful checks remain recommendations until execution exists
    pub recommendation: bool,
}

/// A next check selected from an observed prerequisite
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Recommendation {
    pub check_id: String,
    pub title: String,
    pub risk: RiskClass,
    pub reason: String,
    pub required_agents: usize,
}

/// A complete deterministic plan for the current survey surface
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CheckPlan {
    pub entries: Vec<PlanEntry>,
    pub recommendations: Vec<Recommendation>,
}

impl CheckPlan {
    /// Find one catalog entry by its stable identifier
    #[must_use]
    pub fn entry(&self, check_id: &str) -> Option<&PlanEntry> {
        self.entries.iter().find(|entry| entry.check_id == check_id)
    }
}

fn serialize_duration_millis<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u128(duration.as_millis())
}
