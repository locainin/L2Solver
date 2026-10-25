use crate::{
    evidence::{EvidenceStatus, SourceRange},
    query::IpCidr,
};
use serde::Serialize;
use serde_json::Value;

pub(super) const MAX_BEHAVIOR_FINDINGS: usize = 4096;
const NO_MALICIOUSNESS_CLAIM: &str =
    "Observed patterns do not establish malicious intent or actor identity";
const CAPTURE_TIME_LIMITATION: &str = "Capture timestamp anomalies describe capture metadata only; they do not establish endpoint timestamp changes or timestomping";

/// Behavior categories derived from exact retained packet or graph facts
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorKind {
    /// Repeated packets moving from a configured internal network outward
    OutboundPacketSequence,
    /// Repeated packets moving toward a configured internal network
    InboundPacketSequence,
    /// Initial TCP SYN packets reach several distinct destinations
    TcpSynFanOut,
    /// Initial TCP SYN packets target several services on one destination
    TcpSynServiceSweep,
    /// Adjacent same-flow capture ticks are measured against one baseline
    RegularConnectionIntervals,
    /// Same-clock capture ticks move backward, repeat, or jump past a bound
    CaptureClockAnomaly,
    /// Adjacent packet timestamps use different exact clock definitions
    TimestampClockMismatch,
    /// Existing canonical ARP claim-change evidence is summarized
    ArpClaimChange,
    /// Existing canonical DNS answer-to-destination evidence is summarized
    DnsAnswerDestinationChain,
    /// A bounded SMB2 `FileBasicInformation` `SET_INFO` request candidate
    Smb2FileBasicInfoSetRequest,
    /// Bytes that resemble a NetBIOS-framed SMB input but cannot be fully parsed
    Smb2UnparsedRange,
}

/// Caller-defined network boundary and exact forward-gap threshold
#[derive(Clone, Debug, Default)]
pub struct BehaviorConfig {
    /// Networks treated as internal for directional summaries
    pub internal_networks: Vec<IpCidr>,
    /// A same-clock tick delta strictly greater than this value is reported
    pub large_forward_gap_ticks: Option<u64>,
}

/// One behavior summary with the exact retained graph or packet references
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BehaviorFinding {
    /// Stable behavior category
    pub kind: BehaviorKind,
    /// Evidence state for the stated observation or candidate
    pub status: EvidenceStatus,
    /// Existing evidence node identifiers, when this summarizes graph evidence
    pub node_ids: Vec<u64>,
    /// Original capture record numbers, without renumbering scoped windows
    pub packet_numbers: Vec<u64>,
    /// Exact source byte ranges already present in the case graph
    pub source_ranges: Vec<SourceRange>,
    /// Bounded literal details and counterexamples
    pub details: Value,
}

/// Behavior findings and explicit limits on the bounded analysis
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BehaviorReport {
    /// Findings retained in stable packet/node order
    pub findings: Vec<BehaviorFinding>,
    /// True when source collection is complete and no findings were omitted
    pub complete: bool,
    /// Exact findings omitted by the bounded in-memory adapter
    pub omitted_findings: usize,
    /// Analysis limits and omissions
    pub limitations: Vec<String>,
}

impl Default for BehaviorReport {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            complete: true,
            omitted_findings: 0,
            limitations: default_limitations(),
        }
    }
}

pub(super) fn default_limitations() -> Vec<String> {
    vec![
        NO_MALICIOUSNESS_CLAIM.to_owned(),
        CAPTURE_TIME_LIMITATION.to_owned(),
    ]
}
