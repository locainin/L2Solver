use super::{Result, invalid};
use crate::{evidence::SourceRange, investigation::BuildResult};
use l2_pcap::CollectionSummary;
use serde::Serialize;
use serde_json::Value;
use std::{error::Error, fmt};
use std::{net::IpAddr, str::FromStr};

/// Working memory controls do not impose a total capture or connection ceiling
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub cache_mib: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self { cache_mib: 64 }
    }
}

impl Options {
    pub(super) fn validate(self) -> Result<()> {
        if self.cache_mib == 0 {
            return Err(invalid("index cache budget must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct IngestReceipt {
    pub source_id: String,
    pub bytes: u64,
    pub packets: u64,
    pub transport_packets: u64,
    pub unsupported_transport_packets: u64,
    #[serde(serialize_with = "crate::capture_collection::serialize")]
    pub collection_summary: CollectionSummary,
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub sources: u64,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
    pub dns_exchanges: u64,
    pub dns_addresses: u64,
    pub unsupported_transport_packets: u64,
    #[serde(serialize_with = "crate::capture_collection::serialize")]
    pub collection_summary: CollectionSummary,
    pub sources_with_unknown_collection_quality: u64,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Source {
    pub source_id: String,
    pub label: String,
    pub bytes: u64,
    pub packets: u64,
    #[serde(serialize_with = "crate::capture_collection::serialize")]
    pub collection_summary: CollectionSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct Packet {
    pub source_id: String,
    pub number: u32,
    pub range: SourceRange,
    pub flow: Option<i64>,
}

/// A bidirectional tuple in one source/interface/VLAN scope, without session attribution
#[derive(Clone, Debug, Serialize)]
pub struct Flow {
    pub id: i64,
    pub source_id: String,
    /// Source-local interface and VLAN membership, without device attribution
    pub scope: Value,
    pub protocol: u8,
    pub endpoint_a: IpAddr,
    pub port_a: u16,
    pub endpoint_b: IpAddr,
    pub port_b: u16,
    pub first_packet: u32,
    pub last_packet: u32,
    pub packets: u64,
    /// Captured bytes across the flow's selected packet records
    pub frame_bytes: u64,
    pub payload_bytes: u64,
}

/// One bounded analysis of flows sharing a source, scope, and unordered IP pair
pub struct FlowCohortAnalysis {
    pub member_flows: Vec<Flow>,
    /// Source packet number and indexed flow ID for each selected packet
    pub packet_flow_ids: Vec<(u32, i64)>,
    /// More than one bounded chunk was needed, so relationships between chunks were not tested
    pub split: bool,
    pub result: BuildResult,
}

/// One bounded independent investigation of records after a retained flow prefix
pub struct FlowPageAnalysis {
    /// One-based order among supplementary pages for this flow
    pub page_index: u64,
    /// First original packet number in this page
    pub first_packet: u32,
    /// Last original packet number in this page
    pub last_packet: u32,
    pub selected_records: u64,
    pub retained_records: u64,
    pub omitted_records: u64,
    pub result: BuildResult,
}

/// Exact selected, retained, and omitted records visited after one flow prefix
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FlowPageCoverage {
    pub pages: u64,
    pub selected_records: u64,
    pub retained_records: u64,
    pub omitted_records: u64,
}

/// A flow record cannot be placed into any page under the supplied byte budget
#[derive(Debug, Eq, PartialEq)]
pub enum FlowPageError {
    /// One selected record exceeds the page's captured-byte budget
    RecordExceedsByteLimit {
        /// Original packet number
        packet: u32,
        /// Captured frame bytes
        frame_bytes: u64,
        /// Caller-supplied page byte limit
        byte_limit: usize,
    },
    /// A page could not consume the next indexed record
    NoProgress,
}

impl fmt::Display for FlowPageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordExceedsByteLimit {
                packet,
                frame_bytes,
                byte_limit,
            } => write!(
                formatter,
                "packet {packet} has {frame_bytes} captured bytes and cannot fit one flow page with a {byte_limit}-byte limit"
            ),
            Self::NoProgress => {
                formatter.write_str("flow page selection could not retain its next record")
            }
        }
    }
}

impl Error for FlowPageError {}

/// Coverage for the capture-wide unordered-IP-pair analysis pass
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FlowCohortCoverage {
    /// Pair groups containing more than one indexed flow
    pub multi_flow_groups: u64,
    pub complete_groups: u64,
    pub incomplete_groups: u64,
    pub split_groups: u64,
    pub analysis_chunks: u64,
    pub complete_chunks: u64,
    pub incomplete_chunks: u64,
    /// Flows analyzed again as part of an IP-pair group
    pub reanalyzed_flows: u64,
    /// Selected, retained, and omitted packet records in the separate pair pass
    pub selected_records: u64,
    pub retained_records: u64,
    pub omitted_records: u64,
    pub singleton_chunks_skipped: u64,
    pub oversized_flows_skipped: u64,
}

/// Exact co-occurrence with its independent packet witnesses, without a causal claim
#[derive(Debug, Serialize)]
pub struct Relationship {
    pub source_id: String,
    pub request_packet: Option<u32>,
    pub response_packet: u32,
    pub destination_packet: u32,
    pub destination_flow: i64,
    pub answer_address: IpAddr,
    pub answer_range: SourceRange,
    pub association: String,
    pub questions: serde_json::Value,
    pub answer_owner_wire: Vec<u8>,
}

/// Exact shared bytes grouped by their stated comparison rule
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedFactKind {
    /// One literal IPv4 or IPv6 address from a bounded packet header
    IpAddress,
    /// One DNS question name with only ASCII letters folded to lowercase
    DnsQuestion,
    /// SHA-256 of the complete captured packet bytes
    PacketBytes,
}

impl SharedFactKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::IpAddress => "ip_address",
            Self::DnsQuestion => "dns_question",
            Self::PacketBytes => "packet_bytes",
        }
    }
}

impl FromStr for SharedFactKind {
    type Err = Box<dyn std::error::Error>;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ip_address" => Ok(Self::IpAddress),
            "dns_question" => Ok(Self::DnsQuestion),
            "packet_bytes" => Ok(Self::PacketBytes),
            _ => Err(invalid("unknown shared fact kind")),
        }
    }
}

/// Reasons a shared value must not be treated as an independent identity claim
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedWarning {
    /// Private address literals can be reused on unrelated networks
    PrivateAddressAcrossSources,
    /// Capture-local scope values differ but cannot prove distinct networks
    MultipleCaptureLocalScopes,
    /// One or more matching packet observations lack decoded capture scope
    CaptureScopeUnavailable,
    /// Matching packet bytes may come from duplicate or correlated captures
    CaptureBytesMayBeCorrelated,
}

/// One exact value observed in at least two content-distinct capture sources
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SharedGroup {
    pub kind: SharedFactKind,
    #[serde(serialize_with = "serialize_hex")]
    pub key: Vec<u8>,
    pub source_count: u64,
    pub occurrence_count: u64,
    pub warnings: Vec<SharedWarning>,
}

/// Stable group-page cursor based on the last emitted comparison value
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SharedGroupCursor {
    pub kind: SharedFactKind,
    #[serde(serialize_with = "serialize_hex")]
    pub key: Vec<u8>,
}

/// Stable occurrence-page cursor using the source identity and packet number
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SharedOccurrenceCursor {
    pub source_id: String,
    pub packet: u32,
}

/// One packet supporting an exact shared fact, with its original captured bytes
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SharedOccurrence {
    pub kind: SharedFactKind,
    #[serde(serialize_with = "serialize_hex")]
    pub key: Vec<u8>,
    pub source_id: String,
    pub packet: u32,
    pub range: SourceRange,
    /// Capture-local interface and VLAN context when the link frame can be decoded
    pub scope: Option<Value>,
}

fn serialize_hex<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::Error;

    let encoded = bytes.iter().try_fold(String::new(), |mut output, byte| {
        use std::fmt::Write;
        write!(output, "{byte:02x}").map_err(S::Error::custom)?;
        Ok(output)
    })?;
    serializer.serialize_str(&encoded)
}
