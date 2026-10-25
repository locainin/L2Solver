use crate::tcp_range::{RangeReport, Span, SpanStatus};
use l2_audit::ForensicScope;
use l2_discovery::{IpFamily, NetworkAddress};
use serde::{Deserialize, Serialize};

/// Record selection mode, without claiming the source capture is complete
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputSelection {
    /// Consecutive record numbers were supplied from the configured starting record
    ConsecutiveRecords,
    /// A subset of source records was supplied in strictly increasing order
    SelectedRecords,
}

/// Checked retention budgets for one reconstruction
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub frames: u64,
    pub bytes: usize,
    pub units: usize,
    /// Candidate TCP episodes retained after packet-level parsing
    pub sessions: usize,
    /// Distinct fragment grouping keys retained across this capture
    pub datagrams: usize,
    /// Total byte positions visited during range assembly, including missing positions
    pub range_bytes: usize,
    /// Maximum source observations retained in one TCP or fragment range
    pub range_observations: usize,
    /// Maximum copied source bytes retained in one TCP or fragment range
    pub range_retained_bytes: usize,
}

/// Retention ceiling that stopped selected record collection at its next source record
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordRetentionLimit {
    Frames,
    Bytes,
    Units,
}

/// Whether every selected source record was retained for reconstruction
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordRetentionStatus {
    Complete,
    ResourceTruncatedPrefix,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frames: 65_536,
            bytes: 16 * 1024 * 1024,
            units: 16_384,
            sessions: 2_048,
            datagrams: 1_024,
            range_bytes: 16 * 1024 * 1024,
            range_observations: crate::tcp_range::MAX_OBSERVATIONS,
            range_retained_bytes: crate::tcp_range::MAX_RETAINED_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Endpoint {
    pub address: NetworkAddress,
    pub port: u16,
}

/// A retained input byte range and its offset in the reconstructed object
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Origin {
    pub packet: u32,
    pub frame_offset: usize,
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub length: usize,
    pub observed_bytes: usize,
    pub missing_bytes: usize,
    pub conflicting_bytes: usize,
    pub omitted_bytes: usize,
    pub omitted_observations: u64,
    pub spans: Vec<Span>,
}
impl Coverage {
    #[must_use]
    pub const fn unique(&self) -> bool {
        self.missing_bytes == 0 && self.conflicting_bytes == 0 && self.omitted_observations == 0
    }
    pub(crate) fn from_range(range: RangeReport) -> Self {
        Self {
            length: range.length,
            observed_bytes: range.observed_bytes,
            missing_bytes: range.missing_bytes,
            conflicting_bytes: range.conflicting_bytes,
            omitted_bytes: range.omitted_bytes,
            omitted_observations: range.omitted_observations,
            spans: range.spans,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Datagram {
    pub scope: ForensicScope,
    pub family: IpFamily,
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub identification: u32,
    pub protocols: Vec<u8>,
    pub final_lengths: Vec<usize>,
    /// Unique captured coverage and consistent lengths, without generation attribution
    pub complete: bool,
    /// Reused identification fields cannot distinguish datagram generations from this capture alone
    pub identity_ambiguous: bool,
    pub metadata_consistent: bool,
    pub coverage: Option<Coverage>,
    pub origins: Vec<Origin>,
}

#[derive(Debug, Serialize)]
pub struct Stream {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub start_sequence: u32,
    /// At least one supported SYN supplies the start of this directional byte space
    pub start_known: bool,
    /// Consistent FIN position matches the last retained data position
    pub end_observed: bool,
    pub sequence_ambiguous: bool,
    pub outside_segments: usize,
    pub coverage: Option<Coverage>,
    pub origins: Vec<Origin>,
    pub packets: Vec<u32>,
    /// Indices of fragment candidates that supply transport headers or data
    pub fragment_candidates: Vec<usize>,
}

pub struct ByteRun<'a> {
    pub offset: usize,
    pub bytes: &'a [u8],
}
impl Stream {
    /// Borrow contiguous unique values; gaps, overlaps, and omitted observations split runs
    #[must_use]
    pub fn runs(&self) -> Vec<ByteRun<'_>> {
        self.coverage
            .as_ref()
            .into_iter()
            .flat_map(|coverage| &coverage.spans)
            .filter(|span| span.status == SpanStatus::Observed && !span.omitted_observation)
            .filter_map(|span| {
                span.bytes.as_deref().map(|bytes| ByteRun {
                    offset: span.offset,
                    bytes,
                })
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
pub struct TcpSession {
    pub scope: ForensicScope,
    pub endpoints: [Endpoint; 2],
    pub first_packet: u32,
    /// Unique source of an observed SYN with ACK clear, when present
    pub initiator: Option<Endpoint>,
    pub generation_ambiguous: bool,
    pub reset_packets: Vec<u32>,
    pub handshake: super::HandshakeAssessment,
    pub directions: [Stream; 2],
}

#[derive(Debug, Serialize)]
pub struct UdpMessage {
    pub scope: ForensicScope,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub packet: u32,
    pub bytes: Vec<u8>,
    pub origins: Vec<Origin>,
    pub trailing_bytes: Vec<u8>,
    pub trailing_origins: Vec<Origin>,
    /// Index into the report's fragment candidates, including header provenance
    pub fragment_candidate: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ReconstructionReport {
    /// Number of records supplied to the reconstructor
    pub frames: u64,
    /// Exact budgets used to retain these records and ranges
    pub limits: Limits,
    /// How the input record numbers were supplied, when any records were observed
    pub input_selection: Option<InputSelection>,
    pub omitted_frames: u64,
    pub unsupported_frames: u64,
    /// All configured budgets fit; this does not establish a complete source capture
    pub complete: bool,
    pub omitted_fragments: usize,
    /// TCP transport records skipped after the retained episode ceiling
    pub omitted_tcp_records: usize,
    pub omitted_ranges: usize,
    /// Ranges whose extents were rejected before byte or observation coverage was built
    pub unmeasured_omitted_ranges: usize,
    /// TCP byte positions affected by omitted observations or a rejected range reservation
    pub omitted_tcp_bytes: u64,
    /// TCP observations omitted by per-direction coverage limits
    pub omitted_tcp_observations: u64,
    /// Fragment byte positions affected by omitted observations or a rejected range reservation
    pub omitted_fragment_bytes: u64,
    /// Fragment observations omitted by per-datagram coverage limits
    pub omitted_fragment_observations: u64,
    pub omitted_state_observations: usize,
    pub datagrams: Vec<Datagram>,
    pub sessions: Vec<TcpSession>,
    pub udp: Vec<UdpMessage>,
}
