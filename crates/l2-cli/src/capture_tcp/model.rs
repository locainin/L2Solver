use l2_audit::ForensicScope;
use l2_capture::CapturedFrame;
use l2_discovery::NetworkAddress;
use l2_workbench::tcp_range::RangeReport;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(super) const MAX_UNRESOLVED_SOURCES: usize = 128;

#[derive(Serialize)]
pub(super) struct FlowSelection {
    pub scope: ForensicScope,
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub ports: (u16, u16),
}

#[derive(Serialize)]
pub(super) struct FrameSource {
    pub packet_index: u32,
    pub captured_length: usize,
    pub original_length: u32,
    pub captured_sha256: String,
}

impl FrameSource {
    pub(super) fn new(packet: &CapturedFrame, packet_index: u32) -> Self {
        Self {
            packet_index,
            captured_length: packet.captured_len(),
            original_length: packet.metadata().original_len(),
            captured_sha256: format!("{:x}", Sha256::digest(packet.bytes())),
        }
    }
}

#[derive(Serialize)]
pub(super) struct UnresolvedSource {
    pub source: FrameSource,
    pub reason: UnresolvedReason,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UnresolvedReason {
    EthernetLayout,
    TruncatedCapture,
    LinkType,
    IpLayout,
    IpFragment,
    TcpLayout,
}

#[derive(Serialize)]
pub(super) struct CaptureTcpReport {
    pub schema_version: u32,
    pub tool_version: &'static str,
    pub complete: bool,
    pub first_packet: u32,
    pub last_packet: u32,
    pub capture_packets: u32,
    pub matching_packets: u64,
    pub unresolved_packets: u64,
    /// First 128 unresolved sources; the total count remains exact
    pub unresolved_sources: Vec<UnresolvedSource>,
    pub flow: FlowSelection,
    pub sources: Vec<FrameSource>,
    pub range: RangeReport,
    pub limitations: &'static [&'static str],
}

pub(super) const LIMITATIONS: &[&str] = &[
    "This is a directed tuple and capture-record window, not proof of one connection generation; tuple and sequence reuse remain unresolved",
    "Observed values describe retained payload bytes only; missing positions have no retained value, and omission coverage can overlap them",
    "SYN advances the first payload sequence by one; FIN and RST do not create payload bytes",
    "Conflicting bytes preserve source observations without selecting an endpoint overlap policy",
    "IP fragmentation is not reassembled; incomplete or unsupported candidates in the selected scope prevent a complete range report",
    "Checksums, acknowledgement acceptance, receive windows, clocks, delivery, application processing, and malicious intent are not established",
    "Packets before the selected first record and after an explicit last record do not contribute; a complete range is not a complete session or capture",
];
