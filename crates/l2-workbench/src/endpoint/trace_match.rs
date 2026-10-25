use super::strace::{
    IoDirection, SocketEndpoint, SocketTuple, TraceIoEvent, TraceIoReport, TraceTransport,
};
use crate::{
    evidence::{Case, Node, SourceRange},
    reconstruction::{Origin, ReconstructionReport, Stream, UdpMessage},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, hash_map::Entry};

/// Result state for exact syscall-to-capture byte correlation
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceMatchStatus {
    /// One unique flow and byte location had complete packet provenance
    ExactUniqueMatch,
    /// More than one matching location or an ambiguous flow generation remains
    Ambiguous,
    /// The syscall trace did not record a complete byte string
    IncompleteTraceBytes,
    /// The syscall transferred no bytes
    NoTransferredBytes,
    /// The syscall had no parsed socket tuple
    FlowUnavailable,
    /// No captured flow matched the exact endpoint tuple and direction
    NoMatchingFlow,
    /// A matching flow was present but its retained bytes did not match
    BytesNotObserved,
    /// Captured bytes matched but packet source ranges could not be resolved
    CaptureProvenanceUnavailable,
    /// The capture report omitted input that could contain another match
    CaptureIncomplete,
}

/// Exact packet byte range supporting one trace correlation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TracePacketRange {
    /// Content-derived identity of the source capture file
    pub source: String,
    /// One-based packet number in the source capture
    pub packet: u64,
    /// Byte offset in the original capture source file
    pub offset: u64,
    /// Number of source bytes supporting the matched trace bytes
    pub length: u64,
}

/// One trace syscall's exact-match result and captured source ranges
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceCorrelation {
    /// Range of the syscall line in the externally collected trace file
    pub trace_source_range: SourceRange,
    /// Result state derived from the available trace evidence
    pub status: TraceMatchStatus,
    /// Count of exact byte locations found
    pub candidate_count: u64,
    /// Packet ranges supporting one exact candidate; ambiguity is stated separately
    pub captured_ranges: Vec<TracePacketRange>,
    /// Human-readable evidence boundary for this result
    pub explanation: String,
}

/// Correlate complete strace I/O bytes with retained reconstructed flows
///
/// Only exact address, direction, and byte matches can produce a unique result
/// `capture_scope` identifies the source used for reconstruction when packet numbers overlap
///
#[must_use]
pub fn correlate_trace_with_capture(
    trace: &TraceIoReport,
    reconstruction: &ReconstructionReport,
    case: &Case,
    capture_scope: Option<&str>,
) -> Vec<TraceCorrelation> {
    let packet_ranges = packet_source_map(case, capture_scope);
    trace
        .events
        .iter()
        .map(|event| correlate_event(event, reconstruction, &packet_ranges))
        .collect()
}

fn correlate_event(
    event: &TraceIoEvent,
    reconstruction: &ReconstructionReport,
    packet_ranges: &HashMap<u32, PacketSource>,
) -> TraceCorrelation {
    let mut result = empty_correlation(event);
    if !event.bytes_complete {
        result.status = TraceMatchStatus::IncompleteTraceBytes;
        set_explanation(
            &mut result,
            "The trace string or syscall result does not expose every transferred byte",
        );
        return result;
    }
    if event.bytes.is_empty() {
        result.status = TraceMatchStatus::NoTransferredBytes;
        set_explanation(&mut result, "The syscall returned no transferred bytes");
        return result;
    }
    let Some(socket) = event.socket.as_ref() else {
        result.status = TraceMatchStatus::FlowUnavailable;
        set_explanation(
            &mut result,
            "The trace line has no parsed local and peer socket tuple",
        );
        return result;
    };
    let mut candidates = CandidateAccumulator::default();
    match socket.transport {
        TraceTransport::Tcp => {
            scan_tcp(
                event,
                socket,
                reconstruction,
                packet_ranges,
                &mut candidates,
            );
        }
        TraceTransport::Udp => {
            scan_udp(
                event,
                socket,
                reconstruction,
                packet_ranges,
                &mut candidates,
            );
        }
    }
    result.candidate_count = candidates.candidate_count;
    finalize_correlation(&mut result, candidates, reconstruction.complete);
    result
}

fn set_explanation(result: &mut TraceCorrelation, explanation: &str) {
    explanation.clone_into(&mut result.explanation);
}

fn empty_correlation(event: &TraceIoEvent) -> TraceCorrelation {
    TraceCorrelation {
        trace_source_range: event.source_range.clone(),
        status: TraceMatchStatus::BytesNotObserved,
        candidate_count: 0,
        captured_ranges: Vec::new(),
        explanation: String::new(),
    }
}

struct Candidate {
    ranges: Vec<TracePacketRange>,
    ambiguous: bool,
    provenance_complete: bool,
}

#[derive(Default)]
struct CandidateAccumulator {
    flow_found: bool,
    unique_candidate: Option<Candidate>,
    ambiguous_candidate: bool,
    candidate_count: u64,
}

fn scan_tcp(
    event: &TraceIoEvent,
    socket: &SocketTuple,
    reconstruction: &ReconstructionReport,
    packet_ranges: &HashMap<u32, PacketSource>,
    candidates: &mut CandidateAccumulator,
) {
    for session in &reconstruction.sessions {
        for stream in &session.directions {
            if !tcp_direction_matches(stream, socket, event.direction) {
                continue;
            }
            candidates.flow_found = true;
            let is_ambiguous = session.generation_ambiguous || stream.sequence_ambiguous;
            for run in stream.runs() {
                for (relative, _) in run
                    .bytes
                    .windows(event.bytes.len())
                    .enumerate()
                    .filter(|(_, window)| *window == event.bytes.as_slice())
                {
                    let Some(start) = run.offset.checked_add(relative) else {
                        candidates.ambiguous_candidate = true;
                        continue;
                    };
                    let Some(end) = start.checked_add(event.bytes.len()) else {
                        candidates.ambiguous_candidate = true;
                        continue;
                    };
                    let candidate = tcp_candidate(stream, start, end, packet_ranges, is_ambiguous);
                    record_candidate(candidate, candidates);
                }
            }
        }
    }
}

fn tcp_direction_matches(stream: &Stream, socket: &SocketTuple, direction: IoDirection) -> bool {
    let (source, destination) = match direction {
        IoDirection::OutOfProcess => (&socket.local, &socket.peer),
        IoDirection::IntoProcess => (&socket.peer, &socket.local),
    };
    endpoint_matches(&stream.source, source) && endpoint_matches(&stream.destination, destination)
}

fn endpoint_matches(captured: &crate::reconstruction::Endpoint, observed: &SocketEndpoint) -> bool {
    network_address_matches(captured.address, observed.address) && captured.port == observed.port
}

fn tcp_candidate(
    stream: &Stream,
    start: usize,
    end: usize,
    packet_ranges: &HashMap<u32, PacketSource>,
    ambiguous: bool,
) -> Candidate {
    let mut ranges = Vec::new();
    let mut covered = Vec::new();
    for origin in &stream.origins {
        append_origin_intersection(origin, start, end, packet_ranges, &mut ranges, &mut covered);
    }
    let provenance_complete = covers_interval(&covered, start, end);
    Candidate {
        ranges,
        ambiguous,
        provenance_complete,
    }
}

fn append_origin_intersection(
    origin: &Origin,
    match_start: usize,
    match_end: usize,
    packet_ranges: &HashMap<u32, PacketSource>,
    ranges: &mut Vec<TracePacketRange>,
    covered: &mut Vec<(usize, usize)>,
) {
    let Some(origin_end) = origin.offset.checked_add(origin.length) else {
        return;
    };
    let start = origin.offset.max(match_start);
    let end = origin_end.min(match_end);
    if start >= end {
        return;
    }
    let relative = start.saturating_sub(origin.offset);
    let Some(source) = packet_ranges.get(&origin.packet) else {
        return;
    };
    let Some(range) = source.packet_range(origin, relative, end - start) else {
        return;
    };
    ranges.push(range);
    covered.push((start, end));
}

fn covers_interval(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    let mut intervals = ranges.to_vec();
    intervals.sort_unstable();
    let mut cursor = start;
    for (range_start, range_end) in intervals {
        if range_start > cursor {
            return false;
        }
        cursor = cursor.max(range_end);
        if cursor >= end {
            return true;
        }
    }
    false
}

fn scan_udp(
    event: &TraceIoEvent,
    socket: &SocketTuple,
    reconstruction: &ReconstructionReport,
    packet_ranges: &HashMap<u32, PacketSource>,
    candidates: &mut CandidateAccumulator,
) {
    for message in &reconstruction.udp {
        if !udp_direction_matches(message, socket, event.direction) {
            continue;
        }
        candidates.flow_found = true;
        for (start, _) in message
            .bytes
            .windows(event.bytes.len())
            .enumerate()
            .filter(|(_, window)| *window == event.bytes.as_slice())
        {
            let candidate = udp_candidate(message, start, event.bytes.len(), packet_ranges);
            record_candidate(candidate, candidates);
        }
    }
}

fn udp_direction_matches(
    message: &UdpMessage,
    socket: &SocketTuple,
    direction: IoDirection,
) -> bool {
    let (source, destination) = match direction {
        IoDirection::OutOfProcess => (&socket.local, &socket.peer),
        IoDirection::IntoProcess => (&socket.peer, &socket.local),
    };
    network_address_matches(message.source.address, source.address)
        && message.source.port == source.port
        && network_address_matches(message.destination.address, destination.address)
        && message.destination.port == destination.port
}

fn udp_candidate(
    message: &UdpMessage,
    start: usize,
    length: usize,
    packet_ranges: &HashMap<u32, PacketSource>,
) -> Candidate {
    let end = start.saturating_add(length);
    let mut ranges = Vec::new();
    let mut covered = Vec::new();
    for origin in &message.origins {
        append_origin_intersection(origin, start, end, packet_ranges, &mut ranges, &mut covered);
    }
    Candidate {
        provenance_complete: covers_interval(&covered, start, end),
        ranges,
        ambiguous: message.fragment_candidate.is_some(),
    }
}

fn record_candidate(candidate: Candidate, candidates: &mut CandidateAccumulator) {
    candidates.candidate_count = candidates.candidate_count.saturating_add(1);
    if candidate.ambiguous || candidates.unique_candidate.is_some() {
        candidates.ambiguous_candidate = true;
    } else {
        candidates.unique_candidate = Some(candidate);
    }
}

fn finalize_correlation(
    result: &mut TraceCorrelation,
    candidates: CandidateAccumulator,
    capture_complete: bool,
) {
    if candidates.ambiguous_candidate
        || candidates
            .unique_candidate
            .as_ref()
            .is_some_and(|value| value.ambiguous)
    {
        result.status = TraceMatchStatus::Ambiguous;
        set_explanation(
            result,
            "More than one exact location or an ambiguous connection generation matches",
        );
        return;
    }
    let Some(candidate) = candidates.unique_candidate else {
        result.status = if candidates.flow_found {
            TraceMatchStatus::BytesNotObserved
        } else if !capture_complete {
            TraceMatchStatus::CaptureIncomplete
        } else {
            TraceMatchStatus::NoMatchingFlow
        };
        let explanation = if candidates.flow_found {
            "A flow matched the endpoint tuple, but the complete trace bytes were not observed in it"
        } else if !capture_complete {
            "The capture is incomplete, so the absence of a matching flow is unresolved"
        } else {
            "No reconstructed flow matched the observed address, port, protocol, and direction"
        };
        set_explanation(result, explanation);
        return;
    };
    if !candidate.provenance_complete || candidate.ranges.is_empty() {
        result.status = TraceMatchStatus::CaptureProvenanceUnavailable;
        set_explanation(
            result,
            "Bytes matched a reconstructed stream, but complete original packet ranges were unavailable",
        );
        return;
    }
    if !capture_complete {
        result.status = TraceMatchStatus::CaptureIncomplete;
        result.captured_ranges = candidate.ranges;
        set_explanation(
            result,
            "Exact bytes were observed, but capture omissions prevent a unique result across the full input",
        );
        return;
    }
    result.status = TraceMatchStatus::ExactUniqueMatch;
    result.captured_ranges = candidate.ranges;
    set_explanation(
        result,
        "One complete byte string matched one direction of one nonambiguous captured flow",
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PacketSource {
    source: String,
    source_offset: u64,
    captured_length: usize,
}

impl PacketSource {
    fn packet_range(
        &self,
        origin: &Origin,
        relative: usize,
        length: usize,
    ) -> Option<TracePacketRange> {
        let frame_offset = origin.frame_offset.checked_add(relative)?;
        let frame_end = frame_offset.checked_add(length)?;
        if frame_end > self.captured_length {
            return None;
        }
        let source_offset = self
            .source_offset
            .checked_add(u64::try_from(frame_offset).ok()?)?;
        Some(TracePacketRange {
            source: self.source.clone(),
            packet: u64::from(origin.packet),
            offset: source_offset,
            length: u64::try_from(length).ok()?,
        })
    }
}

fn packet_source_map(case: &Case, capture_scope: Option<&str>) -> HashMap<u32, PacketSource> {
    let mut candidates = HashMap::new();
    for node in case.nodes().iter().filter(|node| node.kind == "packet") {
        for range in &node.ranges {
            let Some((packet, source)) = packet_source(node, range) else {
                continue;
            };
            if capture_scope.is_none_or(|scope| scope == source.source.as_str()) {
                retain_packet_source(&mut candidates, packet, source);
            }
        }
    }
    candidates
        .into_iter()
        .filter_map(|(packet, source)| source.map(|value| (packet, value)))
        .collect()
}

fn retain_packet_source(
    candidates: &mut HashMap<u32, Option<PacketSource>>,
    packet: u32,
    source: PacketSource,
) {
    match candidates.entry(packet) {
        Entry::Vacant(entry) => {
            entry.insert(Some(source));
        }
        Entry::Occupied(mut entry) => {
            if entry
                .get()
                .as_ref()
                .is_some_and(|current| current == &source)
            {
                return;
            }
            entry.insert(None);
        }
    }
}

fn packet_source(node: &Node, range: &SourceRange) -> Option<(u32, PacketSource)> {
    let packet = u32::try_from(node.details.get("record")?.as_u64()?).ok()?;
    let captured_length = usize::try_from(node.details.get("captured_length")?.as_u64()?).ok()?;
    let captured_length_u64 = u64::try_from(captured_length).ok()?;
    if range.packet != Some(u64::from(packet)) || range.length < captured_length_u64 {
        return None;
    }
    Some((
        packet,
        PacketSource {
            source: range.source.clone(),
            source_offset: range.offset,
            captured_length,
        },
    ))
}

fn network_address_matches(
    captured: l2_discovery::NetworkAddress,
    observed: std::net::IpAddr,
) -> bool {
    match (captured, observed) {
        (l2_discovery::NetworkAddress::Ipv4(left), std::net::IpAddr::V4(right)) => {
            left == right.octets()
        }
        (l2_discovery::NetworkAddress::Ipv6(left), std::net::IpAddr::V6(right)) => {
            left == right.octets()
        }
        _ => false,
    }
}
