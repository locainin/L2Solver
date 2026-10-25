use super::{
    applications,
    graph::{Context, MappedRange, clip},
};
use crate::{
    application::{
        ParseContext, ParseReport, ParseStatus,
        ftp::FtpItem,
        http::{HttpRequestMethod, HttpStart, decode_http},
    },
    evidence::{Edge, EvidenceStatus, MAX_NODE_DETAILS_BYTES, MAX_NODE_RANGES, SourceRange},
    reconstruction::{Endpoint, Origin, ReconstructionReport, Stream},
};
use l2_audit::{ForensicScope, ForensicTracker, ResourceLimitStatus};
use l2_discovery::ip_header;
use serde::Serialize;
use serde_json::{Value, json};
use std::error::Error;

pub(super) struct SessionNodes<'a> {
    pub session_index: usize,
    pub control_episode: u32,
    pub id: u64,
    pub scope: ForensicScope,
    pub generation_ambiguous: bool,
    pub directions: [DirectionNodes<'a>; 2],
}

pub(super) struct DirectionNodes<'a> {
    pub id: u64,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub start_known: bool,
    pub end_observed: bool,
    pub sequence_ambiguous: bool,
    pub runs: Vec<RunNodes<'a>>,
}

pub(super) struct RunNodes<'a> {
    pub id: u64,
    pub blob: String,
    pub offset: usize,
    pub bytes: &'a [u8],
    pub start_known: bool,
    pub end_observed: bool,
    pub origins: Vec<Origin>,
    pub mappings: Vec<MappedRange>,
    pub ftp: ParseReport<FtpItem>,
}

pub(super) fn packets(context: &mut Context<'_>) -> Result<(), Box<dyn Error>> {
    let mut unsupported_link_type_seen = false;
    for (&number, frame) in context.records {
        let ethernet_layout = frame.metadata().link_type().is_ethernet();
        unsupported_link_type_seen |= !ethernet_layout;
        let decoded = ethernet_layout
            .then(|| l2_core::decode(frame.bytes()).ok())
            .flatten();
        let ip = decoded.as_ref().and_then(ip_header);
        let mut details = serde_json::Map::new();
        details.insert("record".to_owned(), json!(number));
        details.insert(
            "link_type".to_owned(),
            json!(frame.metadata().link_type().raw()),
        );
        details.insert("captured_length".to_owned(), json!(frame.bytes().len()));
        details.insert(
            "original_length".to_owned(),
            json!(frame.metadata().original_len()),
        );
        details.insert("truncated".to_owned(), json!(frame.is_truncated()));
        details.insert("timestamp".to_owned(), json!(frame.metadata().timestamp().map(|time| json!({
            "ticks":time.ticks(),"radix":time.resolution().radix(),"exponent":time.resolution().exponent(),
            "offset_seconds":time.offset_seconds(),"source":format!("{:?}",time.source()),
        }))));
        details.insert(
            "timestamp_source_ranges".to_owned(),
            json!(super::timestamps::ranges(context.source, number, frame)?),
        );
        if let Some(ethernet) = &decoded {
            details.insert(
                "scope".to_owned(),
                serde_json::to_value(ForensicScope::new(frame.metadata(), ethernet))?,
            );
            details.insert("source_mac".to_owned(), json!(ethernet.source));
            details.insert("destination_mac".to_owned(), json!(ethernet.destination));
        }
        if let Some(ip) = ip {
            details.insert("source_ip".to_owned(), json!(ip.source.to_string()));
            details.insert(
                "destination_ip".to_owned(),
                json!(ip.destination.to_string()),
            );
            details.insert("protocol".to_owned(), json!(ip.protocol));
            details.insert("fragmented".to_owned(), json!(ip.fragmented));
        }
        let mapping = context.mappings(&[crate::reconstruction::Origin {
            packet: number,
            frame_offset: 0,
            offset: 0,
            length: frame.bytes().len(),
        }])?;
        if frame.metadata().locator().is_none() {
            context.incomplete = true;
            context.case.add_limitation("Some retained packets lack file locators; their hashes and bytes are retained but absolute source ranges are unavailable")?;
        }
        let id = context.case.add_mapped_bytes_node(
            "packet",
            frame.bytes(),
            &mapping,
            Value::Object(details),
        )?;
        context.packet_nodes.insert(number, id);
    }
    if unsupported_link_type_seen {
        context.incomplete = true;
        context.case.add_limitation(
            "Raw non-Ethernet packets are retained, but Ethernet packet and dependent forensic analyses cannot interpret that link type",
        )?;
    }
    Ok(())
}

pub(super) fn forensics(context: &mut Context<'_>) -> Result<(), Box<dyn Error>> {
    let mut tracker = ForensicTracker::new(4096, 2048);
    let mut status = ResourceLimitStatus::default();
    for (&number, captured) in context.records {
        if !captured.metadata().link_type().is_ethernet() {
            continue;
        }
        if let Ok(frame) = l2_core::decode(captured.bytes()) {
            tracker.observe(captured, &frame, u64::from(number), true, &mut status);
        }
    }
    let report = tracker.finish();
    if status.collection_incomplete() {
        context.incomplete = true;
        context.case.add_limitation("Some network forensic facts were omitted after tracker budgets; related event chains are incomplete")?;
    }
    for item in &report.communications {
        observation(context, "ip_communication", item, &[item.packet])?;
    }
    for item in &report.arp_observations {
        observation(context, "arp_claim", item, &[item.packet])?;
    }
    for item in &report.arp_changes {
        let mut packets = vec![item.previous_packet, item.packet];
        packets.extend(item.followup_packet);
        observation(context, "arp_claim_sequence", item, &packets)?;
    }
    for item in &report.trailing_data {
        observation(context, "trailing_bytes", item, &[item.packet])?;
    }
    for item in &report.dns_observations {
        observation(context, "dns_wire", item, &[item.packet])?;
    }
    for item in &report.dns_matches {
        let mut packets = vec![item.response_packet];
        packets.extend(item.query_packet);
        observation(context, "dns_query_response", item, &packets)?;
    }
    for item in &report.dns_address_uses {
        observation(
            context,
            "dns_address_sequence",
            item,
            &[item.query_packet, item.response_packet, item.packet],
        )?;
    }
    let limits = serde_json::to_value(status)?;
    context.case.add_node("forensic_coverage", None, Vec::new(), json!({
        "dns_candidates_seen": report.dns_candidates_seen, "dns_messages_parsed": report.dns_messages_parsed,
        "ip_frames_seen": report.ip_frames_seen, "ip_frames_parsed": report.ip_frames_parsed,
        "resource_limits": limits, "trailer_frames_unchecked": report.trailer_frames_unchecked,
    }))?;
    for limitation in report.limitations {
        context.case.add_limitation(limitation)?;
    }
    Ok(())
}

fn observation(
    context: &mut Context<'_>,
    kind: &str,
    value: &impl Serialize,
    packets: &[u64],
) -> Result<u64, Box<dyn Error>> {
    let details = serde_json::to_value(value)?;
    let packet_numbers: Vec<_> = packets
        .iter()
        .filter_map(|number| u32::try_from(*number).ok())
        .collect();
    let mut mappings = Vec::new();
    for number in &packet_numbers {
        if let Some(frame) = context.records.get(number) {
            mappings.extend(context.mappings(&[crate::reconstruction::Origin {
                packet: *number,
                frame_offset: 0,
                offset: 0,
                length: frame.bytes().len(),
            }])?);
        }
    }
    let id = value_node(context, kind, details, &mappings)?;
    context.packet_edges(packet_numbers, id, EvidenceStatus::Observed)?;
    Ok(id)
}

pub(super) fn value_node(
    context: &mut Context<'_>,
    kind: &str,
    details: Value,
    mappings: &[MappedRange],
) -> Result<u64, Box<dyn Error>> {
    let bytes = serde_json::to_vec(&details)?;
    if bytes.len() <= MAX_NODE_DETAILS_BYTES {
        Ok(context.case.add_node(
            kind,
            None,
            mappings
                .iter()
                .map(|mapping| mapping.range.clone())
                .collect(),
            details,
        )?)
    } else {
        Ok(context.case.add_bytes_node(
            kind,
            &bytes,
            mappings
                .iter()
                .map(|mapping| mapping.range.clone())
                .collect(),
            json!({"representation": "json_blob", "bytes": bytes.len()}),
        )?)
    }
}

pub(super) fn reconstruction<'a>(
    context: &mut Context<'_>,
    report: &'a ReconstructionReport,
) -> Result<Vec<SessionNodes<'a>>, Box<dyn Error>> {
    let datagrams = datagrams(context, report)?;
    let sessions = tcp_sessions(context, report, &datagrams)?;
    udp_messages(context, report, &datagrams)?;
    Ok(sessions)
}

fn datagrams(
    context: &mut Context<'_>,
    report: &ReconstructionReport,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut nodes = Vec::with_capacity(report.datagrams.len());
    for datagram in &report.datagrams {
        let mappings = context.mappings(&datagram.origins)?;
        let (ranges, available_ranges, omitted_ranges) =
            bounded_fragment_ranges(mappings.into_iter().map(|mapping| mapping.range).collect())?;
        if omitted_ranges != 0 {
            context.incomplete = true;
            context.case.add_limitation(&format!(
                "A fragment candidate exceeded the per-node evidence source range budget of {MAX_NODE_RANGES}; {omitted_ranges} source ranges were omitted from the candidate"
            ))?;
        }
        let id = context.case.add_node("fragment_candidate", None, ranges, json!({
            "scope": datagram.scope, "family": datagram.family, "source": datagram.source, "destination": datagram.destination,
            "identification": datagram.identification, "protocols": datagram.protocols, "final_lengths": datagram.final_lengths,
            "provenance": {
                "fragment_count": datagram.origins.len(),
                "source_ranges_available": available_ranges,
                "source_ranges_retained": available_ranges - omitted_ranges,
                "source_ranges_omitted": omitted_ranges,
                "source_range_limit": MAX_NODE_RANGES,
            },
            "unique_coverage": datagram.complete, "identity_ambiguous": datagram.identity_ambiguous,
            "metadata_consistent": datagram.metadata_consistent,
            "coverage": datagram.coverage.as_ref().map(|range| json!({"length":range.length,"missing":range.missing_bytes,"conflicting":range.conflicting_bytes,"omitted":range.omitted_bytes,"omitted_observations":range.omitted_observations})),
        }))?;
        context.packet_edges(
            datagram.origins.iter().map(|origin| origin.packet),
            id,
            EvidenceStatus::Hypothesis,
        )?;
        nodes.push(id);
    }
    Ok(nodes)
}

fn bounded_fragment_ranges(
    mut ranges: Vec<SourceRange>,
) -> Result<(Vec<SourceRange>, usize, usize), Box<dyn Error>> {
    // A merged range keeps the exact source union when one packet contains adjacent observations
    ranges.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.packet.cmp(&right.packet))
            .then_with(|| left.offset.cmp(&right.offset))
            .then_with(|| left.length.cmp(&right.length))
    });
    let mut canonical: Vec<SourceRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = canonical.last_mut()
            && previous.packet.is_some()
            && previous.source == range.source
            && previous.packet == range.packet
        {
            let previous_end = previous
                .offset
                .checked_add(previous.length)
                .ok_or("fragment source range overflow")?;
            let range_end = range
                .offset
                .checked_add(range.length)
                .ok_or("fragment source range overflow")?;
            if range.offset <= previous_end {
                previous.length = previous_end.max(range_end) - previous.offset;
                continue;
            }
        }
        canonical.push(range);
    }

    let available = canonical.len();
    let omitted = available.saturating_sub(MAX_NODE_RANGES);
    canonical.truncate(MAX_NODE_RANGES);
    Ok((canonical, available, omitted))
}

fn tcp_sessions<'a>(
    context: &mut Context<'_>,
    report: &'a ReconstructionReport,
    datagrams: &[u64],
) -> Result<Vec<SessionNodes<'a>>, Box<dyn Error>> {
    let mut session_nodes = Vec::with_capacity(report.sessions.len());
    for (session_index, session) in report.sessions.iter().enumerate() {
        let control_episode = u32::try_from(session_index)?;
        let id = context.case.add_node("tcp_episode", None, Vec::new(), json!({
            "scope": session.scope, "endpoints": session.endpoints, "first_packet": session.first_packet,
            "initiator": session.initiator,
            "generation_ambiguous": session.generation_ambiguous, "reset_packets": session.reset_packets,
            "handshake_status": session.handshake.status,
        }))?;
        let checks = value_node(
            context,
            "tcp_handshake_checks",
            json!(&session.handshake),
            &[],
        )?;
        context.case.add_edge(Edge {
            from: id, to: checks, relation: "tested_by".to_owned(), status: EvidenceStatus::Observed,
            reason: "Capture-order sequence and acknowledgement checks describe observed packets, without proving delivery or peer acceptance".to_owned(),
        })?;
        context.packet_edges(
            session
                .directions
                .iter()
                .flat_map(|stream| stream.packets.iter().copied()),
            id,
            EvidenceStatus::Hypothesis,
        )?;
        for candidate in session
            .directions
            .iter()
            .flat_map(|stream| &stream.fragment_candidates)
        {
            fragment_edge(context, datagrams, *candidate, id)?;
        }
        let first = session
            .directions
            .first()
            .ok_or("missing first TCP direction")?;
        let second = session
            .directions
            .get(1)
            .ok_or("missing second TCP direction")?;
        let first_methods = request_methods(second, session.generation_ambiguous);
        let second_methods = request_methods(first, session.generation_ambiguous);
        let first_nodes = add_stream(
            context,
            id,
            first,
            session.generation_ambiguous,
            &first_methods,
        )?;
        let second_nodes = add_stream(
            context,
            id,
            second,
            session.generation_ambiguous,
            &second_methods,
        )?;
        session_nodes.push(SessionNodes {
            session_index,
            control_episode,
            id,
            scope: session.scope.clone(),
            generation_ambiguous: session.generation_ambiguous,
            directions: [first_nodes, second_nodes],
        });
    }
    Ok(session_nodes)
}

fn udp_messages(
    context: &mut Context<'_>,
    report: &ReconstructionReport,
    datagrams: &[u64],
) -> Result<(), Box<dyn Error>> {
    for message in &report.udp {
        let from_fragments = message.fragment_candidate.is_some();
        let mappings = context.mappings(&message.origins)?;
        let id = context.case.add_mapped_bytes_node("udp_payload", &message.bytes, &mappings, json!({
            "scope": message.scope, "source": message.source, "destination": message.destination,
            "available_at_record": message.packet, "from_fragments": from_fragments,
            "identity_ambiguous": from_fragments,
        }))?;
        context.packet_edges(
            message.origins.iter().map(|origin| origin.packet),
            id,
            if from_fragments {
                EvidenceStatus::Hypothesis
            } else {
                EvidenceStatus::Observed
            },
        )?;
        if let Some(candidate) = message.fragment_candidate {
            fragment_edge(context, datagrams, candidate, id)?;
        }
        if !message.trailing_bytes.is_empty() {
            let mappings = context.mappings(&message.trailing_origins)?;
            let trailing = context.case.add_mapped_bytes_node("udp_trailing_bytes", &message.trailing_bytes, &mappings, json!({
                "scope": message.scope, "source": message.source, "destination": message.destination,
                "available_at_record": message.packet, "from_fragments": from_fragments,
                "identity_ambiguous": from_fragments,
                "interpretation": "Bytes inside the IP payload after the declared UDP length; purpose is unresolved",
            }))?;
            context.packet_edges(
                message.trailing_origins.iter().map(|origin| origin.packet),
                trailing,
                EvidenceStatus::Observed,
            )?;
            if let Some(candidate) = message.fragment_candidate {
                fragment_edge(context, datagrams, candidate, trailing)?;
            }
        }
    }
    Ok(())
}

fn fragment_edge(
    context: &mut Context<'_>,
    datagrams: &[u64],
    candidate: usize,
    id: u64,
) -> Result<(), Box<dyn Error>> {
    let from = *datagrams
        .get(candidate)
        .ok_or("missing fragment provenance candidate")?;
    context.edge(from, id, "derived_from", EvidenceStatus::Hypothesis,
        "This fragment candidate supplies transport header fields and bytes; datagram generation and receiver policy remain unresolved")
}

fn request_methods(stream: &Stream, generation_ambiguous: bool) -> Vec<Option<HttpRequestMethod>> {
    if generation_ambiguous || !stream.start_known || stream.sequence_ambiguous {
        return Vec::new();
    }
    let Some(coverage) = &stream.coverage else {
        return Vec::new();
    };
    if !coverage.unique() {
        return Vec::new();
    }
    let runs = stream.runs();
    let Some(run) = runs.first().filter(|run| run.offset == 0) else {
        return Vec::new();
    };
    let parsed = decode_http(
        run.bytes,
        ParseContext {
            start_known: true,
            end_observed: stream.end_observed,
        },
    );
    parsed
        .findings
        .iter()
        .map(|message| {
            if message.status != ParseStatus::Complete {
                return None;
            }
            let HttpStart::Request { method, .. } = message.start else {
                return None;
            };
            method.slice(run.bytes).map(|method| match method {
                b"HEAD" => HttpRequestMethod::Head,
                b"CONNECT" => HttpRequestMethod::Connect,
                _ => HttpRequestMethod::Other,
            })
        })
        .collect()
}

fn add_stream<'a>(
    context: &mut Context<'_>,
    session: u64,
    stream: &'a Stream,
    generation_ambiguous: bool,
    methods: &[Option<HttpRequestMethod>],
) -> Result<DirectionNodes<'a>, Box<dyn Error>> {
    let id = context.case.add_node("tcp_direction", None, Vec::new(), json!({
        "source": stream.source, "destination": stream.destination, "start_sequence": stream.start_sequence,
        "start_known": stream.start_known, "end_observed": stream.end_observed, "sequence_ambiguous": stream.sequence_ambiguous,
        "outside_segments": stream.outside_segments,
        "coverage": stream.coverage.as_ref().map(|range| json!({"length":range.length,"observed":range.observed_bytes,"missing":range.missing_bytes,"conflicting":range.conflicting_bytes,"omitted":range.omitted_bytes,"omitted_observations":range.omitted_observations})),
    }))?;
    context.edge(
        session,
        id,
        "contains",
        EvidenceStatus::Hypothesis,
        "Direction belongs to this capture-order TCP episode candidate",
    )?;
    let mappings = context.mappings(&stream.origins)?;
    let mut runs = Vec::new();
    for run in stream.runs() {
        runs.push(add_run(
            context,
            id,
            stream,
            &run,
            generation_ambiguous,
            methods,
            &mappings,
        )?);
    }
    Ok(DirectionNodes {
        id,
        source: stream.source.clone(),
        destination: stream.destination.clone(),
        start_known: stream.start_known,
        end_observed: stream.end_observed,
        sequence_ambiguous: stream.sequence_ambiguous,
        runs,
    })
}

fn add_run<'a>(
    context: &mut Context<'_>,
    direction: u64,
    stream: &'a Stream,
    run: &crate::reconstruction::ByteRun<'a>,
    generation_ambiguous: bool,
    methods: &[Option<HttpRequestMethod>],
    stream_mappings: &[MappedRange],
) -> Result<RunNodes<'a>, Box<dyn Error>> {
    let mapped = clip(stream_mappings, run.offset, run.bytes.len())?;
    let start_known = stream.start_known
        && run.offset == 0
        && !stream.sequence_ambiguous
        && !generation_ambiguous;
    let end_observed = stream.end_observed
        && stream
            .coverage
            .as_ref()
            .is_some_and(|coverage| run.offset + run.bytes.len() == coverage.length)
        && !stream.sequence_ambiguous
        && !generation_ambiguous;
    let run_id = context.case.add_mapped_bytes_node(
        "tcp_byte_run",
        run.bytes,
        &mapped,
        json!({
            "offset": run.offset, "length": run.bytes.len(), "start_known": start_known,
            "end_observed": end_observed, "generation_ambiguous": generation_ambiguous,
        }),
    )?;
    context.edge(
        direction,
        run_id,
        "contains",
        EvidenceStatus::Observed,
        "Contiguous positions have one retained value and no relevant quota omission",
    )?;
    let ftp = applications::add(
        context,
        run_id,
        run.bytes,
        &mapped,
        ParseContext {
            start_known,
            end_observed,
        },
        if start_known { methods } else { &[] },
    )?;
    let blob = context
        .case
        .node(run_id)
        .and_then(|node| node.blob.clone())
        .ok_or("TCP byte run has no retained blob")?;
    Ok(RunNodes {
        id: run_id,
        blob,
        offset: run.offset,
        bytes: run.bytes,
        start_known,
        end_observed,
        origins: clipped_origins(&stream.origins, run.offset, run.bytes.len())?,
        mappings: mapped,
        ftp,
    })
}

fn clipped_origins(
    origins: &[Origin],
    offset: usize,
    length: usize,
) -> Result<Vec<Origin>, Box<dyn Error>> {
    let end = offset.checked_add(length).ok_or("TCP run range overflow")?;
    let mut clipped = Vec::new();
    for origin in origins {
        let origin_end = origin
            .offset
            .checked_add(origin.length)
            .ok_or("TCP origin range overflow")?;
        let first = origin.offset.max(offset);
        let last = origin_end.min(end);
        if first >= last {
            continue;
        }
        clipped.push(Origin {
            packet: origin.packet,
            frame_offset: origin
                .frame_offset
                .checked_add(first - origin.offset)
                .ok_or("TCP source frame range overflow")?,
            offset: first - offset,
            length: last - first,
        });
    }
    Ok(clipped)
}
