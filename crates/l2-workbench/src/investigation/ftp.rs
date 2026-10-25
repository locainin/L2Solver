//! FTP line facts and exact endpoint-matched TCP data candidates

use super::{
    artifacts,
    graph::{Context, MappedRange},
    network::{DirectionNodes, RunNodes, SessionNodes, value_node},
};
use crate::{
    application::{
        ByteRange,
        ftp::{
            FtpCommandAction, FtpControlEvent, FtpDataMode, FtpItem,
            association::{
                FtpAssociationReport, FtpControlEventKind, FtpEndpointCandidate,
                FtpSessionCandidate, FtpTransferAction, FtpTransferAssessment, MAX_CONTROL_EVENTS,
                associate_data_sessions, payload_reversed,
            },
        },
    },
    evidence::EvidenceStatus,
    reconstruction::{Origin, ReconstructionReport},
};
use serde_json::json;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
    error::Error,
};

const MAX_DATA_CANDIDATES: usize = 8_192;

pub(super) fn add(
    context: &mut Context<'_>,
    reconstruction: &ReconstructionReport,
    sessions: &[SessionNodes<'_>],
) -> Result<(), Box<dyn Error>> {
    let prepared = prepare_events(context, sessions)?;
    let association = associate_data_sessions(&prepared.events, &reconstruction.sessions);
    for limitation in &association.limitations {
        context.case.add_limitation(limitation)?;
    }
    if !association.complete {
        context.incomplete = true;
    }

    let transfer_nodes = add_transfer_candidates(
        context,
        sessions,
        &prepared.bindings,
        &prepared.transfer_binding_indices,
        &association,
    )?;
    let data_counts = add_data_candidates(
        context,
        sessions,
        &prepared.bindings,
        &prepared.transfer_binding_indices,
        &association,
        &transfer_nodes,
    )?;

    add_coverage(
        context,
        &association,
        prepared.bindings.len(),
        prepared.omitted_events,
        prepared.unlocated_events,
        data_counts.retained,
        data_counts.exhausted,
    )?;
    Ok(())
}

struct PreparedEvents<'a> {
    bindings: Vec<EventBinding<'a>>,
    events: Vec<FtpControlEvent>,
    transfer_binding_indices: Vec<usize>,
    omitted_events: usize,
    unlocated_events: usize,
}

fn prepare_events<'a>(
    context: &mut Context<'_>,
    sessions: &'a [SessionNodes<'a>],
) -> Result<PreparedEvents<'a>, Box<dyn Error>> {
    let (mut bindings, omitted_events, unlocated_events) = collect_events(sessions)?;
    let mut events = Vec::with_capacity(bindings.len());
    let mut transfer_binding_indices = Vec::new();
    for (index, binding) in bindings.iter_mut().enumerate() {
        let session = session_nodes(sessions, binding.session_index)?;
        let direction = direction_nodes(session, binding.direction_index)?;
        let run = run_nodes(direction, binding.run_index)?;
        binding.control_node = add_control_candidate(context, session, direction, run, binding)?;
        if matches!(binding.event.kind, FtpControlEventKind::Transfer { .. }) {
            transfer_binding_indices.push(index);
        }
        events.push(binding.event.clone());
    }
    if omitted_events != 0 || unlocated_events != 0 {
        context.incomplete = true;
        context.case.add_limitation(
            "Some supported FTP control events could not be retained or tied to an earliest capture prefix",
        )?;
    }
    Ok(PreparedEvents {
        bindings,
        events,
        transfer_binding_indices,
        omitted_events,
        unlocated_events,
    })
}

fn add_transfer_candidates(
    context: &mut Context<'_>,
    sessions: &[SessionNodes<'_>],
    bindings: &[EventBinding<'_>],
    transfer_indices: &[usize],
    association: &FtpAssociationReport,
) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut nodes = Vec::with_capacity(association.transfers.len());
    for (assessment, binding_index) in association
        .transfers
        .iter()
        .zip(transfer_indices.iter().copied())
    {
        let binding = bindings
            .get(binding_index)
            .ok_or("FTP transfer binding is absent")?;
        let session = session_nodes(sessions, binding.session_index)?;
        let direction = direction_nodes(session, binding.direction_index)?;
        let run = run_nodes(direction, binding.run_index)?;
        let filename_node = add_filename_argument(context, run, binding)?;
        nodes.push(add_transfer_candidate(
            context,
            session,
            direction,
            run,
            binding,
            assessment,
            filename_node,
        )?);
    }
    Ok(nodes)
}

struct DataCandidateCount {
    retained: usize,
    exhausted: bool,
}

struct AssociationCandidate<'a> {
    binding: &'a EventBinding<'a>,
    endpoint: &'a FtpEndpointCandidate,
    assessment: &'a FtpTransferAssessment,
    session_candidate: &'a FtpSessionCandidate,
    transfer_node: u64,
}

fn add_data_candidates(
    context: &mut Context<'_>,
    sessions: &[SessionNodes<'_>],
    bindings: &[EventBinding<'_>],
    transfer_indices: &[usize],
    association: &FtpAssociationReport,
    transfer_nodes: &[u64],
) -> Result<DataCandidateCount, Box<dyn Error>> {
    let mut counts = DataCandidateCount {
        retained: 0,
        exhausted: false,
    };
    'transfers: for (assessment_index, assessment) in association.transfers.iter().enumerate() {
        let transfer_node = *transfer_nodes
            .get(assessment_index)
            .ok_or("FTP transfer node is absent")?;
        let binding_index = *transfer_indices
            .get(assessment_index)
            .ok_or("FTP transfer binding index is absent")?;
        let binding = bindings
            .get(binding_index)
            .ok_or("FTP transfer binding is absent")?;
        for endpoint in &assessment.endpoint_candidates {
            for session_candidate in &endpoint.sessions {
                let candidate = AssociationCandidate {
                    binding,
                    endpoint,
                    assessment,
                    session_candidate,
                    transfer_node,
                };
                if append_candidate_runs(context, sessions, &candidate, &mut counts)? {
                    break 'transfers;
                }
            }
        }
    }
    if counts.exhausted {
        context.incomplete = true;
        context.case.add_limitation(
            "FTP data-run candidates were omitted after the bounded association output limit",
        )?;
    }
    Ok(counts)
}

fn append_candidate_runs(
    context: &mut Context<'_>,
    sessions: &[SessionNodes<'_>],
    candidate: &AssociationCandidate<'_>,
    counts: &mut DataCandidateCount,
) -> Result<bool, Box<dyn Error>> {
    let Some(session) = sessions
        .iter()
        .find(|session| session.session_index == candidate.session_candidate.session_index)
    else {
        context.incomplete = true;
        return Ok(false);
    };
    let control_peer = match candidate.endpoint.mode {
        FtpDataMode::Active => candidate.binding.event.destination.address,
        FtpDataMode::Passive => candidate.binding.event.source.address,
    };
    let Some((connection_index, payload_index)) = expected_directions(
        session,
        control_peer,
        candidate.endpoint,
        candidate.assessment.action,
    ) else {
        return Ok(false);
    };
    let connection = session
        .directions
        .get(connection_index)
        .ok_or("FTP connection direction is absent")?;
    let payload = session
        .directions
        .get(payload_index)
        .ok_or("FTP payload direction is absent")?;
    for run in &payload.runs {
        if run.bytes.is_empty() {
            continue;
        }
        if counts.retained == MAX_DATA_CANDIDATES {
            counts.exhausted = true;
            return Ok(true);
        }
        let data_candidate = DataCandidate {
            session,
            direction: payload,
            run,
            binding: candidate.binding,
            endpoint: candidate.endpoint,
            assessment: candidate.assessment,
            association: candidate.session_candidate,
            connection_direction_node: connection.id,
            transfer_node: candidate.transfer_node,
        };
        add_data_candidate(context, &data_candidate)?;
        counts.retained += 1;
    }
    Ok(false)
}

struct EventBinding<'a> {
    event: FtpControlEvent,
    item: &'a FtpItem,
    line_origins: Vec<Origin>,
    argument_origins: Option<Vec<Origin>>,
    session_index: usize,
    direction_index: usize,
    run_index: usize,
    control_node: u64,
    order: EventOrder,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EventOrder {
    packet: u32,
    stream_offset: usize,
    session_index: usize,
    direction_index: usize,
    run_index: usize,
}

impl PartialEq for EventBinding<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.order == other.order
    }
}

impl Eq for EventBinding<'_> {}

impl PartialOrd for EventBinding<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventBinding<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order.cmp(&other.order)
    }
}

#[derive(Clone, Copy)]
struct Availability {
    end: usize,
    packet: u32,
    origin_index: usize,
}

struct SupportedRange {
    packet: u32,
    origins: Vec<Origin>,
}

fn collect_events<'a>(
    sessions: &'a [SessionNodes<'a>],
) -> Result<(Vec<EventBinding<'a>>, usize, usize), Box<dyn Error>> {
    let mut earliest = BinaryHeap::with_capacity(MAX_CONTROL_EVENTS);
    let mut supported_events = 0_usize;
    let mut unlocated_events = 0_usize;

    for session in sessions {
        for (direction_index, direction) in session.directions.iter().enumerate() {
            for (run_index, run) in direction.runs.iter().enumerate() {
                if run.ftp.findings.is_empty() {
                    continue;
                }
                let availability = availability_index(&run.origins, run.bytes.len())?;
                for item in &run.ftp.findings {
                    let Some(mut event) = FtpControlEvent::from_item(
                        session.scope.clone(),
                        0,
                        run.offset,
                        session.control_episode,
                        direction.source.clone(),
                        direction.destination.clone(),
                        item,
                    ) else {
                        continue;
                    };
                    supported_events = supported_events.saturating_add(1);
                    let Some(line_support) =
                        supported_origins(&run.origins, &availability, item.range)?
                    else {
                        unlocated_events = unlocated_events.saturating_add(1);
                        continue;
                    };
                    let argument_origins = transfer_argument(item)
                        .map(|range| supported_origins(&run.origins, &availability, range))
                        .transpose()?
                        .flatten()
                        .map(|support| support.origins);
                    event.packet = line_support.packet;
                    let order = EventOrder {
                        packet: line_support.packet,
                        stream_offset: event.range.offset,
                        session_index: session.session_index,
                        direction_index,
                        run_index,
                    };
                    let binding = EventBinding {
                        event,
                        item,
                        line_origins: line_support.origins,
                        argument_origins,
                        session_index: session.session_index,
                        direction_index,
                        run_index,
                        control_node: 0,
                        order,
                    };
                    if earliest.len() < MAX_CONTROL_EVENTS {
                        earliest.push(binding);
                    } else if earliest.peek().is_some_and(|latest| binding < *latest) {
                        earliest.pop();
                        earliest.push(binding);
                    }
                }
            }
        }
    }

    let omitted = supported_events
        .saturating_sub(earliest.len())
        .saturating_sub(unlocated_events);
    let mut bindings = earliest.into_vec();
    bindings.sort_by_key(|binding| binding.order);
    Ok((bindings, omitted, unlocated_events))
}

fn availability_index(
    origins: &[Origin],
    run_length: usize,
) -> Result<BTreeMap<usize, Availability>, Box<dyn Error>> {
    let mut ordered = Vec::with_capacity(origins.len());
    for (origin_index, origin) in origins.iter().enumerate() {
        let end = origin
            .offset
            .checked_add(origin.length)
            .ok_or("FTP provenance range overflow")?;
        if end > run_length {
            return Err("FTP provenance exceeds its contiguous TCP run".into());
        }
        if origin.length != 0 {
            ordered.push((origin.packet, origin.offset, end, origin_index));
        }
    }
    ordered.sort_unstable();

    let mut earliest: BTreeMap<usize, Availability> = BTreeMap::new();
    for (packet, start, end, origin_index) in ordered {
        let mut cursor = start;
        while cursor < end {
            if let Some((_, covered)) = earliest.range(..=cursor).next_back()
                && covered.end > cursor
            {
                cursor = covered.end.min(end);
                continue;
            }
            if let Some((&next_start, _)) = earliest.range(cursor..).next() {
                let gap_end = next_start.min(end);
                if gap_end > cursor {
                    earliest.insert(
                        cursor,
                        Availability {
                            end: gap_end,
                            packet,
                            origin_index,
                        },
                    );
                    cursor = gap_end;
                }
            } else {
                earliest.insert(
                    cursor,
                    Availability {
                        end,
                        packet,
                        origin_index,
                    },
                );
                break;
            }
        }
    }
    Ok(earliest)
}

fn supported_origins(
    origins: &[Origin],
    availability: &BTreeMap<usize, Availability>,
    target: ByteRange,
) -> Result<Option<SupportedRange>, Box<dyn Error>> {
    if target.length == 0 {
        return Ok(None);
    }
    let end = target
        .offset
        .checked_add(target.length)
        .ok_or("FTP line range overflow")?;
    let mut cursor = target.offset;
    let mut latest_packet = 0;
    let mut supported = Vec::new();

    while cursor < end {
        let Some((start, available)) = availability
            .range(..=cursor)
            .next_back()
            .filter(|(_, span)| span.end > cursor)
        else {
            return Ok(None);
        };
        let first = (*start).max(target.offset);
        let last = available.end.min(end);
        let origin = origins
            .get(available.origin_index)
            .ok_or("FTP availability index references a missing origin")?;
        supported.push(Origin {
            packet: available.packet,
            frame_offset: origin
                .frame_offset
                .checked_add(first - origin.offset)
                .ok_or("FTP source frame offset overflow")?,
            offset: first - target.offset,
            length: last - first,
        });
        latest_packet = latest_packet.max(available.packet);
        cursor = last;
    }
    Ok(Some(SupportedRange {
        packet: latest_packet,
        origins: supported,
    }))
}

fn add_control_candidate(
    context: &mut Context<'_>,
    session: &SessionNodes<'_>,
    direction: &DirectionNodes<'_>,
    run: &RunNodes<'_>,
    binding: &EventBinding<'_>,
) -> Result<u64, Box<dyn Error>> {
    let mappings = context.mappings(&binding.line_origins)?;
    let line_bytes = binding
        .item
        .range
        .slice(run.bytes)
        .ok_or("FTP control line exceeds its TCP run")?;
    let id = context.case.add_node(
        "ftp_control_candidate",
        Some(&run.blob),
        source_ranges(&mappings),
        json!({
            "event": binding.event,
            "line": binding.item,
            "tcp_episode_node": session.id,
            "tcp_direction_node": direction.id,
            "tcp_byte_run_node": run.id,
            "run_range": binding.item.range,
            "stream_range": ByteRange::new(run.offset.checked_add(binding.item.range.offset).ok_or("FTP stream offset overflow")?, binding.item.range.length),
            "available_at_record": binding.event.packet,
            "raw_line_length": line_bytes.len(),
            "interpretation": "A bounded FTP control-line candidate with earliest retained record-prefix provenance",
        }),
    )?;
    context.edge(
        run.id,
        id,
        "derived_from",
        EvidenceStatus::ConstraintSatisfied,
        "The control-line range is selected from this exact retained TCP byte-run blob",
    )?;
    Ok(id)
}

fn add_filename_argument(
    context: &mut Context<'_>,
    run: &RunNodes<'_>,
    binding: &EventBinding<'_>,
) -> Result<Option<u64>, Box<dyn Error>> {
    let Some(argument) = transfer_argument(binding.item) else {
        return Ok(None);
    };
    let Some(origins) = binding.argument_origins.as_deref() else {
        context.incomplete = true;
        context.case.add_limitation(
            "An FTP transfer argument could not be tied to retained source byte ranges",
        )?;
        return Ok(None);
    };
    let mappings = context.mappings(origins)?;
    let argument_bytes = argument
        .slice(run.bytes)
        .ok_or("FTP argument exceeds its TCP run")?;
    let stream_offset = run
        .offset
        .checked_add(argument.offset)
        .ok_or("FTP argument stream offset overflow")?;
    let id = context.case.add_node(
        "ftp_filename_argument",
        Some(&run.blob),
        source_ranges(&mappings),
        json!({
            "tcp_byte_run_node": run.id,
            "run_range": argument,
            "stream_range": ByteRange::new(stream_offset, argument.length),
            "byte_length": argument_bytes.len(),
            "encoding": "raw_bytes",
            "interpretation": "Literal argument bytes parsed for RETR or STOR; filesystem meaning and acceptance are unresolved",
        }),
    )?;
    context.edge(
        run.id,
        id,
        "slice_of",
        EvidenceStatus::Observed,
        "The argument range selects literal bytes from this retained TCP run",
    )?;
    Ok(Some(id))
}

fn add_transfer_candidate(
    context: &mut Context<'_>,
    session: &SessionNodes<'_>,
    direction: &DirectionNodes<'_>,
    run: &RunNodes<'_>,
    binding: &EventBinding<'_>,
    assessment: &FtpTransferAssessment,
    filename_node: Option<u64>,
) -> Result<u64, Box<dyn Error>> {
    let mappings = context.mappings(&binding.line_origins)?;
    let mut details = serde_json::to_value(assessment)?;
    let object = details
        .as_object_mut()
        .ok_or("FTP transfer assessment did not serialize as an object")?;
    object.insert("control_line_node".to_owned(), json!(binding.control_node));
    object.insert("tcp_episode_node".to_owned(), json!(session.id));
    object.insert("tcp_direction_node".to_owned(), json!(direction.id));
    object.insert("tcp_byte_run_node".to_owned(), json!(run.id));
    object.insert("control_episode".to_owned(), json!(session.control_episode));
    object.insert(
        "available_at_record".to_owned(),
        json!(binding.event.packet),
    );
    object.insert("line_run_range".to_owned(), json!(binding.item.range));
    object.insert("transfer_accepted".to_owned(), json!("unresolved"));
    object.insert("complete_file".to_owned(), json!("unresolved"));
    if let Some(filename_node) = filename_node {
        object.insert("filename_argument_node".to_owned(), json!(filename_node));
    }
    let id = value_node(context, "ftp_transfer_candidate", details, &mappings)?;
    context.edge(
        binding.control_node,
        id,
        "describes_transfer_candidate",
        EvidenceStatus::Hypothesis,
        "The parsed RETR or STOR command is linked to bounded endpoint and session candidates",
    )?;
    if let Some(filename_node) = filename_node {
        context.edge(
            filename_node,
            id,
            "argument_of",
            EvidenceStatus::Observed,
            "The raw argument range belongs to this parsed transfer command",
        )?;
    }
    Ok(id)
}

struct DataCandidate<'a> {
    session: &'a SessionNodes<'a>,
    direction: &'a DirectionNodes<'a>,
    run: &'a RunNodes<'a>,
    binding: &'a EventBinding<'a>,
    endpoint: &'a FtpEndpointCandidate,
    assessment: &'a FtpTransferAssessment,
    association: &'a FtpSessionCandidate,
    connection_direction_node: u64,
    transfer_node: u64,
}

fn add_data_candidate(
    context: &mut Context<'_>,
    candidate: &DataCandidate<'_>,
) -> Result<u64, Box<dyn Error>> {
    let session = candidate.session;
    let direction = candidate.direction;
    let run = candidate.run;
    let binding = candidate.binding;
    let endpoint = candidate.endpoint;
    let assessment = candidate.assessment;
    let association = candidate.association;
    let connection_direction_node = candidate.connection_direction_node;
    let transfer_node = candidate.transfer_node;
    let id = context.case.add_node(
        "ftp_data_candidate",
        Some(&run.blob),
        source_ranges(&run.mappings),
        json!({
            "scope": session.scope,
            "mode": endpoint.mode,
            "action": assessment.action,
            "advertisement_record": endpoint.endpoint_packet,
            "advertised_endpoint": endpoint.endpoint,
            "effective_address": endpoint.effective_address,
            "address_source": endpoint.address_source,
            "connection_direction_node": connection_direction_node,
            "transfer_available_at_record": binding.event.packet,
            "control_episode": session.control_episode,
            "transfer_candidate_node": transfer_node,
            "tcp_episode_node": session.id,
            "tcp_direction_node": direction.id,
            "tcp_byte_run_node": run.id,
            "stream_source": direction.source,
            "stream_destination": direction.destination,
            "run_range": ByteRange::new(0, run.bytes.len()),
            "stream_range": ByteRange::new(run.offset, run.bytes.len()),
            "run_start_known": run.start_known,
            "run_end_observed": run.end_observed,
            "direction_start_known": direction.start_known,
            "direction_end_observed": direction.end_observed,
            "sequence_ambiguous": direction.sequence_ambiguous,
            "generation_ambiguous": association.generation_ambiguous || session.generation_ambiguous,
            "direction_ambiguous": association.direction_ambiguous,
            "association_status": association.association_status,
            "initiator_matches_expected": association.initiator_matches_expected,
            "boundary_ambiguous": assessment.boundary_ambiguous,
            "association_truncated": assessment.truncated,
            "endpoint_candidate_truncated": endpoint.truncated,
            "opened_before_transfer": association.opened_before_transfer,
            "transfer_accepted": "unresolved",
            "complete_file": "unresolved",
            "interpretation": "An endpoint-matched contiguous TCP run; FIN marks a TCP direction end and does not establish one FTP file boundary",
        }),
    )?;
    context.edge(
        run.id,
        id,
        "derived_from",
        EvidenceStatus::ConstraintSatisfied,
        "The candidate references the same retained byte-run blob and source ranges",
    )?;
    context.edge(
        transfer_node,
        id,
        "candidate_data_for",
        EvidenceStatus::Hypothesis,
        "The tuple and direction fit an FTP endpoint candidate; command acceptance and causation remain unresolved",
    )?;
    artifacts::add(context, id, run.bytes, &run.mappings)?;
    Ok(id)
}

fn expected_directions(
    session: &SessionNodes<'_>,
    control_peer: l2_discovery::NetworkAddress,
    endpoint: &FtpEndpointCandidate,
    action: FtpTransferAction,
) -> Option<(usize, usize)> {
    let connection_direction = session.directions.iter().position(|direction| {
        direction.source.address == control_peer
            && direction.destination.address == endpoint.effective_address
            && direction.destination.port == endpoint.endpoint.port
    })?;
    let payload_direction = connection_direction ^ payload_reversed(endpoint.mode, action);
    Some((connection_direction, payload_direction))
}

fn transfer_argument(item: &FtpItem) -> Option<ByteRange> {
    let crate::application::ftp::FtpKind::Command(command) = &item.kind else {
        return None;
    };
    matches!(
        command.action,
        FtpCommandAction::Retrieve | FtpCommandAction::Store
    )
    .then_some(command.argument_range?)
}

fn add_coverage(
    context: &mut Context<'_>,
    association: &FtpAssociationReport,
    retained_events: usize,
    omitted_events: usize,
    unlocated_events: usize,
    data_candidates: usize,
    data_candidate_budget_exhausted: bool,
) -> Result<(), Box<dyn Error>> {
    let complete = association.complete
        && omitted_events == 0
        && unlocated_events == 0
        && !data_candidate_budget_exhausted;
    context.case.add_node(
        "ftp_association_coverage",
        None,
        Vec::new(),
        json!({
            "status": if complete { "complete_within_supported_subset" } else { "incomplete" },
            "control_events_retained": retained_events,
            "control_events_omitted": omitted_events,
            "control_events_without_earliest_provenance": unlocated_events,
            "transfers_assessed": association.transfers.len(),
            "omitted_endpoint_candidates": association.omitted_endpoint_candidates,
            "omitted_session_candidates": association.omitted_session_candidates,
            "data_candidates_retained": data_candidates,
            "data_candidate_budget_exhausted": data_candidate_budget_exhausted,
            "association_complete": association.complete,
            "omitted_sessions": association.omitted_sessions,
            "association_limitations": association.limitations,
            "interpretation": "Completeness describes retained bounded candidate analysis, not protocol coverage or transfer acceptance",
        }),
    )?;
    Ok(())
}

fn source_ranges(mappings: &[MappedRange]) -> Vec<crate::evidence::SourceRange> {
    mappings
        .iter()
        .map(|mapping| mapping.range.clone())
        .collect()
}

fn session_nodes<'b, 'a>(
    sessions: &'b [SessionNodes<'a>],
    index: usize,
) -> Result<&'b SessionNodes<'a>, Box<dyn Error>> {
    sessions
        .iter()
        .find(|session| session.session_index == index)
        .ok_or_else(|| "FTP association references an omitted TCP episode".into())
}

fn direction_nodes<'b, 'a>(
    session: &'b SessionNodes<'a>,
    index: usize,
) -> Result<&'b DirectionNodes<'a>, Box<dyn Error>> {
    session
        .directions
        .get(index)
        .ok_or_else(|| "FTP control direction is absent".into())
}

fn run_nodes<'b, 'a>(
    direction: &'b DirectionNodes<'a>,
    index: usize,
) -> Result<&'b RunNodes<'a>, Box<dyn Error>> {
    direction
        .runs
        .get(index)
        .ok_or_else(|| "FTP control run is absent".into())
}
