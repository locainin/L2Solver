//! Exact tuple correlations between FTP control facts and reconstructed TCP sessions

use super::{FtpCommandAction, FtpEndpoint, FtpItem, FtpKind, FtpReply};
use crate::{
    application::{ByteRange, ParseStatus},
    reconstruction::{Endpoint, TcpSession},
};
use l2_audit::ForensicScope;
use l2_discovery::NetworkAddress;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CONTROL_EVENTS: usize = 4_096;
pub const MAX_ASSOCIATED_SESSIONS: usize = 2_048;
pub const MAX_ENDPOINT_CANDIDATES: usize = 8_192;
pub const MAX_SESSION_CANDIDATES: usize = 8_192;

/// Direction of an observed data session relative to the advertised endpoint
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpDataDirection {
    ActiveControlPeerToEndpoint,
    PassiveControlPeerToEndpoint,
}

/// FTP transfer setup mode represented by a parsed endpoint fact
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpDataMode {
    Active,
    Passive,
}

/// Source used for the endpoint address when comparing a session tuple
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpEndpointAddressSource {
    Advertised,
    ControlPeer,
}

/// Transfer command observed on an FTP control stream
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpTransferAction {
    Retrieve,
    Store,
}

/// Parsed endpoint advertisement or transfer line with capture-local provenance
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpControlEvent {
    pub scope: ForensicScope,
    pub control_episode: u32,
    /// Earliest retained capture prefix covering this complete control line
    pub packet: u32,
    /// Offset in the source directional stream, including the caller's run base
    pub range: ByteRange,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub status: ParseStatus,
    pub kind: FtpControlEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FtpControlEventKind {
    EndpointAdvertisement {
        mode: FtpDataMode,
        endpoint: FtpEndpoint,
        effective_address: NetworkAddress,
        address_source: FtpEndpointAddressSource,
    },
    Transfer {
        action: FtpTransferAction,
    },
}

impl FtpControlEvent {
    /// Convert one parsed line into a reusable correlation fact
    ///
    /// `stream_offset` is the base offset of the source contiguous run. A line
    /// without a supported endpoint or transfer action does not create an event.
    #[must_use]
    pub fn from_item(
        scope: ForensicScope,
        packet: u32,
        stream_offset: usize,
        control_episode: u32,
        source: Endpoint,
        destination: Endpoint,
        item: &FtpItem,
    ) -> Option<Self> {
        if !matches!(item.status, ParseStatus::Complete | ParseStatus::Ambiguous) {
            return None;
        }
        let offset = stream_offset.checked_add(item.range.offset)?;
        let range = ByteRange::new(offset, item.range.length);
        range.offset.checked_add(range.length)?;
        let kind = event_kind(&item.kind, &source)?;
        Some(Self {
            scope,
            control_episode,
            packet,
            range,
            source,
            destination,
            status: item.status,
            kind,
        })
    }
}

fn event_kind(kind: &FtpKind, source: &Endpoint) -> Option<FtpControlEventKind> {
    match kind {
        FtpKind::Command(command) => match command.action {
            FtpCommandAction::ActiveEndpoint => {
                let endpoint = command.endpoint?;
                let effective_address = endpoint.address?;
                Some(FtpControlEventKind::EndpointAdvertisement {
                    mode: FtpDataMode::Active,
                    endpoint,
                    effective_address,
                    address_source: FtpEndpointAddressSource::Advertised,
                })
            }
            FtpCommandAction::Retrieve => Some(FtpControlEventKind::Transfer {
                action: FtpTransferAction::Retrieve,
            }),
            FtpCommandAction::Store => Some(FtpControlEventKind::Transfer {
                action: FtpTransferAction::Store,
            }),
            _ => None,
        },
        FtpKind::Reply(reply) => passive_event(reply, source),
        FtpKind::Other => None,
    }
}

fn passive_event(reply: &FtpReply, source: &Endpoint) -> Option<FtpControlEventKind> {
    if !matches!(reply.code, 227 | 229) {
        return None;
    }
    let endpoint = reply.endpoint?;
    let (effective_address, address_source) = endpoint.address.map_or_else(
        || (source.address, FtpEndpointAddressSource::ControlPeer),
        |address| (address, FtpEndpointAddressSource::Advertised),
    );
    Some(FtpControlEventKind::EndpointAdvertisement {
        mode: FtpDataMode::Passive,
        endpoint,
        effective_address,
        address_source,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpAssociationStatus {
    Candidates,
    NoPriorEndpointFact,
    NoExactSession,
    UnresolvedLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpAssociationReport {
    pub transfers: Vec<FtpTransferAssessment>,
    pub omitted_events: usize,
    pub omitted_sessions: usize,
    pub omitted_endpoint_candidates: usize,
    pub omitted_session_candidates: usize,
    pub complete: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpTransferAssessment {
    pub packet: u32,
    pub range: ByteRange,
    pub action: FtpTransferAction,
    pub status: FtpAssociationStatus,
    pub boundary_ambiguous: bool,
    pub truncated: bool,
    pub endpoint_candidates: Vec<FtpEndpointCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpEndpointCandidate {
    pub mode: FtpDataMode,
    pub endpoint_packet: u32,
    pub endpoint_range: ByteRange,
    pub endpoint: FtpEndpoint,
    pub effective_address: NetworkAddress,
    pub address_source: FtpEndpointAddressSource,
    pub truncated: bool,
    pub sessions: Vec<FtpSessionCandidate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpSessionAssociationStatus {
    Unique,
    ReusedAcrossTransfers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FtpSessionCandidate {
    pub session_index: usize,
    pub direction: FtpDataDirection,
    pub opened_before_transfer: bool,
    pub generation_ambiguous: bool,
    pub initiator_matches_expected: Option<bool>,
    pub direction_ambiguous: bool,
    pub association_status: FtpSessionAssociationStatus,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DataTuple {
    scope: ForensicScope,
    source: NetworkAddress,
    destination: NetworkAddress,
    destination_port: u16,
}

#[derive(Clone, Copy)]
struct IndexedSession {
    session_index: usize,
    tuple_direction: usize,
    first_packet: u32,
    generation_ambiguous: bool,
    initiator_matches_expected: Option<bool>,
    directions: [IndexedDirection; 2],
}

#[derive(Clone, Copy, Default)]
struct IndexedDirection {
    end_observed: bool,
    last_packet: Option<u32>,
}

/// Associate prior endpoint facts with every later exact scoped TCP tuple candidate
///
/// The comparison uses observed control endpoints, advertised data addresses and
/// capture record order. It does not infer command acceptance, NAT rewriting, or
/// causation. Resource limits make worst-case work and report size predictable.
#[must_use]
pub fn associate_data_sessions(
    events: &[FtpControlEvent],
    sessions: &[TcpSession],
) -> FtpAssociationReport {
    let considered_events = events.len().min(MAX_CONTROL_EVENTS);
    let considered_sessions = sessions.len().min(MAX_ASSOCIATED_SESSIONS);
    let omitted_events = events.len().saturating_sub(considered_events);
    let omitted_sessions = sessions.len().saturating_sub(considered_sessions);
    let mut report = empty_association_report(omitted_events, omitted_sessions);
    let event_slice = events.get(..considered_events).unwrap_or_default();
    let session_slice = sessions.get(..considered_sessions).unwrap_or_default();
    let session_index = index_sessions(session_slice);
    let mut budget = CandidateBudget::default();

    for transfer in event_slice.iter().filter_map(transfer_event) {
        let assessment = assess_transfer(
            transfer,
            event_slice,
            &session_index,
            omitted_events != 0 || omitted_sessions != 0,
            &mut budget,
            &mut report,
        );
        report.transfers.push(assessment);
    }
    mark_reused_sessions_ambiguous(&mut report);
    report
}

fn empty_association_report(
    omitted_events: usize,
    omitted_sessions: usize,
) -> FtpAssociationReport {
    FtpAssociationReport {
        transfers: Vec::new(),
        omitted_events,
        omitted_sessions,
        omitted_endpoint_candidates: 0,
        omitted_session_candidates: 0,
        complete: omitted_events == 0 && omitted_sessions == 0,
        limitations: vec![
            "Exact tuple mismatches do not rule out NAT, proxies, protocol helpers, or omitted capture data",
            "A correlated session is an observed endpoint and timing match, not proof that the FTP command was accepted or caused the session",
        ],
    }
}

#[derive(Default)]
struct CandidateBudget {
    endpoint_candidates: usize,
    session_candidates: usize,
}

fn assess_transfer(
    transfer: TransferEvent<'_>,
    events: &[FtpControlEvent],
    session_index: &BTreeMap<DataTuple, Vec<IndexedSession>>,
    inputs_truncated: bool,
    budget: &mut CandidateBudget,
    report: &mut FtpAssociationReport,
) -> FtpTransferAssessment {
    let mut assessment = FtpTransferAssessment {
        packet: transfer.event.packet,
        range: transfer.event.range,
        action: transfer.action,
        status: FtpAssociationStatus::NoPriorEndpointFact,
        boundary_ambiguous: transfer.event.status == ParseStatus::Ambiguous,
        truncated: inputs_truncated,
        endpoint_candidates: Vec::new(),
    };
    for advertisement in events
        .iter()
        .filter_map(endpoint_event)
        .filter(|event| same_control_conversation(event, transfer.event))
        .filter(|event| event_precedes(event, transfer.event))
    {
        append_endpoint_candidate(
            advertisement,
            transfer,
            session_index,
            budget,
            report,
            &mut assessment,
        );
    }
    if assessment.truncated
        && matches!(
            assessment.status,
            FtpAssociationStatus::NoPriorEndpointFact | FtpAssociationStatus::NoExactSession
        )
    {
        assessment.status = FtpAssociationStatus::UnresolvedLimit;
    }
    if assessment.truncated {
        report.complete = false;
    }
    assessment
}

fn append_endpoint_candidate(
    advertisement: EndpointEvent<'_>,
    transfer: TransferEvent<'_>,
    session_index: &BTreeMap<DataTuple, Vec<IndexedSession>>,
    budget: &mut CandidateBudget,
    report: &mut FtpAssociationReport,
    assessment: &mut FtpTransferAssessment,
) {
    if assessment.status == FtpAssociationStatus::NoPriorEndpointFact {
        assessment.status = FtpAssociationStatus::NoExactSession;
    }
    assessment.boundary_ambiguous |= advertisement.event.status == ParseStatus::Ambiguous;
    if budget.endpoint_candidates == MAX_ENDPOINT_CANDIDATES {
        report.omitted_endpoint_candidates = report.omitted_endpoint_candidates.saturating_add(1);
        report.complete = false;
        assessment.truncated = true;
        return;
    }
    budget.endpoint_candidates += 1;
    let mut candidate = FtpEndpointCandidate {
        mode: advertisement.mode,
        endpoint_packet: advertisement.event.packet,
        endpoint_range: advertisement.event.range,
        endpoint: advertisement.endpoint,
        effective_address: *advertisement.effective_address,
        address_source: advertisement.address_source,
        truncated: assessment.truncated,
        sessions: Vec::new(),
    };
    let matched = append_session_candidates(
        advertisement,
        transfer,
        session_index,
        budget,
        report,
        assessment,
        &mut candidate,
    );
    if matched {
        assessment.status = FtpAssociationStatus::Candidates;
    }
    assessment.endpoint_candidates.push(candidate);
}

fn append_session_candidates(
    advertisement: EndpointEvent<'_>,
    transfer: TransferEvent<'_>,
    session_index: &BTreeMap<DataTuple, Vec<IndexedSession>>,
    budget: &mut CandidateBudget,
    report: &mut FtpAssociationReport,
    assessment: &mut FtpTransferAssessment,
    candidate: &mut FtpEndpointCandidate,
) -> bool {
    let Some(indexed) = session_index.get(&data_tuple(advertisement)) else {
        return false;
    };
    let first_later =
        indexed.partition_point(|session| session.first_packet <= advertisement.event.packet);
    let later = indexed.get(first_later..).unwrap_or_default();
    let remaining = MAX_SESSION_CANDIDATES.saturating_sub(budget.session_candidates);
    let mut omitted = 0;
    let mut matched = false;
    for session in later.iter().filter(|session| {
        !payload_direction_ended_before(
            session,
            advertisement.mode,
            transfer.action,
            transfer.event.packet,
        )
    }) {
        matched = true;
        if candidate.sessions.len() < remaining {
            budget.session_candidates += 1;
            candidate.sessions.push(session_candidate(
                session,
                advertisement.mode,
                transfer.event.packet,
            ));
        } else {
            omitted += 1;
        }
    }
    if omitted != 0 {
        report.omitted_session_candidates =
            report.omitted_session_candidates.saturating_add(omitted);
        report.complete = false;
        candidate.truncated = true;
        assessment.truncated = true;
    }
    matched
}

fn session_candidate(
    session: &IndexedSession,
    mode: FtpDataMode,
    transfer_packet: u32,
) -> FtpSessionCandidate {
    let direction = match mode {
        FtpDataMode::Active => FtpDataDirection::ActiveControlPeerToEndpoint,
        FtpDataMode::Passive => FtpDataDirection::PassiveControlPeerToEndpoint,
    };
    FtpSessionCandidate {
        session_index: session.session_index,
        direction,
        opened_before_transfer: session.first_packet < transfer_packet,
        generation_ambiguous: session.generation_ambiguous,
        initiator_matches_expected: session.initiator_matches_expected,
        direction_ambiguous: session.initiator_matches_expected != Some(true),
        association_status: FtpSessionAssociationStatus::Unique,
    }
}

fn payload_direction_ended_before(
    session: &IndexedSession,
    mode: FtpDataMode,
    action: FtpTransferAction,
    transfer_packet: u32,
) -> bool {
    let payload_direction = session.tuple_direction ^ payload_reversed(mode, action);
    session
        .directions
        .get(payload_direction)
        .is_some_and(|direction| {
            direction.end_observed
                && direction
                    .last_packet
                    .is_some_and(|packet| packet < transfer_packet)
        })
}

fn mark_reused_sessions_ambiguous(report: &mut FtpAssociationReport) {
    let mut transfer_counts = BTreeMap::new();
    for transfer in &report.transfers {
        let mut session_indices = BTreeSet::new();
        for endpoint in &transfer.endpoint_candidates {
            session_indices.extend(
                endpoint
                    .sessions
                    .iter()
                    .map(|candidate| candidate.session_index),
            );
        }
        for session_index in session_indices {
            let count = transfer_counts.entry(session_index).or_insert(0_usize);
            *count = count.saturating_add(1);
        }
    }

    let mut any_ambiguous = false;
    for candidate in report
        .transfers
        .iter_mut()
        .flat_map(|transfer| &mut transfer.endpoint_candidates)
        .flat_map(|endpoint| &mut endpoint.sessions)
    {
        let reused = transfer_counts
            .get(&candidate.session_index)
            .is_some_and(|count| *count > 1);
        candidate.association_status = if reused {
            FtpSessionAssociationStatus::ReusedAcrossTransfers
        } else {
            FtpSessionAssociationStatus::Unique
        };
        any_ambiguous |=
            candidate.association_status == FtpSessionAssociationStatus::ReusedAcrossTransfers;
    }
    if any_ambiguous {
        report
            .limitations
            .push("An unended data session matching multiple FTP transfers is ambiguous");
    }
}

#[derive(Clone, Copy)]
struct TransferEvent<'a> {
    event: &'a FtpControlEvent,
    action: FtpTransferAction,
}

const fn transfer_event(event: &FtpControlEvent) -> Option<TransferEvent<'_>> {
    let FtpControlEventKind::Transfer { action } = &event.kind else {
        return None;
    };
    Some(TransferEvent {
        event,
        action: *action,
    })
}

#[derive(Clone, Copy)]
struct EndpointEvent<'a> {
    event: &'a FtpControlEvent,
    mode: FtpDataMode,
    endpoint: FtpEndpoint,
    effective_address: &'a NetworkAddress,
    address_source: FtpEndpointAddressSource,
}

const fn endpoint_event(event: &FtpControlEvent) -> Option<EndpointEvent<'_>> {
    let FtpControlEventKind::EndpointAdvertisement {
        mode,
        endpoint,
        effective_address,
        address_source,
    } = &event.kind
    else {
        return None;
    };
    Some(EndpointEvent {
        event,
        mode: *mode,
        endpoint: *endpoint,
        effective_address,
        address_source: *address_source,
    })
}

fn index_sessions(sessions: &[TcpSession]) -> BTreeMap<DataTuple, Vec<IndexedSession>> {
    let mut index: BTreeMap<DataTuple, Vec<IndexedSession>> = BTreeMap::new();
    for (session_index, session) in sessions.iter().enumerate() {
        let directions = session
            .directions
            .each_ref()
            .map(|stream| IndexedDirection {
                end_observed: stream.end_observed,
                last_packet: stream.packets.last().copied(),
            });
        for (tuple_direction, stream) in session
            .directions
            .iter()
            .enumerate()
            .filter(|(_, stream)| !stream.packets.is_empty())
        {
            let tuple = DataTuple {
                scope: session.scope.clone(),
                source: stream.source.address,
                destination: stream.destination.address,
                destination_port: stream.destination.port,
            };
            let initiator_matches_expected = session
                .initiator
                .as_ref()
                .map(|initiator| initiator.address == tuple.source);
            let candidates = index.entry(tuple).or_default();
            if candidates
                .last()
                .is_some_and(|candidate: &IndexedSession| candidate.session_index == session_index)
            {
                continue;
            }
            candidates.push(IndexedSession {
                session_index,
                tuple_direction,
                first_packet: session.first_packet,
                generation_ambiguous: session.generation_ambiguous,
                initiator_matches_expected,
                directions,
            });
        }
    }
    for indexed in index.values_mut() {
        indexed.sort_by_key(|session| (session.first_packet, session.session_index));
    }
    index
}

pub(crate) const fn payload_reversed(mode: FtpDataMode, action: FtpTransferAction) -> usize {
    match (mode, action) {
        (FtpDataMode::Active, FtpTransferAction::Retrieve)
        | (FtpDataMode::Passive, FtpTransferAction::Store) => 0,
        (FtpDataMode::Active, FtpTransferAction::Store)
        | (FtpDataMode::Passive, FtpTransferAction::Retrieve) => 1,
    }
}

fn data_tuple(advertisement: EndpointEvent<'_>) -> DataTuple {
    DataTuple {
        scope: advertisement.event.scope.clone(),
        source: advertisement.event.destination.address,
        destination: *advertisement.effective_address,
        destination_port: advertisement.endpoint.port,
    }
}

fn same_control_conversation(
    advertisement: &EndpointEvent<'_>,
    transfer: &FtpControlEvent,
) -> bool {
    if advertisement.event.scope != transfer.scope
        || advertisement.event.control_episode != transfer.control_episode
    {
        return false;
    }
    match advertisement.mode {
        FtpDataMode::Active => {
            advertisement.event.source == transfer.source
                && advertisement.event.destination == transfer.destination
        }
        FtpDataMode::Passive => {
            advertisement.event.source == transfer.destination
                && advertisement.event.destination == transfer.source
        }
    }
}

fn event_precedes(advertisement: &EndpointEvent<'_>, transfer: &FtpControlEvent) -> bool {
    if advertisement.event.packet < transfer.packet {
        return true;
    }
    if advertisement.event.packet > transfer.packet {
        return false;
    }
    advertisement
        .event
        .range
        .offset
        .checked_add(advertisement.event.range.length)
        .is_some_and(|end| end <= transfer.range.offset)
}
