//! Native evidence-case selection with exact byte mapping receipts

mod cohort;
mod context;

use self::context::case_context;
use super::{
    engine::{discover, discover_case_to_sink, discover_for_cohort},
    model::{
        DiscoveryError, DiscoveryMapping, DiscoveryPlan, DiscoveryReport, DiscoverySample,
        DiscoveryView,
    },
    plan::validate_mappings,
    results::{
        DiscoveryResultStore, ReplayReceipt, StoreOptions, StoreWriter, StoredDiscoverySummary,
        replay_candidate_with_identity,
    },
};
use crate::{
    carrier::Ambiguity,
    evidence::{Blob, Case, Node},
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Build discovery samples from retained packet, UDP payload, or TCP byte-run nodes
///
/// # Errors
/// Rejects unsupported nodes, missing bytes or context, unresolved ambiguity, and invalid source receipts
pub fn discover_case(
    case: &Case,
    node_ids: &[u64],
    plan: &DiscoveryPlan,
) -> Result<DiscoveryReport, DiscoveryError> {
    discover_case_with_view(case, node_ids, DiscoveryView::Bytes, plan)
}

/// Run discovery over retained bytes or native transport payloads from packet nodes
///
/// # Errors
/// Rejects unsupported nodes, malformed packet envelopes, missing context, or invalid source receipts
pub fn discover_case_with_view(
    case: &Case,
    node_ids: &[u64],
    view: DiscoveryView,
    plan: &DiscoveryPlan,
) -> Result<DiscoveryReport, DiscoveryError> {
    if node_ids.is_empty() {
        return Err(DiscoveryError::InvalidSelection);
    }
    let index = CaseIndex::new(case);
    let CaseSelection {
        nodes,
        identity,
        omitted_empty_sample_ids,
    } = select_nodes(
        case,
        node_ids,
        view,
        plan.max_input_bytes,
        &index.nodes,
        &index.blobs,
    )?;
    let samples = collect_samples(nodes, view, &index)?;
    match identity {
        Some((direction, local_identity)) => discover_for_cohort(
            &samples,
            plan,
            direction,
            local_identity,
            omitted_empty_sample_ids,
        ),
        None => discover(&samples, plan),
    }
}

/// Run native case discovery into a paged, disk-backed result store
///
/// # Errors
/// Rejects invalid selections, plans, provenance, exhausted budgets, or storage failures
pub fn discover_case_to_store(
    case: &Case,
    node_ids: &[u64],
    view: DiscoveryView,
    plan: &DiscoveryPlan,
    directory: &Path,
    options: StoreOptions,
) -> Result<StoredDiscoverySummary, Box<dyn std::error::Error>> {
    if node_ids.is_empty() {
        return Err(DiscoveryError::InvalidSelection.into());
    }
    let index = CaseIndex::new(case);
    let CaseSelection {
        nodes,
        identity,
        omitted_empty_sample_ids,
    } = select_nodes(
        case,
        node_ids,
        view,
        plan.max_input_bytes,
        &index.nodes,
        &index.blobs,
    )?;
    let samples = collect_samples(nodes, view, &index)?;
    let mut writer = StoreWriter::create(directory, options)?;
    let report = match identity {
        Some((direction, local_identity)) => discover_case_to_sink(
            &samples,
            plan,
            direction,
            local_identity,
            omitted_empty_sample_ids,
            &mut writer,
        )?,
        None => super::engine::discover_to_sink(&samples, plan, &mut writer)?,
    };
    writer.finish(&report)
}

/// Replay one candidate against the case's exact selected source mappings and context
///
/// # Errors
/// Rejects changed source bytes, plan identity, case context, or replayed output
pub fn replay_case_candidate(
    case: &Case,
    node_ids: &[u64],
    view: DiscoveryView,
    plan: &DiscoveryPlan,
    store: &DiscoveryResultStore,
    candidate_id: usize,
) -> Result<ReplayReceipt, Box<dyn std::error::Error>> {
    if node_ids.is_empty() {
        return Err(DiscoveryError::InvalidSelection.into());
    }
    let index = CaseIndex::new(case);
    let CaseSelection {
        nodes, identity, ..
    } = select_nodes(
        case,
        node_ids,
        view,
        plan.max_input_bytes,
        &index.nodes,
        &index.blobs,
    )?;
    let samples = collect_samples(nodes, view, &index)?;
    let replay_identity = if let Some((direction, local_identity)) = identity {
        let source_scope = samples
            .first()
            .map(|sample| sample.source_scope.clone())
            .ok_or(DiscoveryError::InvalidSelection)?;
        Some(super::model::DiscoveryIdentity {
            source_scope,
            direction,
            local_identity,
        })
    } else {
        None
    };
    replay_candidate_with_identity(
        &samples,
        plan,
        store,
        candidate_id,
        replay_identity.as_ref(),
    )
}

struct CaseIndex<'a> {
    nodes: HashMap<u64, &'a Node>,
    blobs: HashMap<&'a str, &'a Blob>,
    packet_episodes: HashMap<u64, Vec<u64>>,
    mapped_by: HashMap<u64, Vec<u64>>,
    contains: HashMap<u64, Vec<u64>>,
}

impl<'a> CaseIndex<'a> {
    fn new(case: &'a Case) -> Self {
        let nodes: HashMap<_, _> = case.nodes().iter().map(|node| (node.id, node)).collect();
        let blobs: HashMap<_, _> = case
            .blobs()
            .iter()
            .map(|blob| (blob.id.as_str(), blob))
            .collect();
        let episode_ids: HashSet<_> = case
            .nodes()
            .iter()
            .filter(|node| node.kind == "tcp_episode")
            .map(|node| node.id)
            .collect();
        let mut packet_episodes: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut mapped_by: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut contains: HashMap<u64, Vec<u64>> = HashMap::new();
        // Build child-oriented indexes once so selected samples do not rescan all graph edges
        for edge in case.edges() {
            match edge.relation.as_str() {
                "supports" if episode_ids.contains(&edge.to) => {
                    let members = packet_episodes.entry(edge.from).or_default();
                    if !members.contains(&edge.to) {
                        members.push(edge.to);
                    }
                }
                "mapped_by" => mapped_by.entry(edge.from).or_default().push(edge.to),
                "contains" => contains.entry(edge.to).or_default().push(edge.from),
                _ => {}
            }
        }
        Self {
            nodes,
            blobs,
            packet_episodes,
            mapped_by,
            contains,
        }
    }
}

struct CaseSelection {
    nodes: Vec<(u64, Option<u64>)>,
    identity: Option<(String, String)>,
    omitted_empty_sample_ids: Vec<u64>,
}

fn select_nodes(
    case: &Case,
    node_ids: &[u64],
    view: DiscoveryView,
    max_input_bytes: usize,
    nodes: &HashMap<u64, &Node>,
    blobs: &HashMap<&str, &Blob>,
) -> Result<CaseSelection, DiscoveryError> {
    let selected_cohort = if node_ids.len() == 1 {
        let Some(node_id) = node_ids.first().copied() else {
            return Err(DiscoveryError::InvalidSelection);
        };
        nodes
            .get(&node_id)
            .filter(|node| node.kind == "carrier_endpoint_cohort")
            .copied()
    } else {
        if node_ids.iter().any(|id| {
            nodes
                .get(id)
                .is_some_and(|node| node.kind == "carrier_endpoint_cohort")
        }) {
            return Err(DiscoveryError::InvalidSelection);
        }
        None
    };
    if let Some(cohort) = selected_cohort {
        let selection = cohort::members(case, cohort, nodes, blobs, view, max_input_bytes)?;
        return Ok(CaseSelection {
            nodes: selection.packets,
            identity: Some((selection.direction, selection.local_identity)),
            omitted_empty_sample_ids: selection.omitted_empty_sample_ids,
        });
    }
    if node_ids.len() > max_input_bytes {
        return Err(DiscoveryError::InputBudgetExceeded {
            observed: node_ids.len(),
            limit: max_input_bytes,
        });
    }
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(node_ids.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    selected.extend(node_ids.iter().map(|id| (*id, None)));
    Ok(CaseSelection {
        nodes: selected,
        identity: None,
        omitted_empty_sample_ids: Vec::new(),
    })
}

fn collect_samples<'a>(
    selected: Vec<(u64, Option<u64>)>,
    view: DiscoveryView,
    index: &CaseIndex<'a>,
) -> Result<Vec<DiscoverySample<'a>>, DiscoveryError> {
    let mut seen = HashSet::new();
    seen.try_reserve(selected.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(selected.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for (node_id, session_fallback) in selected {
        if !seen.insert(node_id) {
            return Err(DiscoveryError::InvalidSelection);
        }
        let mapped = mapped_node_indexed(node_id, index, view)?;
        let node = mapped.node;
        if !matches!(
            node.kind.as_str(),
            "packet" | "udp_payload" | "tcp_byte_run"
        ) {
            return Err(DiscoveryError::UnsupportedNodeKind { node_id });
        }
        let context = case_context(
            node,
            &index.nodes,
            &index.blobs,
            &index.packet_episodes,
            &index.contains,
            &mapped.mappings,
            session_fallback,
        )?;
        samples.push(DiscoverySample {
            id: node.id,
            session_id: context.session_id,
            sequence: context.sequence,
            source_scope: context.source_scope,
            direction: context.direction,
            local_identity: context.local_identity,
            bytes: mapped.bytes,
            mappings: mapped.mappings,
            ambiguity: if context.ambiguous {
                Ambiguity::MultipleCandidates
            } else {
                Ambiguity::None
            },
        });
    }
    Ok(samples)
}

/// One retained byte node with its validated, complete source mapping
pub struct MappedNode<'a> {
    /// Selected evidence graph node
    pub node: &'a Node,
    /// Exact selected bytes retained by the case
    pub bytes: &'a [u8],
    /// Exact mapping receipt covering every selected byte
    pub mappings: Vec<DiscoveryMapping>,
}

/// Resolve one case node and validate its complete mapping receipt
///
/// # Errors
/// Rejects missing bytes, mapping receipts, or inconsistent source ranges
pub fn mapped_node(case: &Case, node_id: u64) -> Result<MappedNode<'_>, DiscoveryError> {
    mapped_node_with_view(case, node_id, DiscoveryView::Bytes)
}

/// Resolve one selected view and validate its complete source mapping receipt
///
/// # Errors
/// Rejects missing bytes, malformed packet payloads, or inconsistent source ranges
pub fn mapped_node_with_view(
    case: &Case,
    node_id: u64,
    view: DiscoveryView,
) -> Result<MappedNode<'_>, DiscoveryError> {
    let index = CaseIndex::new(case);
    mapped_node_indexed(node_id, &index, view)
}

fn mapped_node_indexed<'a>(
    node_id: u64,
    index: &CaseIndex<'a>,
    view: DiscoveryView,
) -> Result<MappedNode<'a>, DiscoveryError> {
    let node = index
        .nodes
        .get(&node_id)
        .copied()
        .ok_or(DiscoveryError::MissingNode { node_id })?;
    let blob = node
        .blob
        .as_deref()
        .and_then(|blob_id| index.blobs.get(blob_id).copied())
        .ok_or(DiscoveryError::MissingBlob { node_id })?;
    let mappings = case_mappings(node, blob, index)?;
    apply_view(node_id, node, &blob.bytes, mappings, view)
}

fn apply_view<'a>(
    node_id: u64,
    node: &'a Node,
    bytes: &'a [u8],
    mappings: Vec<DiscoveryMapping>,
    view: DiscoveryView,
) -> Result<MappedNode<'a>, DiscoveryError> {
    let (bytes, mappings) = match view {
        DiscoveryView::Bytes => (bytes, mappings),
        DiscoveryView::Payload if node.kind == "packet" => {
            packet_payload_view(node_id, node, bytes, &mappings)?
        }
        DiscoveryView::Payload if is_payload_node_kind(&node.kind) => (bytes, mappings),
        DiscoveryView::Payload => {
            return Err(DiscoveryError::UnsupportedNodeKind { node_id });
        }
    };
    Ok(MappedNode {
        node,
        bytes,
        mappings,
    })
}

pub(super) fn is_payload_node_kind(kind: &str) -> bool {
    matches!(
        kind,
        "udp_payload" | "tcp_byte_run" | "http_body" | "ftp_data_candidate"
    )
}

fn packet_payload_view<'a>(
    node_id: u64,
    node: &Node,
    bytes: &'a [u8],
    mappings: &[DiscoveryMapping],
) -> Result<(&'a [u8], Vec<DiscoveryMapping>), DiscoveryError> {
    if node.kind != "packet"
        || node
            .details
            .get("link_type")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || node
            .details
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        || node
            .details
            .get("fragmented")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    {
        return Err(DiscoveryError::InvalidPacketPayload { node_id });
    }
    let frame =
        l2_core::decode(bytes).map_err(|_| DiscoveryError::InvalidPacketPayload { node_id })?;
    let ip = l2_discovery::ip_packet(&frame)
        .filter(|packet| !packet.fragmented)
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?;
    let transport = ip
        .transport
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?;
    if transport.payload.is_empty() {
        return Err(DiscoveryError::InvalidPacketPayload { node_id });
    }
    let frame_header_length = 14_usize
        .checked_add(
            frame
                .vlan_tags
                .len()
                .checked_mul(4)
                .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?,
        )
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?;
    let payload_start = frame_header_length
        .checked_add(transport.payload_offset)
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?;
    let payload_end = payload_start
        .checked_add(transport.payload.len())
        .filter(|end| *end <= bytes.len())
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id })?;
    let mut payload_mappings = Vec::new();
    for mapping in mappings {
        let length = usize::try_from(mapping.range.length)
            .map_err(|_| DiscoveryError::InvalidCaseMapping { node_id })?;
        let mapping_end = mapping
            .offset
            .checked_add(length)
            .ok_or(DiscoveryError::InvalidCaseMapping { node_id })?;
        let clipped_start = mapping.offset.max(payload_start);
        let clipped_end = mapping_end.min(payload_end);
        if clipped_start >= clipped_end {
            continue;
        }
        let source_delta = u64::try_from(clipped_start - mapping.offset)
            .map_err(|_| DiscoveryError::InvalidCaseMapping { node_id })?;
        payload_mappings.push(DiscoveryMapping {
            offset: clipped_start - payload_start,
            range: crate::evidence::SourceRange {
                source: mapping.range.source.clone(),
                packet: mapping.range.packet,
                offset: mapping
                    .range
                    .offset
                    .checked_add(source_delta)
                    .ok_or(DiscoveryError::InvalidCaseMapping { node_id })?,
                length: u64::try_from(clipped_end - clipped_start)
                    .map_err(|_| DiscoveryError::InvalidCaseMapping { node_id })?,
            },
        });
    }
    validate_mappings(node_id, transport.payload.len(), &payload_mappings)?;
    Ok((transport.payload, payload_mappings))
}
fn case_mappings(
    node: &Node,
    blob: &Blob,
    index: &CaseIndex<'_>,
) -> Result<Vec<DiscoveryMapping>, DiscoveryError> {
    let mappings = if let Some(receipt_id) = unique_mapping_receipt(node.id, index)? {
        let receipt_node = index
            .nodes
            .get(&receipt_id)
            .copied()
            .ok_or(DiscoveryError::InvalidCaseMapping { node_id: node.id })?;
        if receipt_node.kind != "byte_mapping_receipt" {
            return Err(DiscoveryError::InvalidCaseMapping { node_id: node.id });
        }
        let receipt_blob_id = receipt_node
            .blob
            .as_deref()
            .ok_or(DiscoveryError::InvalidCaseMapping { node_id: node.id })?;
        let receipt_blob = index
            .blobs
            .get(receipt_blob_id)
            .copied()
            .ok_or(DiscoveryError::InvalidCaseMapping { node_id: node.id })?;
        serde_json::from_slice::<Vec<DiscoveryMapping>>(&receipt_blob.bytes)
            .map_err(|_| DiscoveryError::InvalidCaseMapping { node_id: node.id })?
    } else if node.ranges.len() == 1
        && usize::try_from(node.ranges.first().map_or(0, |range| range.length)).ok()
            == Some(blob.bytes.len())
    {
        vec![DiscoveryMapping {
            offset: 0,
            range: node
                .ranges
                .first()
                .cloned()
                .ok_or(DiscoveryError::InvalidCaseMapping { node_id: node.id })?,
        }]
    } else {
        return Err(DiscoveryError::InvalidCaseMapping { node_id: node.id });
    };
    if mappings
        .iter()
        .map(|mapping| &mapping.range)
        .ne(node.ranges.iter())
    {
        return Err(DiscoveryError::InvalidCaseMapping { node_id: node.id });
    }
    validate_mappings(node.id, blob.bytes.len(), &mappings)?;
    Ok(mappings)
}

fn unique_mapping_receipt(
    node_id: u64,
    index: &CaseIndex<'_>,
) -> Result<Option<u64>, DiscoveryError> {
    let mut receipt_id = None;
    for candidate_id in index.mapped_by.get(&node_id).into_iter().flatten() {
        if receipt_id.is_some_and(|receipt_id| receipt_id != *candidate_id) {
            return Err(DiscoveryError::InvalidCaseMapping { node_id });
        }
        receipt_id = Some(*candidate_id);
    }
    Ok(receipt_id)
}
