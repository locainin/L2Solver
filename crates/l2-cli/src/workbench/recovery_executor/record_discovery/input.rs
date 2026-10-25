use super::super::RecoveryExecutionError;
use super::super::tcp_ancestry::{TcpAncestry, TcpAncestryError, TcpAncestryIndex};
use crate::workbench::framing_materialize::FramingSelectionBasis;
use l2_workbench::{
    evidence::{Case, EvidenceStatus, Node},
    protocol::{ByteRange, Direction, FramingKind, RecordSchemaProposalLimits},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_OMISSION_EXAMPLES: usize = 32;

#[derive(Clone, Default)]
pub(super) struct RecordDiscoveryInputOmissions {
    pub(super) total: usize,
    pub(super) reason_counts: BTreeMap<&'static str, usize>,
    pub(super) examples: Vec<Value>,
}

impl RecordDiscoveryInputOmissions {
    fn record(
        &mut self,
        node_id: u64,
        reason: &'static str,
        source_id: Option<&str>,
    ) -> Result<(), RecoveryExecutionError> {
        self.total = self
            .total
            .checked_add(1)
            .ok_or_else(|| invalid_work("record discovery omission count overflowed"))?;
        let count = self.reason_counts.entry(reason).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid_work("record discovery omission reason count overflowed"))?;
        if self.examples.len() < MAX_OMISSION_EXAMPLES {
            self.examples.try_reserve(1).map_err(|error| {
                operational("record discovery omission allocation failed", error)
            })?;
            self.examples.push(json!({
                "frame_node_id": node_id,
                "reason": reason,
                "source_id": source_id,
            }));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct RecordFrameInput {
    pub(super) node_id: u64,
    pub(super) blob_id: String,
    pub(super) receipt_node_id: u64,
    pub(super) session_node_id: u64,
    pub(super) session_id: u64,
    pub(super) frame_index: usize,
    pub(super) stream_range: ByteRange,
    pub(super) stream_offset: usize,
    pub(super) byte_length: usize,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct RecordCohortKey {
    pub(super) source_id: String,
    pub(super) scope_json: String,
    pub(super) endpoints_json: String,
    pub(super) direction: Direction,
    pub(super) framing_rule_json: String,
}

#[derive(Clone, Default)]
pub(in crate::workbench::recovery_executor) struct RecordDiscoveryPlan {
    pub(super) cohorts: BTreeMap<RecordCohortKey, Vec<RecordFrameInput>>,
    pub(super) cohort_omitted_frames: BTreeMap<RecordCohortKey, usize>,
    pub(super) omissions: BTreeMap<Option<String>, RecordDiscoveryInputOmissions>,
    pub(super) graph_work: usize,
}

#[cfg(test)]
pub(in crate::workbench::recovery_executor) fn collect_plan(
    case: &Case,
    limits: RecordSchemaProposalLimits,
) -> Result<RecordDiscoveryPlan, RecoveryExecutionError> {
    apply_input_limits(collect_input_plan(case)?, limits)
}

#[derive(Clone, Copy)]
enum OmissionKind {
    MissingSource,
    MixedSource,
    MissingBlob,
    InvalidFrame,
    MissingReceipt,
    AmbiguousReceipt,
    InvalidReceipt,
    IncompleteFraming,
    MissingSelectionEvidence,
    AmbiguousSelectionEvidence,
    InvalidSelectionEvidence,
    MissingInputLink,
    AmbiguousInputLink,
    MissingContext,
    AmbiguousContext,
    InvalidContext,
    DuplicateFrameIndex,
    SessionMessageCountLimit,
    SessionAggregateByteLimit,
    SessionMessageCountAndAggregateByteLimits,
}

impl OmissionKind {
    const fn name(self) -> &'static str {
        match self {
            Self::MissingSource => "missing_source",
            Self::MixedSource => "mixed_source",
            Self::MissingBlob => "missing_blob",
            Self::InvalidFrame => "invalid_frame",
            Self::MissingReceipt => "missing_materialization_receipt",
            Self::AmbiguousReceipt => "ambiguous_materialization_receipt",
            Self::InvalidReceipt => "invalid_materialization_receipt",
            Self::IncompleteFraming => "incomplete_framing",
            Self::MissingSelectionEvidence => "missing_framing_selection_evidence",
            Self::AmbiguousSelectionEvidence => "ambiguous_framing_selection_evidence",
            Self::InvalidSelectionEvidence => "invalid_framing_selection_evidence",
            Self::MissingInputLink => "missing_framing_input_link",
            Self::AmbiguousInputLink => "ambiguous_framing_input_link",
            Self::MissingContext => "missing_conversation_context",
            Self::AmbiguousContext => "ambiguous_conversation_context",
            Self::InvalidContext => "invalid_conversation_context",
            Self::DuplicateFrameIndex => "duplicate_receipt_frame_index",
            Self::SessionMessageCountLimit => "whole_session_exceeds_message_count_limit",
            Self::SessionAggregateByteLimit => "whole_session_exceeds_aggregate_byte_limit",
            Self::SessionMessageCountAndAggregateByteLimits => {
                "whole_session_exceeds_message_count_and_aggregate_byte_limits"
            }
        }
    }
}

type Omission = (Option<String>, OmissionKind);

struct ResolvedFrame {
    key: RecordCohortKey,
    input: RecordFrameInput,
}

struct FrameDescriptor<'a> {
    source_id: String,
    blob_id: &'a str,
    bytes: &'a [u8],
    input_node_id: u64,
    frame_index: usize,
    stream_range: ByteRange,
    framing_rule: FramingKind,
    normalized_rule: String,
    selection_basis: FramingSelectionBasis,
}

struct MaterializationEvidence {
    receipt_node_id: u64,
    stream_offset: usize,
}

struct ResolvedConversation {
    session_node_id: u64,
    session_id: u64,
    scope: Value,
    endpoints: Value,
    direction: Direction,
}

#[derive(Default)]
struct EdgeIndex {
    tcp_ancestry: TcpAncestryIndex,
    receipt_parents_by_frame: HashMap<u64, Vec<(u64, EvidenceStatus)>>,
    selection_report_parents_by_receipt: HashMap<u64, Vec<(u64, EvidenceStatus)>>,
    framing_input_link_counts: HashMap<(u64, u64), usize>,
}

pub(in crate::workbench::recovery_executor) fn collect_input_plan(
    case: &Case,
) -> Result<RecordDiscoveryPlan, RecoveryExecutionError> {
    let node_by_id = index_nodes(case)?;
    let blobs = index_blobs(case)?;
    let mut sources = HashSet::new();
    sources
        .try_reserve(case.sources().len())
        .map_err(|error| operational("record discovery source index allocation failed", error))?;
    sources.extend(case.sources().iter().map(|source| source.id.as_str()));
    let (edges, edge_scan_work) = index_edges(case, &node_by_id)?;
    let graph_work = graph_scan_work(case)?
        .checked_add(edge_scan_work)
        .ok_or_else(|| invalid_work("record discovery edge scan work overflowed"))?;
    let mut plan = RecordDiscoveryPlan {
        graph_work,
        ..RecordDiscoveryPlan::default()
    };
    let mut receipt_indexes = HashMap::<(u64, usize), u64>::new();
    receipt_indexes
        .try_reserve(case.nodes().len())
        .map_err(|error| operational("record discovery frame index allocation failed", error))?;
    let mut duplicate_frames = HashSet::new();
    duplicate_frames
        .try_reserve(case.nodes().len())
        .map_err(|error| {
            operational("record discovery duplicate index allocation failed", error)
        })?;
    let mut digest_cache = HashMap::<&str, String>::new();
    digest_cache
        .try_reserve(case.blobs().len())
        .map_err(|error| operational("record discovery digest cache allocation failed", error))?;
    let mut receipt_cache = HashMap::<&str, Result<Value, OmissionKind>>::new();
    receipt_cache
        .try_reserve(case.blobs().len())
        .map_err(|error| operational("record discovery receipt cache allocation failed", error))?;

    for frame in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
    {
        match collect_frame(
            frame,
            &node_by_id,
            &blobs,
            &sources,
            &edges,
            &mut digest_cache,
            &mut receipt_cache,
        ) {
            Ok(resolved) => {
                let index_key = (resolved.input.receipt_node_id, resolved.input.frame_index);
                if let Some(previous) = receipt_indexes.insert(index_key, frame.id) {
                    duplicate_frames.insert(previous);
                    duplicate_frames.insert(frame.id);
                }
                plan.cohorts
                    .entry(resolved.key)
                    .or_default()
                    .push(resolved.input);
            }
            Err((source_id, reason)) => {
                plan.record_omission(source_id.as_deref(), frame.id, reason)?;
            }
        }
    }

    remove_duplicate_frames(&mut plan, &duplicate_frames)?;
    sort_cohorts(&mut plan);
    Ok(plan)
}

pub(in crate::workbench::recovery_executor) fn apply_input_limits(
    mut plan: RecordDiscoveryPlan,
    limits: RecordSchemaProposalLimits,
) -> Result<RecordDiscoveryPlan, RecoveryExecutionError> {
    if limits.discovery.max_messages == 0 || limits.discovery.record_limits.max_input_bytes == 0 {
        return Err(RecoveryExecutionError::InvalidPolicy(
            "record discovery message and input limits must be positive".to_owned(),
        ));
    }
    cap_cohorts(&mut plan, limits)?;
    Ok(plan)
}

impl RecordDiscoveryPlan {
    fn record_omission(
        &mut self,
        source_id: Option<&str>,
        node_id: u64,
        reason: OmissionKind,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions
            .entry(source_id.map(str::to_owned))
            .or_default()
            .record(node_id, reason.name(), source_id)
    }
}

fn index_nodes(case: &Case) -> Result<HashMap<u64, &Node>, RecoveryExecutionError> {
    let mut nodes = HashMap::new();
    nodes
        .try_reserve(case.nodes().len())
        .map_err(|error| operational("record discovery node index allocation failed", error))?;
    nodes.extend(case.nodes().iter().map(|node| (node.id, node)));
    Ok(nodes)
}

fn index_blobs(
    case: &Case,
) -> Result<HashMap<&str, &l2_workbench::evidence::Blob>, RecoveryExecutionError> {
    let mut blobs = HashMap::new();
    blobs
        .try_reserve(case.blobs().len())
        .map_err(|error| operational("record discovery blob index allocation failed", error))?;
    blobs.extend(case.blobs().iter().map(|blob| (blob.id.as_str(), blob)));
    Ok(blobs)
}

fn index_edges(
    case: &Case,
    nodes: &HashMap<u64, &Node>,
) -> Result<(EdgeIndex, usize), RecoveryExecutionError> {
    let mut index = EdgeIndex::default();
    let mut scan_work = 0_usize;
    index
        .tcp_ancestry
        .reserve(case.edges().len())
        .map_err(|error| {
            operational(
                "record discovery TCP ancestry index allocation failed",
                error,
            )
        })?;
    index
        .receipt_parents_by_frame
        .try_reserve(case.edges().len())
        .map_err(|error| operational("record discovery receipt index allocation failed", error))?;
    index
        .selection_report_parents_by_receipt
        .try_reserve(case.edges().len())
        .map_err(|error| {
            operational("record discovery selection index allocation failed", error)
        })?;
    index
        .framing_input_link_counts
        .try_reserve(case.edges().len())
        .map_err(|error| {
            operational("record discovery input-link index allocation failed", error)
        })?;
    for edge in case.edges() {
        index
            .tcp_ancestry
            .index_edge(edge, nodes)
            .map_err(|error| {
                operational("record discovery TCP ancestry allocation failed", error)
            })?;
        scan_work = scan_work
            .checked_add(edge.relation.len())
            .and_then(|total| total.checked_add(edge.reason.len()))
            .and_then(|total| total.checked_add(17))
            .ok_or_else(|| invalid_work("record discovery edge scan work overflowed"))?;
        if edge.relation == "materialized" {
            let receipt_parents = index.receipt_parents_by_frame.entry(edge.to).or_default();
            receipt_parents.try_reserve(1).map_err(|error| {
                operational("record discovery receipt edge allocation failed", error)
            })?;
            receipt_parents.push((edge.from, edge.status));
        }
        if edge.relation == "framing_rule_selected_from" {
            let selection_parents = index
                .selection_report_parents_by_receipt
                .entry(edge.to)
                .or_default();
            selection_parents.try_reserve(1).map_err(|error| {
                operational("record discovery selection edge allocation failed", error)
            })?;
            selection_parents.push((edge.from, edge.status));
        }
        if edge.relation == "framing_tested_by" && edge.status == EvidenceStatus::Observed {
            let count = index
                .framing_input_link_counts
                .entry((edge.from, edge.to))
                .or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| invalid_work("record discovery input-link count overflowed"))?;
        }
    }
    Ok((index, scan_work))
}

fn graph_scan_work(case: &Case) -> Result<usize, RecoveryExecutionError> {
    let mut work = 0_usize;
    for node in case.nodes() {
        let details_bytes = serde_json::to_vec(&node.details)
            .map_err(|error| {
                operational("record discovery node details could not be counted", error)
            })?
            .len();
        let details_work = details_bytes
            .checked_mul(2)
            .ok_or_else(|| invalid_work("record discovery node details work overflowed"))?;
        let range_work = node
            .ranges
            .len()
            .checked_mul(64)
            .ok_or_else(|| invalid_work("record discovery range work overflowed"))?;
        work = work
            .checked_add(node.kind.len())
            .and_then(|total| total.checked_add(node.blob.as_deref().map_or(0, str::len)))
            .and_then(|total| total.checked_add(details_work))
            .and_then(|total| total.checked_add(range_work))
            .ok_or_else(|| invalid_work("record discovery node scan work overflowed"))?;
        for range in &node.ranges {
            work =
                work.checked_add(range.source.len().checked_mul(2).ok_or_else(|| {
                    invalid_work("record discovery source-range work overflowed")
                })?)
                .ok_or_else(|| {
                    invalid_work("record discovery source-range scan work overflowed")
                })?;
        }
    }
    for blob in case.blobs() {
        work = work
            .checked_add(blob.id.len())
            .and_then(|total| total.checked_add(blob.bytes.len()))
            .ok_or_else(|| invalid_work("record discovery blob index work overflowed"))?;
    }
    for source in case.sources() {
        work = work
            .checked_add(source.id.len())
            .ok_or_else(|| invalid_work("record discovery source index work overflowed"))?;
    }
    Ok(work)
}

fn collect_frame<'a>(
    frame: &'a Node,
    nodes: &HashMap<u64, &'a Node>,
    blobs: &HashMap<&'a str, &'a l2_workbench::evidence::Blob>,
    sources: &HashSet<&'a str>,
    edges: &EdgeIndex,
    digest_cache: &mut HashMap<&'a str, String>,
    receipt_cache: &mut HashMap<&'a str, Result<Value, OmissionKind>>,
) -> Result<ResolvedFrame, Omission> {
    let descriptor = inspect_frame(frame, blobs, sources, digest_cache)?;
    let materialization = validate_materialization(
        frame,
        &descriptor,
        nodes,
        blobs,
        edges,
        digest_cache,
        receipt_cache,
    )?;
    let ancestry = edges
        .tcp_ancestry
        .resolve_run(descriptor.input_node_id)
        .map_err(|error| {
            let reason = match error {
                TcpAncestryError::Missing => OmissionKind::MissingContext,
                TcpAncestryError::Ambiguous => OmissionKind::AmbiguousContext,
                TcpAncestryError::Invalid => OmissionKind::InvalidContext,
            };
            (Some(descriptor.source_id.clone()), reason)
        })?;
    let conversation = resolve_conversation(nodes, ancestry).ok_or_else(|| {
        (
            Some(descriptor.source_id.clone()),
            OmissionKind::InvalidContext,
        )
    })?;
    let scope_json = serde_json::to_string(&conversation.scope).map_err(|_| {
        (
            Some(descriptor.source_id.clone()),
            OmissionKind::InvalidContext,
        )
    })?;
    let endpoints_json = serde_json::to_string(&conversation.endpoints).map_err(|_| {
        (
            Some(descriptor.source_id.clone()),
            OmissionKind::InvalidContext,
        )
    })?;
    let key = RecordCohortKey {
        source_id: descriptor.source_id,
        scope_json,
        endpoints_json,
        direction: conversation.direction,
        framing_rule_json: descriptor.normalized_rule,
    };
    Ok(ResolvedFrame {
        key,
        input: RecordFrameInput {
            node_id: frame.id,
            blob_id: descriptor.blob_id.to_owned(),
            receipt_node_id: materialization.receipt_node_id,
            session_node_id: conversation.session_node_id,
            session_id: conversation.session_id,
            frame_index: descriptor.frame_index,
            stream_range: descriptor.stream_range,
            stream_offset: materialization.stream_offset,
            byte_length: descriptor.bytes.len(),
        },
    })
}

fn inspect_frame<'a>(
    frame: &'a Node,
    blobs: &HashMap<&'a str, &'a l2_workbench::evidence::Blob>,
    sources: &HashSet<&'a str>,
    digest_cache: &mut HashMap<&'a str, String>,
) -> Result<FrameDescriptor<'a>, Omission> {
    let source_id = exact_source(frame).map_err(|reason| (None, reason))?;
    let reject = |reason| (Some(source_id.clone()), reason);
    if !sources.contains(source_id.as_str()) {
        return Err(reject(OmissionKind::MissingSource));
    }
    let frame_blob_id = frame
        .blob
        .as_deref()
        .ok_or_else(|| reject(OmissionKind::MissingBlob))?;
    let frame_blob = blobs
        .get(frame_blob_id)
        .ok_or_else(|| reject(OmissionKind::MissingBlob))?;
    let frame_digest = digest_cache
        .entry(frame_blob_id)
        .or_insert_with(|| l2_workbench::sha256(&frame_blob.bytes));
    if frame_blob.bytes.is_empty()
        || frame.details.get("sha256").and_then(Value::as_str) != Some(frame_digest.as_str())
    {
        return Err(reject(OmissionKind::InvalidFrame));
    }
    let input_node_id = frame
        .details
        .get("input_node")
        .and_then(Value::as_u64)
        .ok_or_else(|| reject(OmissionKind::InvalidFrame))?;
    let frame_index = frame
        .details
        .get("frame_index")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| reject(OmissionKind::InvalidFrame))?;
    let stream_range: ByteRange = serde_json::from_value(
        frame
            .details
            .get("stream_range")
            .cloned()
            .ok_or_else(|| reject(OmissionKind::InvalidFrame))?,
    )
    .map_err(|_| reject(OmissionKind::InvalidFrame))?;
    let framing_rule: FramingKind = serde_json::from_value(
        frame
            .details
            .get("framing_rule")
            .cloned()
            .ok_or_else(|| reject(OmissionKind::InvalidFrame))?,
    )
    .map_err(|_| reject(OmissionKind::InvalidFrame))?;
    if frame.details.get("framing_rule") != Some(&json!(framing_rule)) {
        return Err(reject(OmissionKind::InvalidFrame));
    }
    let normalized_rule =
        serde_json::to_string(&framing_rule).map_err(|_| reject(OmissionKind::InvalidFrame))?;
    let selection_basis =
        parse_selection_basis(frame.details.get("selection_basis")).map_err(reject)?;

    Ok(FrameDescriptor {
        source_id,
        blob_id: frame_blob_id,
        bytes: &frame_blob.bytes,
        input_node_id,
        frame_index,
        stream_range,
        framing_rule,
        normalized_rule,
        selection_basis,
    })
}

fn validate_materialization<'a>(
    frame: &Node,
    descriptor: &FrameDescriptor<'_>,
    nodes: &HashMap<u64, &'a Node>,
    blobs: &HashMap<&'a str, &'a l2_workbench::evidence::Blob>,
    edges: &EdgeIndex,
    digest_cache: &mut HashMap<&'a str, String>,
    receipt_cache: &mut HashMap<&'a str, Result<Value, OmissionKind>>,
) -> Result<MaterializationEvidence, Omission> {
    let (receipt_node_id, receipt_node, receipt) =
        materialization_receipt(frame.id, descriptor, nodes, blobs, edges, receipt_cache)?;
    let input = validate_materialized_input(
        descriptor,
        receipt_node,
        receipt,
        nodes,
        blobs,
        digest_cache,
    )?;
    let matching_input_edges = edges
        .framing_input_link_counts
        .get(&(descriptor.input_node_id, receipt_node_id))
        .copied()
        .unwrap_or_default();
    if matching_input_edges != 1 {
        return Err((
            Some(descriptor.source_id.clone()),
            if matching_input_edges == 0 {
                OmissionKind::MissingInputLink
            } else {
                OmissionKind::AmbiguousInputLink
            },
        ));
    }
    Ok(MaterializationEvidence {
        receipt_node_id,
        stream_offset: input.stream_offset,
    })
}

fn materialization_receipt<'case, 'cache>(
    frame_id: u64,
    descriptor: &FrameDescriptor<'_>,
    nodes: &HashMap<u64, &'case Node>,
    blobs: &HashMap<&'case str, &'case l2_workbench::evidence::Blob>,
    edges: &EdgeIndex,
    receipt_cache: &'cache mut HashMap<&'case str, Result<Value, OmissionKind>>,
) -> Result<(u64, &'case Node, &'cache Value), Omission> {
    let reject = |reason| (Some(descriptor.source_id.clone()), reason);
    let receipts = edges
        .receipt_parents_by_frame
        .get(&frame_id)
        .map_or(&[][..], Vec::as_slice);
    let [receipt_edge] = receipts else {
        return Err(reject(if receipts.is_empty() {
            OmissionKind::MissingReceipt
        } else {
            OmissionKind::AmbiguousReceipt
        }));
    };
    if receipt_edge.1 != EvidenceStatus::Observed {
        return Err(reject(OmissionKind::InvalidReceipt));
    }
    let receipt_node_id = receipt_edge.0;
    let receipt_node = *nodes
        .get(&receipt_node_id)
        .filter(|node| node.kind == "custom_protocol_framing_receipt")
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let receipt_blob = blobs
        .get(receipt_blob_id)
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    if !receipt_cache.contains_key(receipt_blob_id) {
        let value =
            serde_json::from_slice(&receipt_blob.bytes).map_err(|_| OmissionKind::InvalidReceipt);
        receipt_cache.insert(receipt_blob_id, value);
    }
    let receipt = receipt_cache
        .get(receipt_blob_id)
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?
        .as_ref()
        .map_err(|reason| reject(*reason))?;
    let receipt_basis = parse_selection_basis(receipt.get("selection_basis")).map_err(reject)?;
    let receipt_details_basis =
        parse_selection_basis(receipt_node.details.get("selection_basis")).map_err(reject)?;
    if receipt_basis != descriptor.selection_basis
        || receipt_details_basis != descriptor.selection_basis
    {
        return Err(reject(OmissionKind::InvalidSelectionEvidence));
    }
    validate_selection_provenance(descriptor.selection_basis, receipt_node_id, nodes, edges)
        .map_err(reject)?;
    Ok((receipt_node_id, receipt_node, receipt))
}

fn validate_selection_provenance(
    basis: FramingSelectionBasis,
    receipt_node_id: u64,
    nodes: &HashMap<u64, &Node>,
    edges: &EdgeIndex,
) -> Result<(), OmissionKind> {
    let parents = edges
        .selection_report_parents_by_receipt
        .get(&receipt_node_id)
        .map_or(&[][..], Vec::as_slice);
    match basis {
        FramingSelectionBasis::CallerSupplied {} if parents.is_empty() => Ok(()),
        FramingSelectionBasis::CallerSupplied {} => Err(OmissionKind::InvalidSelectionEvidence),
        FramingSelectionBasis::Discovered { report_node }
        | FramingSelectionBasis::CallerAndDiscovered { report_node } => match parents {
            [] => Err(OmissionKind::MissingSelectionEvidence),
            [(parent_node, EvidenceStatus::Observed)] if *parent_node == report_node => nodes
                .get(&report_node)
                .is_some_and(|node| node.kind == "recovery_framing_discovery_report")
                .then_some(())
                .ok_or(OmissionKind::InvalidSelectionEvidence),
            [_] => Err(OmissionKind::InvalidSelectionEvidence),
            _ => Err(OmissionKind::AmbiguousSelectionEvidence),
        },
    }
}

struct MaterializedInput {
    stream_offset: usize,
}

struct ReceiptSummary {
    status: Value,
    input_length: u64,
    frame_count: usize,
    frame_count_u64: u64,
}

fn validate_materialized_input<'a>(
    descriptor: &FrameDescriptor<'_>,
    receipt_node: &Node,
    receipt: &Value,
    nodes: &HashMap<u64, &'a Node>,
    blobs: &HashMap<&'a str, &'a l2_workbench::evidence::Blob>,
    digest_cache: &mut HashMap<&'a str, String>,
) -> Result<MaterializedInput, Omission> {
    let reject = |reason| (Some(descriptor.source_id.clone()), reason);
    let input = nodes
        .get(&descriptor.input_node_id)
        .filter(|node| node.kind == "tcp_byte_run")
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let input_blob_id = input
        .blob
        .as_deref()
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let input_blob = blobs
        .get(input_blob_id)
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let input_digest = digest_cache
        .entry(input_blob_id)
        .or_insert_with(|| l2_workbench::sha256(&input_blob.bytes));
    let input_length = input_blob.bytes.len();
    let stream_offset = input
        .details
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let receipt_summary = receipt_summary(descriptor, receipt, input_length)?;
    if input.details.get("length").and_then(Value::as_u64) != Some(receipt_summary.input_length)
        || input.details.get("generation_ambiguous") != Some(&Value::Bool(false))
        || descriptor.stream_range.start >= descriptor.stream_range.end
        || descriptor
            .stream_range
            .end
            .checked_sub(descriptor.stream_range.start)
            != Some(descriptor.bytes.len())
        || input_blob
            .bytes
            .get(descriptor.stream_range.start..descriptor.stream_range.end)
            != Some(descriptor.bytes)
        || receipt_node.details.get("receipt_schema_version") != Some(&json!(1))
        || receipt_node.details.get("representation") != Some(&json!("json_blob"))
        || receipt.get("schema_version") != Some(&json!(1))
        || receipt.get("input_node").and_then(Value::as_u64) != Some(descriptor.input_node_id)
        || receipt.get("input_kind") != Some(&json!("tcp_byte_run"))
        || receipt.get("input_blob") != Some(&json!(input_blob_id))
        || receipt.get("input_length").and_then(Value::as_u64) != Some(receipt_summary.input_length)
        || receipt.get("input_sha256").and_then(Value::as_str) != Some(input_digest.as_str())
        || receipt.get("framing_rule") != Some(&json!(descriptor.framing_rule))
        || receipt_node.details.get("input_node") != Some(&json!(descriptor.input_node_id))
        || receipt_node.details.get("input_length") != Some(&json!(input_length))
        || receipt_node
            .details
            .get("input_sha256")
            .and_then(Value::as_str)
            != Some(input_digest.as_str())
        || receipt_node.details.get("framing_rule") != Some(&json!(descriptor.framing_rule))
        || receipt_node.details.get("status") != Some(&receipt_summary.status)
        || receipt.get("frame_count").and_then(Value::as_u64)
            != Some(receipt_summary.frame_count_u64)
        || receipt_node
            .details
            .get("frame_count")
            .and_then(Value::as_u64)
            != Some(receipt_summary.frame_count_u64)
        || descriptor.frame_index >= receipt_summary.frame_count
    {
        return Err(reject(OmissionKind::InvalidReceipt));
    }
    if !source_matches(input, &descriptor.source_id) {
        return Err(reject(OmissionKind::InvalidReceipt));
    }
    if receipt_summary.status != json!("complete") {
        return Err(reject(OmissionKind::IncompleteFraming));
    }
    Ok(MaterializedInput { stream_offset })
}

fn receipt_summary(
    descriptor: &FrameDescriptor<'_>,
    receipt: &Value,
    input_length: usize,
) -> Result<ReceiptSummary, Omission> {
    let reject = |reason| (Some(descriptor.source_id.clone()), reason);
    let status = match receipt.get("status").and_then(Value::as_str) {
        Some(status @ ("complete" | "incomplete_tail" | "invalid_candidate")) => {
            Value::String(status.to_owned())
        }
        _ => return Err(reject(OmissionKind::InvalidReceipt)),
    };
    let input_length =
        u64::try_from(input_length).map_err(|_| reject(OmissionKind::InvalidReceipt))?;
    let frame_count_u64 = receipt
        .get("frame_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| reject(OmissionKind::InvalidReceipt))?;
    let frame_count =
        usize::try_from(frame_count_u64).map_err(|_| reject(OmissionKind::InvalidReceipt))?;
    Ok(ReceiptSummary {
        status,
        input_length,
        frame_count,
        frame_count_u64,
    })
}

fn source_matches(node: &Node, expected: &str) -> bool {
    let mut sources = node.ranges.iter().map(|range| range.source.as_str());
    sources.next() == Some(expected) && sources.all(|source| source == expected)
}

fn resolve_conversation(
    nodes: &HashMap<u64, &Node>,
    ancestry: TcpAncestry,
) -> Option<ResolvedConversation> {
    let direction = nodes.get(&ancestry.direction_node_id)?;
    let episode = nodes.get(&ancestry.episode_node_id)?;
    if episode.details.get("generation_ambiguous") != Some(&Value::Bool(false))
        || direction.details.get("sequence_ambiguous") != Some(&Value::Bool(false))
    {
        return None;
    }
    let endpoints = episode.details.get("endpoints")?.clone();
    let [first, second] = endpoints.as_array()?.as_slice() else {
        return None;
    };
    if !valid_endpoint(first) || !valid_endpoint(second) || first == second {
        return None;
    }
    let source = direction.details.get("source")?;
    let destination = direction.details.get("destination")?;
    let direction = if source == first && destination == second {
        Direction::FirstToSecond
    } else if source == second && destination == first {
        Direction::SecondToFirst
    } else {
        return None;
    };
    let scope = episode.details.get("scope")?.clone();
    if scope.is_null() {
        return None;
    }
    let session_id = episode.details.get("first_packet")?.as_u64()?;
    // Episode node identity keeps repeated first-packet labels in separate conversations
    Some(ResolvedConversation {
        session_node_id: ancestry.episode_node_id,
        session_id,
        scope,
        endpoints,
        direction,
    })
}

fn valid_endpoint(value: &Value) -> bool {
    let Some(address) = value.get("address") else {
        return false;
    };
    let valid_address = address.as_str().map_or_else(
        || serde_json::from_value::<l2_discovery::NetworkAddress>(address.clone()).is_ok(),
        |address| !address.is_empty(),
    );
    let Some(port) = value.get("port").and_then(Value::as_u64) else {
        return false;
    };
    valid_address && u16::try_from(port).is_ok()
}

fn exact_source(node: &Node) -> Result<String, OmissionKind> {
    let mut sources = node.ranges.iter().map(|range| range.source.as_str());
    let Some(source) = sources.next() else {
        return Err(OmissionKind::MissingSource);
    };
    if sources.any(|candidate| candidate != source) {
        return Err(OmissionKind::MixedSource);
    }
    Ok(source.to_owned())
}

fn parse_selection_basis(value: Option<&Value>) -> Result<FramingSelectionBasis, OmissionKind> {
    let value = value.ok_or(OmissionKind::MissingSelectionEvidence)?;
    let basis: FramingSelectionBasis = serde_json::from_value(value.clone())
        .map_err(|_| OmissionKind::InvalidSelectionEvidence)?;
    let canonical =
        serde_json::to_value(basis).map_err(|_| OmissionKind::InvalidSelectionEvidence)?;
    if canonical != *value || basis.report_node() == Some(0) {
        return Err(OmissionKind::InvalidSelectionEvidence);
    }
    Ok(basis)
}

fn remove_duplicate_frames(
    plan: &mut RecordDiscoveryPlan,
    duplicate_ids: &HashSet<u64>,
) -> Result<(), RecoveryExecutionError> {
    if duplicate_ids.is_empty() {
        return Ok(());
    }
    let mut omitted = Vec::new();
    omitted.try_reserve(duplicate_ids.len()).map_err(|error| {
        operational(
            "record discovery duplicate omission allocation failed",
            error,
        )
    })?;
    for (key, inputs) in &mut plan.cohorts {
        let mut retained = Vec::new();
        retained.try_reserve_exact(inputs.len()).map_err(|error| {
            operational("record discovery retained input allocation failed", error)
        })?;
        for input in inputs.drain(..) {
            if duplicate_ids.contains(&input.node_id) {
                omitted.push((key.source_id.clone(), input.node_id));
            } else {
                retained.push(input);
            }
        }
        *inputs = retained;
    }
    for (source_id, node_id) in omitted {
        plan.record_omission(Some(&source_id), node_id, OmissionKind::DuplicateFrameIndex)?;
    }
    Ok(())
}

fn cap_cohorts(
    plan: &mut RecordDiscoveryPlan,
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecoveryExecutionError> {
    let mut omitted_inputs = Vec::new();
    let input_count = plan
        .cohorts
        .values()
        .try_fold(0_usize, |total, inputs| total.checked_add(inputs.len()))
        .ok_or_else(|| invalid_work("record discovery input count overflowed"))?;
    omitted_inputs
        .try_reserve(input_count)
        .map_err(|error| operational("record discovery capped-input allocation failed", error))?;
    for (key, inputs) in &mut plan.cohorts {
        inputs.sort_by_key(|input| {
            (
                input.session_id,
                input.session_node_id,
                input.stream_offset,
                input.stream_range.start,
                input.frame_index,
                input.node_id,
            )
        });
        let maximum_messages = limits
            .discovery
            .max_messages
            .min(limits.discovery.record_limits.max_records);
        let maximum_bytes = limits.discovery.record_limits.max_input_bytes;
        let mut kept = Vec::new();
        kept.try_reserve_exact(inputs.len())
            .map_err(|error| operational("record discovery input allocation failed", error))?;
        let mut retained_messages = 0_usize;
        let mut retained_bytes = 0_usize;
        let mut omitted = 0_usize;
        for session in inputs.chunk_by(|left, right| left.session_node_id == right.session_node_id)
        {
            let session_messages = session.len();
            let session_bytes = session
                .iter()
                .try_fold(0_usize, |total, input| total.checked_add(input.byte_length))
                .ok_or_else(|| invalid_work("record discovery session byte count overflowed"))?;
            let next_messages =
                retained_messages
                    .checked_add(session_messages)
                    .ok_or_else(|| {
                        invalid_work("record discovery retained message count overflowed")
                    })?;
            let next_bytes = retained_bytes
                .checked_add(session_bytes)
                .ok_or_else(|| invalid_work("record discovery retained byte count overflowed"))?;
            let fits_messages = next_messages <= maximum_messages;
            let fits_bytes = next_bytes <= maximum_bytes;
            if fits_messages && fits_bytes {
                retained_messages = next_messages;
                retained_bytes = next_bytes;
                kept.extend(session.iter().cloned());
            } else {
                let reason = if !fits_messages && !fits_bytes {
                    OmissionKind::SessionMessageCountAndAggregateByteLimits
                } else if !fits_messages {
                    OmissionKind::SessionMessageCountLimit
                } else {
                    OmissionKind::SessionAggregateByteLimit
                };
                omitted = omitted.checked_add(session_messages).ok_or_else(|| {
                    invalid_work("record discovery omitted-frame count overflowed")
                })?;
                for input in session {
                    omitted_inputs.push((key.source_id.clone(), input.node_id, reason));
                }
            }
        }
        *inputs = kept;
        if omitted > 0 {
            plan.cohort_omitted_frames.insert(key.clone(), omitted);
        }
    }
    for (source_id, node_id, reason) in omitted_inputs {
        plan.record_omission(Some(&source_id), node_id, reason)?;
    }
    Ok(())
}

fn sort_cohorts(plan: &mut RecordDiscoveryPlan) {
    for inputs in plan.cohorts.values_mut() {
        inputs.sort_by_key(|input| {
            (
                input.session_id,
                input.session_node_id,
                input.stream_offset,
                input.stream_range.start,
                input.frame_index,
                input.node_id,
            )
        });
    }
    plan.cohorts.retain(|_, inputs| !inputs.is_empty());
}

fn operational(
    message: &'static str,
    source: impl std::error::Error + 'static,
) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: l2_workbench::recovery::RecoveryStage::RecordDiscovery,
        source: Box::new(RecordDiscoveryInputError {
            message,
            source: Box::new(source),
        }),
    }
}

fn invalid_work(message: &'static str) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(message.to_owned())
}

#[derive(Debug)]
struct RecordDiscoveryInputError {
    message: &'static str,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for RecordDiscoveryInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.message, self.source)
    }
}

impl std::error::Error for RecordDiscoveryInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_record_ancestry.rs"]
mod ancestry_tests;
