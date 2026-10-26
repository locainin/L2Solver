use super::super::RecoveryExecutionError;
use super::super::tcp_ancestry::{TcpAncestry, TcpAncestryError, TcpAncestryIndex};
use l2_workbench::{
    evidence::{Case, CaseIdentity, Edge, EvidenceStatus, Node},
    protocol::{ByteRange as StreamRange, Direction, MessageContext, ProtocolLimits},
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug)]
enum InputOmissionKind {
    MissingSource,
    MixedSource,
    MissingBlob,
    InvalidRun,
    EmptyRun,
    MissingContext,
    AmbiguousContext,
    InvalidContext,
    GenerationAmbiguous,
    RunTooLarge,
    TooManySamples,
    TotalBytes,
}

impl InputOmissionKind {
    const fn name(self) -> &'static str {
        match self {
            Self::MissingSource => "missing_source",
            Self::MixedSource => "mixed_source",
            Self::MissingBlob => "missing_blob",
            Self::InvalidRun => "invalid_run",
            Self::EmptyRun => "empty_run",
            Self::MissingContext => "missing_context",
            Self::AmbiguousContext => "ambiguous_context",
            Self::InvalidContext => "invalid_context",
            Self::GenerationAmbiguous => "generation_ambiguous",
            Self::RunTooLarge => "run_too_large",
            Self::TooManySamples => "too_many_samples",
            Self::TotalBytes => "total_bytes",
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct FramingInputOmissions {
    pub(super) counts: BTreeMap<&'static str, usize>,
    pub(super) total: usize,
}

impl FramingInputOmissions {
    fn record(&mut self, kind: InputOmissionKind) -> Result<(), RecoveryExecutionError> {
        let count = self.counts.entry(kind.name()).or_default();
        *count = count.checked_add(1).ok_or_else(graph_work_overflow)?;
        self.total = self.total.checked_add(1).ok_or_else(graph_work_overflow)?;
        Ok(())
    }
}

#[derive(Clone)]
pub(in crate::workbench::recovery_executor) struct FramingInput {
    pub(in crate::workbench::recovery_executor) node_id: u64,
    pub(in crate::workbench::recovery_executor) blob_id: String,
    pub(in crate::workbench::recovery_executor) source_id: String,
    pub(in crate::workbench::recovery_executor) context: MessageContext,
    pub(in crate::workbench::recovery_executor) direction_node_id: u64,
    pub(in crate::workbench::recovery_executor) direction_contains_status: EvidenceStatus,
    pub(in crate::workbench::recovery_executor) episode_node_id: u64,
    pub(in crate::workbench::recovery_executor) episode_contains_status: EvidenceStatus,
    // Episode identity prevents unrelated conversations from sharing evidence
    // First-packet order keeps discovery partitions stable across insertion order
    pub(in crate::workbench::recovery_executor) session_order: u64,
    pub(in crate::workbench::recovery_executor) stream_offset: usize,
    pub(in crate::workbench::recovery_executor) byte_length: usize,
    pub(in crate::workbench::recovery_executor) start_known: bool,
    pub(in crate::workbench::recovery_executor) end_observed: bool,
}

#[derive(Default)]
pub(in crate::workbench::recovery_executor) struct FramingDiscoveryPlan {
    pub(super) cohorts: BTreeMap<FramingCohortKey, Vec<FramingInput>>,
    pub(super) omissions: BTreeMap<Option<String>, FramingInputOmissions>,
    pub(super) graph_work: usize,
    native_http_coverage_by_run: HashMap<u64, NativeHttpCoverage>,
    case_identity: Option<CaseIdentity>,
    node_high_water_mark: usize,
    edge_high_water_mark: usize,
    blob_high_water_mark: usize,
}

impl FramingDiscoveryPlan {
    pub(in crate::workbench::recovery_executor) fn cohort_inputs(
        &self,
    ) -> impl Iterator<Item = (&FramingCohortKey, &FramingInput)> {
        self.cohorts
            .iter()
            .flat_map(|(key, inputs)| inputs.iter().map(move |input| (key, input)))
    }

    pub(super) fn matches_case(&self, case: &Case) -> bool {
        let has_same_case_identity = self
            .case_identity
            .as_ref()
            .is_some_and(|identity| identity.identifies(case));
        if !has_same_case_identity || case.blobs().len() < self.blob_high_water_mark {
            return false;
        }

        let Some(appended_nodes) = case.nodes().get(self.node_high_water_mark..) else {
            return false;
        };
        if appended_nodes
            .iter()
            .any(|node| node.kind == "tcp_byte_run")
        {
            return false;
        }

        let Some(appended_edges) = case.edges().get(self.edge_high_water_mark..) else {
            return false;
        };
        !appended_edges
            .iter()
            .any(|edge| appended_edge_changes_framing_inputs(case, edge, self.node_high_water_mark))
    }

    pub(in crate::workbench::recovery_executor) fn native_http_message_ranges(
        &self,
        run_node_id: u64,
    ) -> Option<&[StreamRange]> {
        self.native_http_coverage_by_run
            .get(&run_node_id)
            .map(|coverage| coverage.message_ranges.as_slice())
    }

    pub(in crate::workbench::recovery_executor) const fn native_http_coverage_by_run(
        &self,
    ) -> &HashMap<u64, NativeHttpCoverage> {
        &self.native_http_coverage_by_run
    }

    pub(in crate::workbench::recovery_executor) fn source_eligibility_omissions(
        &self,
        source_id: &str,
    ) -> usize {
        for (source, omission) in &self.omissions {
            if source.as_deref() == Some(source_id) {
                return omission.total;
            }
        }
        0
    }
}

#[derive(Clone, Debug)]
pub(in crate::workbench::recovery_executor) struct NativeHttpCoverage {
    pub(in crate::workbench::recovery_executor) application_checks_node_id: u64,
    pub(in crate::workbench::recovery_executor) message_candidate_node_ids: Vec<u64>,
    pub(in crate::workbench::recovery_executor) message_ranges: Vec<StreamRange>,
}

#[derive(Default)]
struct NativeHttpEvidenceIndex {
    application_checks_by_run: HashMap<u64, Vec<u64>>,
    message_candidates_by_run: HashMap<u64, Vec<u64>>,
}

fn appended_edge_changes_framing_inputs(
    case: &Case,
    edge: &Edge,
    node_high_water_mark: usize,
) -> bool {
    let nodes = case.nodes();
    let parent = nodes
        .binary_search_by_key(&edge.from, |node| node.id)
        .ok()
        .and_then(|index| nodes.get(index));
    let child = nodes
        .binary_search_by_key(&edge.to, |node| node.id)
        .ok()
        .and_then(|index| nodes.get(index).map(|node| (index, node)));
    let (Some(parent), Some((child_index, child))) = (parent, child) else {
        return false;
    };
    if matches!(
        (
            edge.relation.as_str(),
            parent.kind.as_str(),
            child.kind.as_str()
        ),
        ("tested_by", "tcp_byte_run", "application_checks")
            | ("parsed_as", "tcp_byte_run", "http_message_candidate")
    ) {
        return true;
    }
    if edge.relation != "contains" {
        return false;
    }
    if child_index >= node_high_water_mark {
        return false;
    }

    matches!(
        (parent.kind.as_str(), child.kind.as_str()),
        ("tcp_direction", "tcp_byte_run") | ("tcp_episode", "tcp_direction")
    )
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::workbench::recovery_executor) struct FramingCohortKey {
    pub(in crate::workbench::recovery_executor) source_id: String,
    pub(in crate::workbench::recovery_executor) scope: String,
    pub(in crate::workbench::recovery_executor) endpoint_pair: String,
    pub(in crate::workbench::recovery_executor) direction: Direction,
}

impl FramingDiscoveryPlan {
    fn record_omission(
        &mut self,
        source_id: Option<&str>,
        kind: InputOmissionKind,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions
            .entry(source_id.map(str::to_owned))
            .or_default()
            .record(kind)
    }
}

pub(in crate::workbench::recovery_executor) fn collect_plan(
    case: &Case,
    limits: ProtocolLimits,
) -> Result<FramingDiscoveryPlan, RecoveryExecutionError> {
    let node_by_id = case
        .nodes()
        .iter()
        .map(|node| (node.id, node))
        .collect::<HashMap<_, _>>();
    let blobs = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob))
        .collect::<HashMap<_, _>>();
    let ancestry = TcpAncestryIndex::index_case(case, &node_by_id).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: l2_workbench::recovery::RecoveryStage::FramingDiscovery,
            source: Box::new(source),
        }
    })?;
    let (graph_work, native_http_evidence) = case_graph_work(case, &node_by_id)?;
    let mut plan = FramingDiscoveryPlan {
        graph_work,
        case_identity: Some(case.identity()),
        node_high_water_mark: case.nodes().len(),
        edge_high_water_mark: case.edges().len(),
        blob_high_water_mark: case.blobs().len(),
        ..FramingDiscoveryPlan::default()
    };
    for node in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "tcp_byte_run")
    {
        match collect_tcp_run(node, &node_by_id, &blobs, &ancestry, limits) {
            Ok((key, input)) => plan.cohorts.entry(key).or_default().push(input),
            Err((source_id, reason)) => {
                plan.record_omission(source_id.as_deref(), reason)?;
            }
        }
    }
    sort_and_cap_cohorts(&mut plan, limits)?;
    index_native_http_message_ranges(&blobs, &native_http_evidence, &node_by_id, &mut plan)?;
    Ok(plan)
}

fn index_native_http_message_ranges(
    blobs: &HashMap<&str, &l2_workbench::evidence::Blob>,
    evidence: &NativeHttpEvidenceIndex,
    nodes: &HashMap<u64, &Node>,
    plan: &mut FramingDiscoveryPlan,
) -> Result<(), RecoveryExecutionError> {
    let run_count = plan.cohorts.values().try_fold(0_usize, |count, inputs| {
        count
            .checked_add(inputs.len())
            .ok_or_else(graph_work_overflow)
    })?;
    plan.native_http_coverage_by_run
        .try_reserve(run_count)
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: l2_workbench::recovery::RecoveryStage::FramingDiscovery,
            source: Box::new(source),
        })?;
    for input in plan.cohorts.values().flatten() {
        let blob = blobs
            .get(input.blob_id.as_str())
            .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?;
        if let Some(coverage) = native_http_coverage_for_run(
            input.node_id,
            input.byte_length,
            input.start_known,
            blob.bytes.len(),
            evidence,
            nodes,
        ) {
            plan.native_http_coverage_by_run
                .insert(input.node_id, coverage);
        }
    }
    Ok(())
}

fn native_http_coverage_for_run(
    run_node_id: u64,
    expected_length: usize,
    start_known: bool,
    actual_length: usize,
    evidence: &NativeHttpEvidenceIndex,
    nodes: &HashMap<u64, &Node>,
) -> Option<NativeHttpCoverage> {
    if !start_known || expected_length == 0 || expected_length != actual_length {
        return None;
    }
    let [application_checks_node_id] = evidence
        .application_checks_by_run
        .get(&run_node_id)?
        .as_slice()
    else {
        return None;
    };
    let check_node = nodes.get(application_checks_node_id)?;
    if check_node.kind != "application_checks"
        || check_node.details.get("start_known") != Some(&Value::Bool(true))
    {
        return None;
    }
    let http = check_node.details.get("http")?.as_object()?;
    let expected_messages = http.get("messages")?.as_u64()?;
    let candidate_ids = evidence
        .message_candidates_by_run
        .get(&run_node_id)
        .map_or(&[][..], Vec::as_slice);
    if expected_messages != u64::try_from(candidate_ids.len()).ok()? {
        return None;
    }
    let unparsed_ranges = parse_application_ranges(http.get("unparsed")?, actual_length)?;
    let budget_omission_ranges =
        parse_budget_omission_ranges(http.get("budget_omissions")?, actual_length)?;
    let mut complete_messages = Vec::new();
    for candidate_id in candidate_ids {
        let candidate = nodes.get(candidate_id)?;
        if candidate.kind != "http_message_candidate"
            || candidate.details.get("status").and_then(Value::as_str) != Some("complete")
        {
            continue;
        }
        let framing_kind = candidate.details.get("framing")?.get("kind")?.as_str()?;
        if !matches!(
            framing_kind,
            "no_body" | "content_length" | "chunked" | "close_delimited"
        ) {
            return None;
        }
        let range = parse_application_range(candidate.details.get("range")?, actual_length)?;
        if overlaps_any(range, &unparsed_ranges) || overlaps_any(range, &budget_omission_ranges) {
            continue;
        }
        complete_messages.push((range, *candidate_id));
    }
    complete_messages.sort_unstable_by_key(|(range, _)| *range);
    if complete_messages
        .iter()
        .zip(complete_messages.iter().skip(1))
        .any(|((left, _), (right, _))| left.end > right.start)
    {
        return None;
    }
    if complete_messages.is_empty() {
        return None;
    }
    let (message_ranges, message_candidate_node_ids): (Vec<_>, Vec<_>) =
        complete_messages.into_iter().unzip();
    Some(NativeHttpCoverage {
        application_checks_node_id: *application_checks_node_id,
        message_candidate_node_ids,
        message_ranges,
    })
}

fn parse_application_ranges(value: &Value, input_length: usize) -> Option<Vec<StreamRange>> {
    value
        .as_array()?
        .iter()
        .map(|value| parse_application_range(value, input_length))
        .collect()
}

fn parse_budget_omission_ranges(value: &Value, input_length: usize) -> Option<Vec<StreamRange>> {
    value
        .as_array()?
        .iter()
        .map(|value| parse_application_range(value.get("range")?, input_length))
        .collect()
}

fn parse_application_range(value: &Value, input_length: usize) -> Option<StreamRange> {
    let start = usize::try_from(value.get("offset")?.as_u64()?).ok()?;
    let length = usize::try_from(value.get("length")?.as_u64()?).ok()?;
    let end = start.checked_add(length)?;
    (length > 0 && end <= input_length).then_some(StreamRange { start, end })
}

fn overlaps_any(range: StreamRange, others: &[StreamRange]) -> bool {
    others
        .iter()
        .any(|other| range.start < other.end && other.start < range.end)
}

pub(in crate::workbench::recovery_executor) fn range_covered_by_native_messages(
    range: StreamRange,
    message_ranges: &[StreamRange],
) -> bool {
    if range.start >= range.end {
        return false;
    }
    let mut covered_until = range.start;
    for message in message_ranges {
        if message.end <= covered_until {
            continue;
        }
        if message.start > covered_until {
            return false;
        }
        covered_until = message.end;
        if covered_until >= range.end {
            return true;
        }
    }
    false
}

type RunMetadataError = (Option<String>, InputOmissionKind);

fn run_metadata(
    node: &Node,
    blobs: &HashMap<&str, &l2_workbench::evidence::Blob>,
    limits: ProtocolLimits,
) -> Result<(String, String, usize, usize), RunMetadataError> {
    let source_id = exact_source(node).map_err(|reason| (None, reason))?;
    let reject = |reason| (Some(source_id.clone()), reason);
    let blob_id = node
        .blob
        .as_deref()
        .ok_or_else(|| reject(InputOmissionKind::MissingBlob))?;
    let blob = blobs
        .get(blob_id)
        .ok_or_else(|| reject(InputOmissionKind::MissingBlob))?;
    let stream_offset = node
        .details
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| reject(InputOmissionKind::InvalidRun))?;
    let byte_length = node
        .details
        .get("length")
        .and_then(Value::as_u64)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| reject(InputOmissionKind::InvalidRun))?;
    if byte_length != blob.bytes.len() {
        return Err(reject(InputOmissionKind::InvalidRun));
    }
    if blob.bytes.is_empty() {
        return Err(reject(InputOmissionKind::EmptyRun));
    }
    if blob.bytes.len() > limits.max_run_bytes {
        return Err(reject(InputOmissionKind::RunTooLarge));
    }
    if node.details.get("generation_ambiguous") != Some(&Value::Bool(false)) {
        return Err(reject(InputOmissionKind::GenerationAmbiguous));
    }
    Ok((source_id, blob_id.to_owned(), stream_offset, byte_length))
}

fn collect_tcp_run(
    node: &Node,
    nodes: &HashMap<u64, &Node>,
    blobs: &HashMap<&str, &l2_workbench::evidence::Blob>,
    ancestry: &TcpAncestryIndex,
    limits: ProtocolLimits,
) -> Result<(FramingCohortKey, FramingInput), RunMetadataError> {
    let (source_id, blob_id, stream_offset, byte_length) = run_metadata(node, blobs, limits)?;
    let resolved = resolve_context(node, nodes, ancestry, &source_id)
        .map_err(|reason| (Some(source_id.clone()), reason))?;
    let key = FramingCohortKey {
        source_id: source_id.clone(),
        scope: resolved.message.scope.clone(),
        endpoint_pair: resolved.endpoint_pair,
        direction: resolved.message.direction,
    };
    let input = FramingInput {
        node_id: node.id,
        blob_id,
        source_id,
        context: resolved.message,
        direction_node_id: resolved.ancestry.direction_node_id,
        direction_contains_status: resolved.ancestry.direction_contains_status,
        episode_node_id: resolved.ancestry.episode_node_id,
        episode_contains_status: resolved.ancestry.episode_contains_status,
        session_order: resolved.first_packet,
        stream_offset,
        byte_length,
        start_known: node.details.get("start_known") == Some(&Value::Bool(true)),
        end_observed: node.details.get("end_observed") == Some(&Value::Bool(true)),
    };
    Ok((key, input))
}

fn sort_and_cap_cohorts(
    plan: &mut FramingDiscoveryPlan,
    limits: ProtocolLimits,
) -> Result<(), RecoveryExecutionError> {
    let mut capped_omissions = Vec::new();
    for inputs in plan.cohorts.values_mut() {
        inputs.sort_by(|left, right| {
            left.context
                .scope
                .cmp(&right.context.scope)
                .then_with(|| left.session_order.cmp(&right.session_order))
                .then_with(|| left.context.session.cmp(&right.context.session))
                .then_with(|| left.context.direction.cmp(&right.context.direction))
                .then_with(|| left.stream_offset.cmp(&right.stream_offset))
                .then_with(|| left.node_id.cmp(&right.node_id))
        });
        let mut retained = 0_usize;
        let mut total_bytes = 0_usize;
        let mut kept = Vec::new();
        kept.try_reserve_exact(inputs.len()).map_err(|error| {
            RecoveryExecutionError::Operational {
                stage: l2_workbench::recovery::RecoveryStage::FramingDiscovery,
                source: Box::new(error),
            }
        })?;
        for input in inputs.drain(..) {
            let next_count = retained.checked_add(1);
            let next_total = total_bytes.checked_add(input.byte_length);
            let reason = if retained >= limits.max_samples || next_count.is_none() {
                Some(InputOmissionKind::TooManySamples)
            } else if next_total.is_none_or(|total| total > limits.max_total_bytes) {
                Some(InputOmissionKind::TotalBytes)
            } else {
                None
            };
            if let Some(reason) = reason {
                capped_omissions.push((reason, input.source_id));
                continue;
            }
            retained = next_count.ok_or_else(graph_work_overflow)?;
            total_bytes = next_total.ok_or_else(graph_work_overflow)?;
            kept.push(input);
        }
        *inputs = kept;
    }
    for (reason, source_id) in capped_omissions {
        plan.record_omission(Some(&source_id), reason)?;
    }
    Ok(())
}

fn exact_source(node: &Node) -> Result<String, InputOmissionKind> {
    let Some(first) = node.ranges.first() else {
        return Err(InputOmissionKind::MissingSource);
    };
    if node
        .ranges
        .iter()
        .skip(1)
        .any(|range| range.source != first.source)
    {
        return Err(InputOmissionKind::MixedSource);
    }
    Ok(first.source.clone())
}

fn case_graph_work(
    case: &Case,
    nodes: &HashMap<u64, &Node>,
) -> Result<(usize, NativeHttpEvidenceIndex), RecoveryExecutionError> {
    let node_work = case.nodes().iter().try_fold(0_usize, |total, node| {
        let details = serde_json::to_vec(&node.details).map_err(|error| {
            RecoveryExecutionError::Operational {
                stage: l2_workbench::recovery::RecoveryStage::FramingDiscovery,
                source: Box::new(error),
            }
        })?;
        let range_work = node.ranges.iter().try_fold(0_usize, |subtotal, range| {
            subtotal
                .checked_add(range.source.len())
                .and_then(|value| value.checked_add(4 * std::mem::size_of::<u64>()))
                .ok_or_else(graph_work_overflow)
        })?;
        // Details are serialized once for accounting and selected sub-values are serialized
        // again while resolving a TCP conversation
        details
            .len()
            .checked_mul(2)
            .and_then(|details_work| total.checked_add(details_work))
            .and_then(|value| value.checked_add(node.kind.len()))
            .and_then(|value| value.checked_add(range_work))
            .and_then(|value| value.checked_add(std::mem::size_of::<u64>()))
            .ok_or_else(graph_work_overflow)
    })?;
    let mut native_http_evidence = NativeHttpEvidenceIndex::default();
    let mut edge_work = 0_usize;
    for edge in case.edges() {
        edge_work = edge_work
            .checked_add(edge.relation.len())
            .and_then(|value| value.checked_add(edge.reason.len()))
            .and_then(|value| value.checked_add(3 * std::mem::size_of::<u64>()))
            .ok_or_else(graph_work_overflow)?;
        let Some((target_kind, target)) = (match (edge.relation.as_str(), edge.status) {
            ("tested_by", EvidenceStatus::Observed) => Some((
                "application_checks",
                &mut native_http_evidence.application_checks_by_run,
            )),
            ("parsed_as", EvidenceStatus::Hypothesis) => Some((
                "http_message_candidate",
                &mut native_http_evidence.message_candidates_by_run,
            )),
            _ => None,
        }) else {
            continue;
        };
        if nodes
            .get(&edge.from)
            .is_none_or(|parent| parent.kind != "tcp_byte_run")
            || nodes
                .get(&edge.to)
                .is_none_or(|child| child.kind != target_kind)
        {
            continue;
        }
        let targets = target.entry(edge.from).or_default();
        targets
            .try_reserve(1)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: l2_workbench::recovery::RecoveryStage::FramingDiscovery,
                source: Box::new(source),
            })?;
        targets.push(edge.to);
    }
    let blob_work = case.blobs().iter().try_fold(0_usize, |total, blob| {
        total
            .checked_add(blob.id.len())
            .and_then(|value| value.checked_add(std::mem::size_of::<usize>()))
            .ok_or_else(graph_work_overflow)
    })?;
    let work = node_work
        .checked_add(edge_work)
        .and_then(|value| value.checked_add(blob_work))
        .ok_or_else(graph_work_overflow)?;
    Ok((work, native_http_evidence))
}

fn graph_work_overflow() -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(
        "framing discovery Case graph work exceeds this platform's address space".to_owned(),
    )
}

struct ResolvedFramingContext {
    message: MessageContext,
    endpoint_pair: String,
    first_packet: u64,
    ancestry: TcpAncestry,
}

fn resolve_context(
    run: &Node,
    nodes: &HashMap<u64, &Node>,
    ancestry_index: &TcpAncestryIndex,
    source_id: &str,
) -> Result<ResolvedFramingContext, InputOmissionKind> {
    let ancestry = ancestry_index
        .resolve_run(run.id)
        .map_err(|error| match error {
            TcpAncestryError::Missing => InputOmissionKind::MissingContext,
            TcpAncestryError::Ambiguous => InputOmissionKind::AmbiguousContext,
            TcpAncestryError::Invalid => InputOmissionKind::InvalidContext,
        })?;
    let direction = nodes
        .get(&ancestry.direction_node_id)
        .ok_or(InputOmissionKind::InvalidContext)?;
    let episode = nodes
        .get(&ancestry.episode_node_id)
        .ok_or(InputOmissionKind::InvalidContext)?;
    let endpoints = episode
        .details
        .get("endpoints")
        .and_then(Value::as_array)
        .ok_or(InputOmissionKind::InvalidContext)?;
    let [first_endpoint, second_endpoint] = endpoints.as_slice() else {
        return Err(InputOmissionKind::InvalidContext);
    };
    let source = direction
        .details
        .get("source")
        .ok_or(InputOmissionKind::InvalidContext)?;
    let destination = direction
        .details
        .get("destination")
        .ok_or(InputOmissionKind::InvalidContext)?;
    let direction = if source == first_endpoint && destination == second_endpoint {
        Direction::FirstToSecond
    } else if source == second_endpoint && destination == first_endpoint {
        Direction::SecondToFirst
    } else {
        return Err(InputOmissionKind::InvalidContext);
    };
    // TCP byte runs each contain one observed, contiguous span
    // Gaps elsewhere in the direction do not invalidate that input
    if episode.details.get("generation_ambiguous") != Some(&Value::Bool(false))
        || direction_sequence_is_ambiguous(ancestry.direction_node_id, nodes)
    {
        return Err(InputOmissionKind::InvalidContext);
    }
    let first_packet = episode
        .details
        .get("first_packet")
        .and_then(Value::as_u64)
        .ok_or(InputOmissionKind::InvalidContext)?;
    if first_packet == 0 {
        return Err(InputOmissionKind::InvalidContext);
    }
    let scope = episode
        .details
        .get("scope")
        .ok_or(InputOmissionKind::InvalidContext)?;
    let scope = serde_json::to_string(scope).map_err(|_| InputOmissionKind::InvalidContext)?;
    let endpoint_pair =
        serde_json::to_string(endpoints).map_err(|_| InputOmissionKind::InvalidContext)?;
    if scope == "null" || scope.is_empty() || endpoint_pair == "null" {
        return Err(InputOmissionKind::InvalidContext);
    }
    Ok(ResolvedFramingContext {
        message: MessageContext {
            source: source_id.to_owned(),
            scope,
            // Node identity separates distinct episodes that reuse a packet label
            session: ancestry.episode_node_id,
            direction,
        },
        endpoint_pair,
        first_packet,
        ancestry,
    })
}

fn direction_sequence_is_ambiguous(direction_id: u64, nodes: &HashMap<u64, &Node>) -> bool {
    nodes.get(&direction_id).is_none_or(|direction| {
        direction.details.get("sequence_ambiguous") != Some(&Value::Bool(false))
    })
}

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_framing_ancestry.rs"]
mod ancestry_tests;
