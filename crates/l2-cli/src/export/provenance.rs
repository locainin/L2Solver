//! Project validated artifact bytes back to their capture evidence

#[cfg(test)]
#[path = "../../tests/export/provenance/canonical_move.rs"]
mod canonical_move_tests;

#[cfg(test)]
use super::COHORT_ARTIFACT_LOOKUP_BUILDS;
use super::{artifact_collection::ArtifactProvenance, collection::CaseArtifactIndex};
use crate::workbench;
use l2_workbench::{
    evidence::{
        Blob, ByteMapping, Case, Node, SourceRange, clip_byte_mappings,
        clip_byte_mappings_with_memory,
    },
    job::{JsonMemoryAdmission, MemoryBudget, MemoryClass, MemoryLease, admit_json},
};
use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    ops::Deref,
};

pub(super) struct CohortArtifactContextIndex<'a> {
    cohort: &'a workbench::full_source::CohortAnalysis,
    member_flows_by_id: Vec<(i64, usize)>,
    packet_to_flow: Vec<(u32, usize)>,
    // Index vectors drop before the shared charge
    _memory: Option<MemoryLease>,
}

impl<'a> CohortArtifactContextIndex<'a> {
    pub(super) fn new(
        cohort: &'a workbench::full_source::CohortAnalysis,
        budget: Option<&MemoryBudget>,
    ) -> Result<Self, Box<dyn Error>> {
        #[cfg(test)]
        COHORT_ARTIFACT_LOOKUP_BUILDS.with(|builds| builds.set(builds.get() + 1));

        if cohort.member_flows.is_empty() {
            return Err("cohort analysis has no member flows".into());
        }
        let mut memory = budget
            .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
            .transpose()?;
        let mut member_flows_by_id = Vec::new();
        for (index, flow) in cohort.member_flows.iter().enumerate() {
            crate::retained_memory::grow_vec_optional(&mut member_flows_by_id, &mut memory, 1)?;
            member_flows_by_id.push((flow.id, index));
        }
        // Original positions break ties so the last entry wins
        member_flows_by_id.sort_unstable();
        let mut packet_to_flow = Vec::new();
        for (index, (packet, _)) in cohort.packet_flow_ids.iter().enumerate() {
            crate::retained_memory::grow_vec_optional(&mut packet_to_flow, &mut memory, 1)?;
            packet_to_flow.push((*packet, index));
        }
        packet_to_flow.sort_unstable();

        Ok(Self {
            cohort,
            member_flows_by_id,
            packet_to_flow,
            _memory: memory,
        })
    }

    fn packet_flow(&self, packet: u64) -> Option<i64> {
        let packet = u32::try_from(packet).ok()?;
        let last = self
            .packet_to_flow
            .partition_point(|(candidate, _)| *candidate <= packet)
            .checked_sub(1)?;
        let (candidate, index) = self.packet_to_flow.get(last)?;
        if *candidate != packet {
            return None;
        }
        self.cohort
            .packet_flow_ids
            .get(*index)
            .map(|(_, flow)| *flow)
    }

    fn member_flow(&self, flow: i64) -> Option<&l2_workbench::store::Flow> {
        let last = self
            .member_flows_by_id
            .partition_point(|(candidate, _)| *candidate <= flow)
            .checked_sub(1)?;
        let (candidate, index) = self.member_flows_by_id.get(last)?;
        if *candidate != flow {
            return None;
        }
        self.cohort.member_flows.get(*index)
    }

    pub(super) fn for_node(
        &self,
        node: &Node,
        case: &Case,
        case_id: Option<&str>,
        case_scope: &serde_json::Value,
    ) -> Result<ArtifactSourceContext, Box<dyn Error>> {
        let mut packet_numbers = BTreeSet::new();
        let mut visited_nodes = HashSet::new();
        collect_node_packets(node, case, &mut visited_nodes, &mut packet_numbers)?;

        let mut complete = true;
        let mut supporting_ids = packet_numbers
            .iter()
            .filter_map(|packet| {
                self.packet_flow(*packet).or_else(|| {
                    complete = false;
                    None
                })
            })
            .collect::<BTreeSet<_>>();
        // Missing packet witnesses cannot safely narrow support to one indexed flow
        if supporting_ids.is_empty() || !complete {
            supporting_ids.extend(self.member_flows_by_id.iter().map(|(flow, _)| *flow));
        }
        // Serialize only flows needed by this artifact instead of caching every JSON copy
        let supporting_flows = supporting_ids
            .iter()
            .filter_map(|flow_id| self.member_flow(*flow_id))
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;

        if supporting_ids.len() == 1
            && let Some(flow) = supporting_flows.first()
        {
            return Ok(ArtifactSourceContext {
                flow: Some(flow.clone()),
                supporting_flows,
                cohort_scope: None,
                case_id: case_id.map(str::to_owned),
                case_scope: case_scope.clone(),
            });
        }

        Ok(ArtifactSourceContext {
            flow: None,
            supporting_flows,
            cohort_scope: Some(cohort_scope(self.cohort)?),
            case_id: case_id.map(str::to_owned),
            case_scope: case_scope.clone(),
        })
    }
}

fn collect_node_packets(
    node: &Node,
    case: &Case,
    visited: &mut HashSet<u64>,
    packets: &mut BTreeSet<u64>,
) -> Result<(), Box<dyn Error>> {
    if !visited.insert(node.id) {
        return Ok(());
    }
    packets.extend(node.ranges.iter().filter_map(|range| range.packet));
    collect_node_references(&node.details, case, visited, packets)
}

fn collect_node_references(
    value: &serde_json::Value,
    case: &Case,
    visited: &mut HashSet<u64>,
    packets: &mut BTreeSet<u64>,
) -> Result<(), Box<dyn Error>> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if is_node_reference_list(key) {
                    let references = value.as_array().ok_or_else(|| {
                        node_reference_error(
                            key,
                            "expected an array of unsigned node IDs",
                            json_type(value),
                        )
                    })?;
                    for reference in references {
                        collect_referenced_node(key, reference, case, visited, packets)?;
                    }
                } else if is_node_reference(key) {
                    // Multi-input record evidence has no single input node
                    if is_optional_node_reference(key) && value.is_null() {
                        continue;
                    }
                    collect_referenced_node(key, value, case, visited, packets)?;
                } else {
                    collect_node_references(value, case, visited, packets)?;
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_node_references(value, case, visited, packets)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_referenced_node(
    key: &str,
    value: &serde_json::Value,
    case: &Case,
    visited: &mut HashSet<u64>,
    packets: &mut BTreeSet<u64>,
) -> Result<(), Box<dyn Error>> {
    let node_id = value.as_u64().ok_or_else(|| {
        node_reference_error(key, "expected an unsigned node ID", json_type(value))
    })?;
    let referenced = case
        .node(node_id)
        .ok_or_else(|| missing_node_reference_error(key, json_type(value)))?;
    collect_node_packets(referenced, case, visited, packets)
}

fn node_reference_error(key: &str, expected: &str, value_type: &str) -> String {
    format!("artifact node reference `{key}` has JSON type `{value_type}`; {expected}")
}

fn missing_node_reference_error(key: &str, value_type: &str) -> String {
    format!(
        "artifact node reference `{key}` has JSON type `{value_type}`; referenced Case node is missing"
    )
}

const fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

pub(super) fn cohort_scope(
    cohort: &workbench::full_source::CohortAnalysis,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let first = cohort
        .member_flows
        .first()
        .ok_or("cohort analysis has no member flows")?;
    let mut addresses = [first.endpoint_a.to_string(), first.endpoint_b.to_string()];
    addresses.sort();
    Ok(serde_json::json!({
        "source_id": first.source_id,
        "scope": first.scope,
        "unordered_ip_pair": addresses,
        "split": cohort.split,
    }))
}

#[derive(Clone)]
pub(super) struct ArtifactSourceContext {
    pub(super) flow: Option<serde_json::Value>,
    pub(super) supporting_flows: Vec<serde_json::Value>,
    pub(super) cohort_scope: Option<serde_json::Value>,
    pub(super) case_id: Option<String>,
    pub(super) case_scope: serde_json::Value,
}

struct ValidatedArtifactInput<'a> {
    validation_node: &'a Node,
    input_node: &'a Node,
    input_blob_id: &'a str,
    input_blob: &'a Blob,
    offset: usize,
    length: usize,
    end: usize,
}

pub(super) struct SelectedSourceRanges {
    pub(super) ranges: Vec<SourceRange>,
    // The source ranges drop before their shared charge
    _memory: Option<MemoryLease>,
}

pub(super) struct ArtifactSelection {
    pub(super) details: serde_json::Value,
    pub(super) source_ranges: Vec<SourceRange>,
}

pub(super) fn selected_artifact_source_ranges(
    selected_origin: &workbench::artifact_export::ArtifactProvenance,
    index: &CaseArtifactIndex<'_>,
    budget: Option<&MemoryBudget>,
) -> Result<SelectedSourceRanges, Box<dyn Error>> {
    let mut memory = budget
        .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
        .transpose()?;
    let ranges = selected_source_ranges(selected_origin, index, budget, &mut memory)?;
    Ok(SelectedSourceRanges {
        ranges,
        _memory: memory,
    })
}

fn selected_source_ranges(
    selected_origin: &workbench::artifact_export::ArtifactProvenance,
    index: &CaseArtifactIndex<'_>,
    budget: Option<&MemoryBudget>,
    memory: &mut Option<MemoryLease>,
) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    let Some(input) = validated_artifact_input(selected_origin, index)? else {
        return Ok(Vec::new());
    };
    let selected_node = index
        .case
        .node(selected_origin.id)
        .ok_or("selected artifact source node is missing")?;
    let Some(selected_blob_id) = selected_node.blob.as_deref() else {
        return Ok(Vec::new());
    };
    let selected_blob = index
        .case
        .blob(selected_blob_id)
        .ok_or("selected artifact bytes are missing")?;
    let validated_bytes = input
        .input_blob
        .bytes
        .get(input.offset..input.end)
        .ok_or("artifact object range exceeds its validation input")?;
    if selected_blob.bytes.as_slice() != validated_bytes {
        return Ok(Vec::new());
    }
    let Some(receipt_node) = index.mapping_receipt(input.input_node.id) else {
        return exact_direct_input_ranges(&input, memory);
    };
    source_ranges_from_mapping_receipt(receipt_node, &input, index, budget, memory)
}

fn validated_artifact_input<'a>(
    selected_origin: &workbench::artifact_export::ArtifactProvenance,
    index: &'a CaseArtifactIndex<'a>,
) -> Result<Option<ValidatedArtifactInput<'a>>, Box<dyn Error>> {
    let Some(validation_node_id) = selected_origin.validation_evidence_node() else {
        return Ok(None);
    };
    let validation_node = index
        .case
        .node(validation_node_id)
        .ok_or("artifact validation evidence references a missing node")?;
    let Some(input_node_id) = validation_node
        .details
        .get("input_node")
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(None);
    };
    let input_node = index
        .case
        .node(input_node_id)
        .ok_or("artifact validation input references a missing node")?;
    let Some(input_blob_id) = input_node.blob.as_deref() else {
        return Ok(None);
    };
    let input_blob = index
        .case
        .blob(input_blob_id)
        .ok_or("artifact validation input bytes are missing")?;
    let Some(object_range) = validation_node.details.get("object_range") else {
        return Ok(None);
    };
    let Some(offset) = object_range
        .get("offset")
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(None);
    };
    let Some(length) = object_range
        .get("length")
        .and_then(serde_json::Value::as_u64)
    else {
        return Ok(None);
    };
    let offset = usize::try_from(offset)?;
    let length = usize::try_from(length)?;
    let end = offset
        .checked_add(length)
        .ok_or("artifact object range exceeds the supported size")?;
    if end > input_blob.bytes.len() {
        return Err("artifact object range exceeds its validation input".into());
    }
    Ok(Some(ValidatedArtifactInput {
        validation_node,
        input_node,
        input_blob_id,
        input_blob,
        offset,
        length,
        end,
    }))
}

fn source_ranges_from_mapping_receipt(
    receipt_node: &Node,
    input: &ValidatedArtifactInput<'_>,
    index: &CaseArtifactIndex<'_>,
    budget: Option<&MemoryBudget>,
    memory: &mut Option<MemoryLease>,
) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or("byte mapping receipt has no retained bytes")?;
    let receipt_blob = index
        .case
        .blob(receipt_blob_id)
        .ok_or("byte mapping receipt bytes are missing")?;
    let decoded = decode_mapping_receipt(&receipt_blob.bytes, budget)?;
    validate_mapping_receipt(&decoded.mappings, input)?;
    let before_clip = memory.as_ref().map(MemoryLease::bytes);
    let clipped = if let Some(lease) = memory.as_mut() {
        clip_byte_mappings_with_memory(&decoded.mappings, input.offset..input.end, lease)?
    } else {
        clip_byte_mappings(&decoded.mappings, input.offset..input.end)?
    };
    if !mappings_cover_object(&clipped, input.length, memory)? {
        drop(clipped);
        if let (Some(lease), Some(before)) = (memory.as_mut(), before_clip) {
            lease.try_resize(before)?;
        }
        return Ok(Vec::new());
    }
    let clipped_vector_bytes = clipped
        .capacity()
        .checked_mul(std::mem::size_of::<ByteMapping>())
        .ok_or("clipped mapping vector size overflows")?;
    let mut ranges = Vec::new();
    crate::retained_memory::grow_vec_exact_optional(&mut ranges, memory, clipped.len())?;
    for mapping in clipped {
        ranges.push(mapping.range);
    }
    if let Some(lease) = memory {
        // Source names moved into the output, but the clipped vector has dropped
        let remaining = lease
            .bytes()
            .checked_sub(u64::try_from(clipped_vector_bytes)?)
            .ok_or("clipped mapping vector charge is inconsistent")?;
        lease.try_resize(remaining)?;
    }
    Ok(ranges)
}

struct DecodedMappings {
    mappings: Vec<ByteMapping>,
    // The typed mappings drop before their decoded JSON allowance
    _memory: Option<MemoryLease>,
}

fn decode_mapping_receipt(
    bytes: &[u8],
    budget: Option<&MemoryBudget>,
) -> Result<DecodedMappings, Box<dyn Error>> {
    // ByteMapping numeric fields do not size any allocations during decoding
    let admission = budget
        .map(|budget| admit_json(bytes, budget, MemoryClass::Publication))
        .transpose()?;
    let mappings = serde_json::from_slice(bytes)?;
    Ok(DecodedMappings {
        mappings,
        _memory: admission.map(JsonMemoryAdmission::into_retained),
    })
}

fn validate_mapping_receipt(
    mappings: &[ByteMapping],
    input: &ValidatedArtifactInput<'_>,
) -> Result<(), Box<dyn Error>> {
    for mapping in mappings {
        let length = usize::try_from(mapping.range.length)?;
        let end = mapping
            .offset
            .checked_add(length)
            .ok_or("byte mapping output range overflowed")?;
        if end > input.input_blob.bytes.len() || !input.input_node.ranges.contains(&mapping.range) {
            return Err("byte mapping receipt disagrees with its output node ranges".into());
        }
    }
    Ok(())
}

fn exact_direct_input_ranges(
    input: &ValidatedArtifactInput<'_>,
    memory: &mut Option<MemoryLease>,
) -> Result<Vec<SourceRange>, Box<dyn Error>> {
    if input.length == 0 {
        return Ok(Vec::new());
    }
    if input.validation_node.blob.as_deref() == Some(input.input_blob_id)
        && input.offset == 0
        && input.end == input.input_blob.bytes.len()
    {
        let mut ranges = Vec::new();
        crate::retained_memory::grow_vec_exact_optional(
            &mut ranges,
            memory,
            input.input_node.ranges.len(),
        )?;
        for range in &input.input_node.ranges {
            ranges.push(copy_source_range(range, memory)?);
        }
        return Ok(ranges);
    }
    let [input_range] = input.input_node.ranges.as_slice() else {
        return Ok(Vec::new());
    };
    if usize::try_from(input_range.length)? != input.input_blob.bytes.len() {
        return Ok(Vec::new());
    }
    let source_offset = input_range
        .offset
        .checked_add(u64::try_from(input.offset)?)
        .ok_or("clipped source range offset overflowed")?;
    source_offset
        .checked_add(u64::try_from(input.length)?)
        .ok_or("clipped source range end overflowed")?;
    let mut ranges = Vec::new();
    crate::retained_memory::grow_vec_exact_optional(&mut ranges, memory, 1)?;
    let mut range = copy_source_range(input_range, memory)?;
    range.offset = source_offset;
    range.length = u64::try_from(input.length)?;
    ranges.push(range);
    Ok(ranges)
}

fn copy_source_range(
    range: &SourceRange,
    memory: &mut Option<MemoryLease>,
) -> Result<SourceRange, Box<dyn Error>> {
    Ok(SourceRange {
        source: crate::retained_memory::copy_optional(&range.source, memory)?,
        packet: range.packet,
        offset: range.offset,
        length: range.length,
    })
}

fn mappings_cover_object(
    mappings: &[ByteMapping],
    object_length: usize,
    memory: &mut Option<MemoryLease>,
) -> Result<bool, Box<dyn Error>> {
    let before = memory.as_ref().map(MemoryLease::bytes);
    let mut intervals = Vec::new();
    crate::retained_memory::grow_vec_exact_optional(&mut intervals, memory, mappings.len())?;
    for mapping in mappings {
        let length = usize::try_from(mapping.range.length)?;
        let end = mapping
            .offset
            .checked_add(length)
            .ok_or("clipped object mapping range overflowed")?;
        intervals.push((mapping.offset, end));
    }
    intervals.sort_unstable();
    let mut covered_end = 0_usize;
    let mut complete = true;
    for (start, end) in intervals {
        if start > covered_end {
            complete = false;
            break;
        }
        covered_end = covered_end.max(end);
    }
    if let (Some(lease), Some(before)) = (memory, before) {
        // The sorted interval vector has dropped
        lease.try_resize(before)?;
    }
    Ok(complete && covered_end >= object_length)
}

#[derive(Clone, Copy)]
pub(super) struct ArtifactPublication<'a> {
    pub(super) case: &'a Case,
    pub(super) memory: Option<&'a MemoryBudget>,
}

pub(super) struct AdmittedArtifactProvenance {
    origin: ArtifactProvenance,
    // Owned Node copies drop before their shared charge
    _memory: Option<MemoryLease>,
}

impl Deref for AdmittedArtifactProvenance {
    type Target = ArtifactProvenance;

    fn deref(&self) -> &Self::Target {
        &self.origin
    }
}

pub(super) fn artifact_provenance<'a>(
    category: &str,
    context: &ArtifactSourceContext,
    node: Option<&Node>,
    description: Option<String>,
    selection: Option<ArtifactSelection>,
    signature_candidates: impl Iterator<Item = &'a Node>,
    publication: ArtifactPublication<'_>,
) -> Result<AdmittedArtifactProvenance, Box<dyn Error>> {
    let case = publication.case;
    let mut memory = publication
        .memory
        .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
        .transpose()?;
    let graph_retained = context.case_id.is_some();
    let (selection, selected_ranges) = selection_parts(selection, graph_retained);
    let selected_node_id = node.map(|node| node.id);
    let validation_node_id = selection
        .as_ref()
        .and_then(|selection| selection.get("validation_evidence_node"))
        .and_then(serde_json::Value::as_u64);
    let extension_node_id = selection
        .as_ref()
        .and_then(|selection| selection.get("extension_evidence_node"))
        .and_then(serde_json::Value::as_u64);
    validate_provenance_nodes(
        case,
        [selected_node_id, validation_node_id, extension_node_id],
    )?;
    let mut source_projection =
        artifact_source_projection(context, node, selected_node_id, selected_ranges);
    // Copy evidence only when the sidecar retains the corresponding Case
    let (node, retained_candidates) =
        retained_node_copies(node, signature_candidates, graph_retained, &mut memory)?;
    let selection = graph_retained.then_some(selection).flatten();
    // Keep exact source ranges when their Case graph is omitted from the sidecar
    let source_ranges = if graph_retained {
        Vec::new()
    } else {
        std::mem::take(&mut source_projection.source_ranges)
    };
    let canonical_source_ranges = (!source_ranges.is_empty()).then_some(source_ranges.as_slice());
    let selected_node_id = graph_retained.then_some(selected_node_id).flatten();
    let validation_node_id = graph_retained.then_some(validation_node_id).flatten();
    let extension_node_id = graph_retained.then_some(extension_node_id).flatten();
    let stable_node = node
        .as_ref()
        .map(|node| canonical_node(node, case))
        .transpose()?;
    let stable_selection = selection
        .as_ref()
        .map(|selection| canonical_selection(selection, case))
        .transpose()?;
    let stable_candidates = canonical_nodes(&retained_candidates, case)?;
    let canonical_origin = canonical_origin(
        category,
        context,
        &source_projection,
        canonical_source_ranges,
        description.as_deref(),
        (stable_node, stable_selection, stable_candidates),
    );
    let origin = ArtifactProvenance {
        category: category.to_owned(),
        case_id: context.case_id.clone(),
        selected_node_id,
        validation_node_id,
        extension_node_id,
        flow: context.flow.clone(),
        supporting_flows: context.supporting_flows.clone(),
        cohort_scope: context.cohort_scope.clone(),
        node,
        description,
        selection,
        signature_candidates: retained_candidates,
        source_ranges,
        canonical_origin,
    };
    Ok(AdmittedArtifactProvenance {
        origin,
        _memory: memory,
    })
}

fn validate_provenance_nodes(case: &Case, nodes: [Option<u64>; 3]) -> Result<(), Box<dyn Error>> {
    for node_id in nodes.into_iter().flatten() {
        if case.node(node_id).is_none() {
            return Err("artifact provenance references a missing Case node".into());
        }
    }
    Ok(())
}

fn retained_node_copies<'a>(
    node: Option<&Node>,
    signatures: impl Iterator<Item = &'a Node>,
    graph_retained: bool,
    memory: &mut Option<MemoryLease>,
) -> Result<(Option<Node>, Vec<Node>), Box<dyn Error>> {
    if !graph_retained {
        return Ok((None, Vec::new()));
    }
    let node = node.map(|node| copy_node(node, memory)).transpose()?;
    let mut candidates = Vec::new();
    for candidate in signatures {
        crate::retained_memory::grow_vec_optional(&mut candidates, memory, 1)?;
        candidates.push(copy_node(candidate, memory)?);
    }
    Ok((node, candidates))
}

fn canonical_origin(
    category: &str,
    context: &ArtifactSourceContext,
    projection: &ArtifactSourceProjection<'_>,
    source_ranges: Option<&[SourceRange]>,
    description: Option<&str>,
    stable: (
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Vec<serde_json::Value>,
    ),
) -> serde_json::Value {
    let (node, selection, candidates) = stable;
    // Flow and cohort Cases can describe the same packet-backed object with different local IDs
    serde_json::Value::Object(serde_json::Map::from_iter([
        ("category".to_owned(), serde_json::json!(category)),
        (
            "local_case_identity".to_owned(),
            serde_json::json!(projection.local_case_identity),
        ),
        (
            "local_case_scope".to_owned(),
            serde_json::json!(projection.local_case_scope),
        ),
        ("flow".to_owned(), serde_json::json!(context.flow)),
        (
            "supporting_flows".to_owned(),
            serde_json::json!(context.supporting_flows),
        ),
        (
            "cohort_scope".to_owned(),
            serde_json::json!(context.cohort_scope),
        ),
        // Already-owned canonical values move into the final origin
        ("node".to_owned(), node.unwrap_or(serde_json::Value::Null)),
        ("source_ranges".to_owned(), serde_json::json!(source_ranges)),
        ("description".to_owned(), serde_json::json!(description)),
        (
            "selection".to_owned(),
            selection.unwrap_or(serde_json::Value::Null),
        ),
        (
            "signature_candidates".to_owned(),
            serde_json::Value::Array(candidates),
        ),
    ]))
}

fn copy_node(node: &Node, memory: &mut Option<MemoryLease>) -> Result<Node, Box<dyn Error>> {
    let Some(memory) = memory else {
        return Ok(node.clone());
    };
    let before = memory.bytes();
    let expected = node
        .owned_heap_bytes()
        .ok_or("Node copy memory overflows")?;
    crate::retained_memory::charge(memory, expected)?;
    let copy = node.clone();
    let admitted = copy
        .owned_heap_bytes()
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| before.checked_add(bytes));
    let Some(admitted) = admitted else {
        drop(copy);
        memory.try_resize(before)?;
        return Err("Node copy memory overflows".into());
    };
    if let Err(error) = memory.try_resize(admitted) {
        drop(copy);
        memory.try_resize(before)?;
        return Err(Box::new(error));
    }
    Ok(copy)
}

fn selection_parts(
    selection: Option<ArtifactSelection>,
    graph_retained: bool,
) -> (Option<serde_json::Value>, Option<Vec<SourceRange>>) {
    let Some(mut selection) = selection else {
        return (None, None);
    };
    // An omitted Case stores the ranges directly on its artifact origin
    if graph_retained
        && !selection.source_ranges.is_empty()
        && let Some(fields) = selection.details.as_object_mut()
    {
        fields.insert(
            "source_ranges".to_owned(),
            serde_json::json!(&selection.source_ranges),
        );
    }
    (Some(selection.details), Some(selection.source_ranges))
}

struct ArtifactSourceProjection<'a> {
    source_ranges: Vec<SourceRange>,
    local_case_identity: Option<serde_json::Value>,
    local_case_scope: Option<&'a serde_json::Value>,
}

fn artifact_source_projection<'a>(
    context: &'a ArtifactSourceContext,
    node: Option<&Node>,
    selected_node_id: Option<u64>,
    selected_ranges: Option<Vec<SourceRange>>,
) -> ArtifactSourceProjection<'a> {
    let graph_retained = context.case_id.is_some();
    let source_backed = selected_ranges.as_ref().map_or_else(
        || node.is_some_and(|node| !node.ranges.is_empty()),
        |ranges| !ranges.is_empty(),
    );
    let source_ranges = match selected_ranges {
        Some(ranges) => ranges,
        None if graph_retained => Vec::new(),
        None => node.map_or_else(Vec::new, |node| node.ranges.clone()),
    };

    ArtifactSourceProjection {
        source_ranges,
        local_case_identity: (graph_retained && !source_backed).then(|| {
            serde_json::json!({
                "case_id": context.case_id,
                "node_id": selected_node_id,
            })
        }),
        local_case_scope: (graph_retained && !source_backed).then_some(&context.case_scope),
    }
}

fn canonical_node(node: &Node, case: &Case) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut ranges = node.ranges.clone();
    ranges.sort_by(|left, right| {
        (&left.source, left.packet, left.offset, left.length).cmp(&(
            &right.source,
            right.packet,
            right.offset,
            right.length,
        ))
    });
    let mut details = node.details.clone();
    canonicalize_node_references(&mut details, case)?;
    Ok(serde_json::json!({
        "kind": node.kind,
        "blob": node.blob,
        "ranges": ranges,
        "details": details,
    }))
}

fn canonical_selection(
    selection: &serde_json::Value,
    case: &Case,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut selection = selection.clone();
    if let Some(fields) = selection.as_object_mut() {
        fields.remove("id");
        fields.remove("selected_file_name");
    }
    canonicalize_node_references(&mut selection, case)?;
    Ok(selection)
}

fn canonical_nodes(nodes: &[Node], case: &Case) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    nodes
        .iter()
        .map(|node| canonical_node(node, case))
        .collect()
}

fn canonicalize_node_references(
    value: &mut serde_json::Value,
    case: &Case,
) -> Result<(), Box<dyn Error>> {
    match value {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields.iter_mut() {
                if is_node_reference_list(key) {
                    let value_type = json_type(value);
                    let references = value.as_array_mut().ok_or_else(|| {
                        node_reference_error(
                            key,
                            "expected an array of unsigned node IDs",
                            value_type,
                        )
                    })?;
                    for reference in references {
                        let node_id = reference.as_u64().ok_or_else(|| {
                            node_reference_error(
                                key,
                                "expected an unsigned node ID",
                                json_type(reference),
                            )
                        })?;
                        let node = case.node(node_id).ok_or_else(|| {
                            missing_node_reference_error(key, json_type(reference))
                        })?;
                        *reference = canonical_node_reference(node);
                    }
                } else if is_node_reference(key) {
                    // Null input_node is the documented multi-input form
                    if is_optional_node_reference(key) && value.is_null() {
                        continue;
                    }
                    let node_id = value.as_u64().ok_or_else(|| {
                        node_reference_error(key, "expected an unsigned node ID", json_type(value))
                    })?;
                    let node = case
                        .node(node_id)
                        .ok_or_else(|| missing_node_reference_error(key, json_type(value)))?;
                    *value = canonical_node_reference(node);
                } else {
                    canonicalize_node_references(value, case)?;
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                canonicalize_node_references(value, case)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_node_reference(key: &str) -> bool {
    key == "node_id" || key.ends_with("_node") || key.ends_with("_node_id")
}

fn is_node_reference_list(key: &str) -> bool {
    key == "node_ids" || key.ends_with("_node_ids")
}

fn is_optional_node_reference(key: &str) -> bool {
    key == "input_node"
}

fn canonical_node_reference(node: &Node) -> serde_json::Value {
    let mut ranges = node.ranges.clone();
    ranges.sort_by(|left, right| {
        (&left.source, left.packet, left.offset, left.length).cmp(&(
            &right.source,
            right.packet,
            right.offset,
            right.length,
        ))
    });
    serde_json::json!({
        "kind": node.kind,
        "blob": node.blob,
        "ranges": ranges,
    })
}
