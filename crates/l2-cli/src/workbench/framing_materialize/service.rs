use l2_workbench::{
    carrier::discovery::{DiscoveryMapping, mapped_node},
    evidence::{
        ByteMapping, Case, CheckedByteMappingCursor, Edge, EvidenceError, EvidenceStatus,
        clip_byte_mappings,
    },
    protocol::{self, BoundaryStatus, ByteRange, FrameBoundary, FramingKind},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error, ops::Range};

const FRAMING_LIMITATION: &str = "Materialized frame boundaries remain a selected hypothesis and do not establish an application grammar";
const FRAMED_REASON: &str = "This exact byte interval follows the selected rule; the rule does not establish an application message boundary";
const TAIL_REASON: &str =
    "These exact remaining bytes follow the selected rule's incomplete or invalid boundary result";
pub(in crate::workbench) const FRAME_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::workbench) struct FramingOutcome {
    pub(in crate::workbench) receipt_node: u64,
    pub(in crate::workbench) frame_nodes: Vec<u64>,
    pub(in crate::workbench) tail_node: Option<u64>,
    pub(in crate::workbench) status: BoundaryStatus,
}

/// Provenance for the rule selected to materialize frame boundaries
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::workbench) enum FramingSelectionBasis {
    /// The rule was supplied directly by the caller
    CallerSupplied {},
    /// The rule was selected from one retained framing discovery report
    Discovered { report_node: u64 },
    /// The same rule was supplied directly and selected from one discovery report
    CallerAndDiscovered { report_node: u64 },
}

impl FramingSelectionBasis {
    pub(in crate::workbench) const fn report_node(self) -> Option<u64> {
        match self {
            Self::CallerSupplied {} => None,
            Self::Discovered { report_node } | Self::CallerAndDiscovered { report_node } => {
                Some(report_node)
            }
        }
    }
}

struct Selection {
    input_kind: String,
    input_blob: String,
    input_bytes: Vec<u8>,
    mappings: Vec<ByteMapping>,
}

/// Exact selected boundaries and output size before frame evidence is committed
pub(in crate::workbench) struct PreparedFraming {
    input_node: u64,
    selection: Selection,
    rule: FramingKind,
    basis: FramingSelectionBasis,
    output_bytes: usize,
}

impl PreparedFraming {
    pub(in crate::workbench) const fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

struct MaterializedFrames {
    nodes: Vec<u64>,
    status: BoundaryStatus,
    trailing: Option<ByteRange>,
    tail_node: Option<u64>,
}

struct MaterializationContext<'a> {
    input_node: u64,
    selection: &'a Selection,
}

#[derive(Serialize)]
struct FramingReceipt<'a> {
    schema_version: u32,
    input_node: u64,
    input_kind: &'a str,
    input_blob: &'a str,
    input_length: usize,
    input_sha256: &'a str,
    framing_rule: &'a FramingKind,
    selection_basis: FramingSelectionBasis,
    status: BoundaryStatus,
    frame_count: usize,
    trailing: Option<ByteRange>,
    issue_offset: Option<usize>,
}

/// Materialize one exact framing interpretation and its evidence atomically
pub(in crate::workbench) fn apply(
    case: &mut Case,
    input_node: u64,
    rule: &FramingKind,
) -> Result<FramingOutcome, Box<dyn Error>> {
    apply_with_basis(
        case,
        input_node,
        rule,
        FramingSelectionBasis::CallerSupplied {},
    )
}

/// Materialize one exact framing interpretation and its typed selection provenance atomically
pub(in crate::workbench) fn apply_with_basis(
    case: &mut Case,
    input_node: u64,
    rule: &FramingKind,
    basis: FramingSelectionBasis,
) -> Result<FramingOutcome, Box<dyn Error>> {
    let prepared = prepare_recovery_with_basis(case, input_node, rule, basis)?;
    commit_recovery(case, prepared)
}

/// Parse exact ranges and verify the selected provenance without writing evidence nodes
pub(in crate::workbench) fn prepare_recovery_with_basis(
    case: &Case,
    input_node: u64,
    rule: &FramingKind,
    basis: FramingSelectionBasis,
) -> Result<PreparedFraming, Box<dyn Error>> {
    validate_selection_basis(case, basis)?;
    let selection = select_input(case, input_node)?;
    let mut output_bytes = 0_usize;
    for boundary in protocol::frame_boundaries(&selection.input_bytes, rule) {
        let range = match boundary {
            FrameBoundary::Frame(range) | FrameBoundary::Tail { range, .. } => range,
        };
        let range_length = range
            .end
            .checked_sub(range.start)
            .ok_or("invalid frame range")?;
        output_bytes = output_bytes
            .checked_add(range_length)
            .ok_or("framing output length overflowed")?;
    }
    Ok(PreparedFraming {
        input_node,
        selection,
        rule: rule.clone(),
        basis,
        output_bytes,
    })
}

/// Commit prechecked frame ranges atomically to the recovery-owned Case
pub(in crate::workbench) fn commit_recovery(
    case: &mut Case,
    prepared: PreparedFraming,
) -> Result<FramingOutcome, Box<dyn Error>> {
    let PreparedFraming {
        input_node,
        selection,
        rule,
        basis,
        ..
    } = prepared;
    case.transaction(|case| {
        validate_selection_basis(case, basis)?;
        let materialized = materialize(case, input_node, &selection, &rule)?;
        let receipt_node = add_receipt(case, input_node, &selection, &rule, basis, &materialized)?;
        link_receipt(case, input_node, receipt_node, basis, &materialized)?;
        case.add_limitation(FRAMING_LIMITATION)?;
        Ok(FramingOutcome {
            receipt_node,
            frame_nodes: materialized.nodes,
            tail_node: materialized.tail_node,
            status: materialized.status,
        })
    })
}

fn add_receipt(
    case: &mut Case,
    input_node: u64,
    selection: &Selection,
    rule: &FramingKind,
    basis: FramingSelectionBasis,
    materialized: &MaterializedFrames,
) -> Result<u64, Box<dyn Error>> {
    let input_sha256 = l2_workbench::sha256(&selection.input_bytes);
    let receipt = FramingReceipt {
        schema_version: FRAME_SCHEMA_VERSION,
        input_node,
        input_kind: &selection.input_kind,
        input_blob: &selection.input_blob,
        input_length: selection.input_bytes.len(),
        input_sha256: &input_sha256,
        framing_rule: rule,
        selection_basis: basis,
        status: materialized.status,
        frame_count: materialized.nodes.len(),
        trailing: materialized.trailing,
        issue_offset: materialized.trailing.map(|range| range.start),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)?;
    Ok(case.add_bytes_node(
        "custom_protocol_framing_receipt",
        &receipt_bytes,
        Vec::new(),
        json!({
            "representation":"json_blob",
            "receipt_schema_version":FRAME_SCHEMA_VERSION,
            "input_node":input_node,
            "input_length":selection.input_bytes.len(),
            "input_sha256":input_sha256,
            "framing_rule":rule,
            "selection_basis":basis,
            "status":materialized.status,
            "frame_count":materialized.nodes.len(),
            "trailing":materialized.trailing,
        }),
    )?)
}

fn link_receipt(
    case: &mut Case,
    input_node: u64,
    receipt_node: u64,
    basis: FramingSelectionBasis,
    materialized: &MaterializedFrames,
) -> Result<(), Box<dyn Error>> {
    add_edge(
        case,
        input_node,
        receipt_node,
        "framing_tested_by",
        "The receipt records the selected rule, exact input digest, frame count, and any remaining bytes",
    )?;
    if let Some(report_node) = basis.report_node() {
        add_edge(
            case,
            report_node,
            receipt_node,
            "framing_rule_selected_from",
            "The selected framing rule is associated with this retained discovery report",
        )?;
    }
    for frame in &materialized.nodes {
        add_edge(
            case,
            receipt_node,
            *frame,
            "materialized",
            "The receipt records the selected framing rule used for this exact byte range",
        )?;
    }
    if let Some(tail) = materialized.tail_node {
        add_edge(
            case,
            receipt_node,
            tail,
            "materialized",
            "The receipt records the selected framing rule and exact remaining byte range",
        )?;
    }
    Ok(())
}

fn add_edge(
    case: &mut Case,
    from: u64,
    to: u64,
    relation: &str,
    reason: &str,
) -> Result<(), EvidenceError> {
    case.add_edge(Edge {
        from,
        to,
        relation: relation.to_owned(),
        status: EvidenceStatus::Observed,
        reason: reason.to_owned(),
    })
}

fn materialize(
    case: &mut Case,
    input_node: u64,
    selection: &Selection,
    rule: &FramingKind,
) -> Result<MaterializedFrames, Box<dyn Error>> {
    let context = MaterializationContext {
        input_node,
        selection,
    };
    let mut result = MaterializedFrames {
        nodes: Vec::new(),
        status: BoundaryStatus::Complete,
        trailing: None,
        tail_node: None,
    };
    let mut cursor = CheckedByteMappingCursor::new(&selection.mappings)?;
    for boundary in protocol::frame_boundaries(&selection.input_bytes, rule) {
        match boundary {
            FrameBoundary::Frame(range) => {
                let frame_index = result.nodes.len();
                let frame = add_frame(case, &context, range, frame_index, &mut cursor)?;
                result.nodes.try_reserve(1)?;
                result.nodes.push(frame);
            }
            FrameBoundary::Tail { range, status } => {
                result.tail_node = Some(add_tail(case, &context, range, status, &mut cursor)?);
                result.status = status;
                result.trailing = Some(range);
            }
        }
    }
    Ok(result)
}

fn add_frame(
    case: &mut Case,
    context: &MaterializationContext<'_>,
    range: ByteRange,
    frame_index: usize,
    cursor: &mut Option<CheckedByteMappingCursor<'_>>,
) -> Result<u64, Box<dyn Error>> {
    let bytes = byte_range(&context.selection.input_bytes, range)?;
    let mappings = clip_mappings(&context.selection.mappings, cursor, range.start..range.end)?;
    let frame = case.add_mapped_bytes_node(
        "custom_protocol_frame",
        bytes,
        &mappings,
        json!({
            "framing_schema_version":FRAME_SCHEMA_VERSION,
            "input_node":context.input_node,
            "frame_index":frame_index,
            "stream_start":range.start,
            "stream_end":range.end,
            "sha256":l2_workbench::sha256(bytes),
        }),
    )?;
    case.add_edge(Edge {
        from: context.input_node,
        to: frame,
        relation: "candidate_framed_as".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: FRAMED_REASON.to_owned(),
    })?;
    Ok(frame)
}

fn add_tail(
    case: &mut Case,
    context: &MaterializationContext<'_>,
    range: ByteRange,
    status: BoundaryStatus,
    cursor: &mut Option<CheckedByteMappingCursor<'_>>,
) -> Result<u64, Box<dyn Error>> {
    let bytes = byte_range(&context.selection.input_bytes, range)?;
    let mappings = clip_mappings(&context.selection.mappings, cursor, range.start..range.end)?;
    let tail = case.add_mapped_bytes_node(
        "custom_protocol_framing_tail",
        bytes,
        &mappings,
        json!({
            "framing_schema_version":FRAME_SCHEMA_VERSION,
            "input_node":context.input_node,
            "stream_start":range.start,
            "stream_end":range.end,
            "status":status,
            "issue_offset":range.start,
            "sha256":l2_workbench::sha256(bytes),
        }),
    )?;
    case.add_edge(Edge {
        from: context.input_node,
        to: tail,
        relation: "candidate_framing_tail".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: TAIL_REASON.to_owned(),
    })?;
    Ok(tail)
}

/// Read the exact stored range from a compact or legacy materialized frame
pub(in crate::workbench) fn frame_stream_range(details: &Value) -> Option<ByteRange> {
    match details.get("framing_schema_version") {
        None if details.get("stream_start").is_none() && details.get("stream_end").is_none() => {
            serde_json::from_value(details.get("stream_range")?.clone()).ok()
        }
        Some(version) if version.as_u64() == Some(u64::from(FRAME_SCHEMA_VERSION)) => {
            if details.get("stream_range").is_some() {
                return None;
            }
            Some(ByteRange {
                start: usize::try_from(details.get("stream_start")?.as_u64()?).ok()?,
                end: usize::try_from(details.get("stream_end")?.as_u64()?).ok()?,
            })
        }
        _ => None,
    }
}

fn validate_selection_basis(
    case: &Case,
    basis: FramingSelectionBasis,
) -> Result<(), Box<dyn Error>> {
    let Some(report_node) = basis.report_node() else {
        return Ok(());
    };
    retained_discovery_report(case, report_node).map(|_| ())
}

/// Check caller-specified discovery provenance when the retained report includes candidates
pub(in crate::workbench) fn validate_cli_discovered_rule(
    case: &Case,
    report_node: u64,
    rule: &FramingKind,
) -> Result<(), Box<dyn Error>> {
    let report = retained_discovery_report(case, report_node)?;
    let selected_rule = serde_json::to_value(rule)?;
    let hypotheses = report
        .pointer("/bootstrap/hypotheses")
        .and_then(serde_json::Value::as_array)
        .ok_or("selected framing discovery report has no retained hypotheses")?;
    if !hypotheses
        .iter()
        .any(|hypothesis| hypothesis == &selected_rule)
    {
        return Err("selected framing rule is not listed in the discovery report".into());
    }
    Ok(())
}

fn retained_discovery_report(
    case: &Case,
    report_node_id: u64,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let report_node = case
        .nodes()
        .iter()
        .find(|node| node.id == report_node_id)
        .ok_or("selected framing discovery report is missing")?;
    if report_node.kind != "recovery_framing_discovery_report" {
        return Err("selected node is not a framing discovery report".into());
    }
    let report_blob = report_node
        .blob
        .as_deref()
        .and_then(|blob_id| case.blob(blob_id))
        .ok_or("selected framing discovery report has no retained bytes")?;
    let report: serde_json::Value = serde_json::from_slice(&report_blob.bytes)?;
    let has_source_identity = report
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|source_id| !source_id.is_empty());
    if report.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || report.get("case_scope").and_then(serde_json::Value::as_str) != Some("current_case")
        || !has_source_identity
        || !report
            .get("cohort")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("selected framing discovery report has an unsupported schema".into());
    }
    Ok(report)
}

fn clip_mappings(
    mappings: &[ByteMapping],
    cursor: &mut Option<CheckedByteMappingCursor<'_>>,
    range: Range<usize>,
) -> Result<Vec<ByteMapping>, EvidenceError> {
    let Some(mapping_cursor) = cursor.as_mut() else {
        return clip_byte_mappings(mappings, range);
    };
    if let Some(clipped) = mapping_cursor.clip_range(range.clone())? {
        return Ok(clipped);
    }
    *cursor = None;
    clip_byte_mappings(mappings, range)
}

fn select_input(case: &Case, node_id: u64) -> Result<Selection, Box<dyn Error>> {
    let node = case
        .node(node_id)
        .ok_or("selected framing node is missing")?;
    if node.kind == "decoding_output" {
        return select_contextual_output(case, node);
    }
    if node.kind != "tcp_byte_run" {
        return Err(
            "selected node must be a retained TCP run or contextual transform output".into(),
        );
    }
    let mapped = mapped_node(case, node_id)?;
    if mapped.bytes.is_empty() {
        return Err("selected framing input is empty".into());
    }
    let input_blob = mapped
        .node
        .blob
        .clone()
        .ok_or("selected framing input has no retained blob")?;
    let mut input_bytes = Vec::new();
    input_bytes.try_reserve_exact(mapped.bytes.len())?;
    input_bytes.extend_from_slice(mapped.bytes);
    let mut mappings = Vec::new();
    mappings.try_reserve_exact(mapped.mappings.len())?;
    mappings.extend(mapped.mappings.into_iter().map(to_mapping));
    Ok(Selection {
        input_kind: mapped.node.kind.clone(),
        input_blob,
        input_bytes,
        mappings,
    })
}

fn select_contextual_output(
    case: &Case,
    node: &l2_workbench::evidence::Node,
) -> Result<Selection, Box<dyn Error>> {
    let source_input_node = node
        .details
        .get("source_input_node")
        .and_then(serde_json::Value::as_u64)
        .filter(|node_id| *node_id != 0)
        .ok_or("contextual transform output has no source input")?;
    let receipt_node_id = node
        .details
        .get("shared_transform_receipt")
        .and_then(serde_json::Value::as_u64)
        .filter(|node_id| *node_id != 0)
        .ok_or("contextual transform output has no decoder receipt")?;
    if !node.ranges.is_empty() {
        return Err("contextual transform output has invalid source provenance".into());
    }
    let receipt_node = case
        .node(receipt_node_id)
        .filter(|receipt| receipt.kind == "decoding_receipt")
        .ok_or("contextual transform output has an invalid decoder receipt")?;
    let (blob_id, bytes) =
        validate_contextual_decoder_receipt(case, receipt_node, source_input_node, node)?;
    if bytes.is_empty() {
        return Err("selected framing input is empty".into());
    }
    let mut input_bytes = Vec::new();
    input_bytes.try_reserve_exact(bytes.len())?;
    input_bytes.extend_from_slice(bytes);
    Ok(Selection {
        input_kind: node.kind.clone(),
        input_blob: blob_id.to_owned(),
        input_bytes,
        mappings: Vec::new(),
    })
}

fn validate_contextual_decoder_receipt<'a>(
    case: &'a Case,
    receipt_node: &'a l2_workbench::evidence::Node,
    source_input_node_id: u64,
    output_node: &'a l2_workbench::evidence::Node,
) -> Result<(&'a str, &'a [u8]), Box<dyn Error>> {
    let source_input = case
        .node(source_input_node_id)
        .ok_or("contextual transform source input is missing")?;
    if receipt_node.details.get("operation_completed") != Some(&serde_json::Value::Bool(true))
        || receipt_node.details.get("constraints_satisfied") != Some(&serde_json::Value::Bool(true))
    {
        return Err("contextual transform output does not have a completed decoder receipt".into());
    }

    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or("decoder receipt has no retained bytes")?;
    let receipt_blob = case
        .blob(receipt_blob_id)
        .ok_or("decoder receipt bytes are missing")?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)?;
    let source_blob_id = source_input
        .blob
        .as_deref()
        .ok_or("contextual transform source input has no retained blob")?;
    let source_blob = case
        .blob(source_blob_id)
        .ok_or("contextual transform source input bytes are missing")?;
    let output_blob_id = output_node
        .blob
        .as_deref()
        .ok_or("contextual transform output has no retained blob")?;
    let output_blob = case
        .blob(output_blob_id)
        .ok_or("contextual transform output bytes are missing")?;

    // Blob IDs already carry the digest checked by Case, so reuse them for receipt matching
    let input_length = receipt
        .get("input_length")
        .and_then(serde_json::Value::as_u64)
        .and_then(|length| usize::try_from(length).ok());
    let input_sha256 = receipt
        .get("input_sha256")
        .and_then(serde_json::Value::as_str);
    let output_length = receipt
        .get("output_length")
        .and_then(serde_json::Value::as_u64)
        .and_then(|length| usize::try_from(length).ok());
    let output_sha256 = receipt
        .get("output_sha256")
        .and_then(serde_json::Value::as_str);
    if input_length != Some(source_blob.bytes.len())
        || input_sha256 != source_blob_id.strip_prefix("sha256:")
        || output_length != Some(output_blob.bytes.len())
        || output_sha256 != output_blob_id.strip_prefix("sha256:")
    {
        return Err("decoder receipt does not match the contextual output bytes".into());
    }
    Ok((output_blob_id, output_blob.bytes.as_slice()))
}

fn to_mapping(mapping: DiscoveryMapping) -> ByteMapping {
    ByteMapping {
        offset: mapping.offset,
        range: mapping.range,
    }
}

fn byte_range(bytes: &[u8], range: ByteRange) -> Result<&[u8], Box<dyn Error>> {
    bytes
        .get(range.start..range.end)
        .ok_or_else(|| "selected rule returned an out-of-range byte interval".into())
}
