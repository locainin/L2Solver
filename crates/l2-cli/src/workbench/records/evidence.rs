use super::super::file_signatures;
use super::analysis::Analysis;
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    protocol::{RecordError, RecordGroupReceipt},
};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
};

pub(super) struct GroupNodes {
    pub(super) groups: Vec<u64>,
    pub(super) issues: Vec<u64>,
}

struct GroupContext<'a> {
    input_nodes: &'a [u64],
    receipt_node: u64,
    group_index: usize,
    receipt: &'a RecordGroupReceipt,
    terminal_sequence: Option<u64>,
    force_unresolved: bool,
}

pub(super) fn add_receipt_node(
    case: &mut Case,
    analysis: &Analysis,
) -> Result<u64, Box<dyn Error>> {
    let complete_groups = analysis
        .assembly
        .groups()
        .iter()
        .filter(|group| group.receipt().complete)
        .count();
    let incomplete_groups = analysis
        .assembly
        .groups()
        .len()
        .saturating_sub(complete_groups);
    let record_count = analysis
        .assembly
        .groups()
        .iter()
        .map(|group| group.receipt().record_count)
        .sum::<usize>();
    Ok(case.add_bytes_node(
        "record_parse_receipt",
        &analysis.receipt,
        Vec::new(),
        json!({
            "input_node":(analysis.inputs.len() == 1)
                .then(|| analysis.inputs.first().map(|input| input.node))
                .flatten(),
            "input_count":analysis.inputs.len(),
            "input_length":analysis.assembly.report().input_length,
            "record_count":record_count,
            "group_count":analysis.assembly.groups().len(),
            "complete_group_count":complete_groups,
            "incomplete_group_count":incomplete_groups,
            "representation":"json_blob"
        }),
    )?)
}

pub(super) fn record_groups(
    case: &mut Case,
    receipt_node: u64,
    analysis: &Analysis,
) -> Result<GroupNodes, Box<dyn Error>> {
    let group_input_nodes = group_input_nodes(analysis)?;
    let force_unresolved = !analysis.rejected_inputs.is_empty();
    let mut group_nodes = Vec::new();
    group_nodes
        .try_reserve_exact(analysis.assembly.groups().len())
        .map_err(|_| RecordError::AllocationFailed)?;
    let mut issue_nodes = Vec::new();
    issue_nodes
        .try_reserve_exact(analysis.assembly.groups().len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for (group_index, group) in analysis.assembly.groups().iter().enumerate() {
        let input_nodes = group_input_nodes
            .get(group_index)
            .ok_or("record group provenance is missing")?;
        let complete_bytes = group.bytes();
        if let Some(bytes) = complete_bytes.filter(|_| !force_unresolved) {
            let context = GroupContext {
                input_nodes,
                receipt_node,
                group_index,
                receipt: group.receipt(),
                terminal_sequence: analysis.assembly.report().terminal_sequence,
                force_unresolved: false,
            };
            let group_node = add_complete_group(case, &context, bytes)?;
            group_nodes.push(group_node);
        } else {
            let context = GroupContext {
                input_nodes,
                receipt_node,
                group_index,
                receipt: group.receipt(),
                terminal_sequence: (!force_unresolved)
                    .then_some(analysis.assembly.report().terminal_sequence)
                    .flatten(),
                force_unresolved,
            };
            let group_node = add_candidate_group(case, &context, group.candidate_bytes())?;
            group_nodes.push(group_node);
            if !force_unresolved || complete_bytes.is_none() {
                let issue_node = add_group_issue(case, &context)?;
                issue_nodes.push(issue_node);
            }
        }
    }
    Ok(GroupNodes {
        groups: group_nodes,
        issues: issue_nodes,
    })
}

fn group_input_nodes(analysis: &Analysis) -> Result<Vec<Vec<u64>>, RecordError> {
    // Reuse exact mappings to record the first input position for each source node
    let mut result = Vec::new();
    result
        .try_reserve_exact(analysis.assembly.groups().len())
        .map_err(|_| RecordError::AllocationFailed)?;
    for group in analysis.assembly.groups() {
        let mut first_input_by_node = HashMap::<u64, usize>::new();
        for part in &group.receipt().parts {
            let original_index = analysis
                .assembly_input_indexes
                .get(part.input_index)
                .copied()
                .ok_or(RecordError::InvalidReport)?;
            let input = analysis
                .inputs
                .get(original_index)
                .ok_or(RecordError::InvalidReport)?;
            if let Some(first_index) = first_input_by_node.get_mut(&input.node) {
                *first_index = (*first_index).min(part.input_index);
            } else {
                first_input_by_node
                    .try_reserve(1)
                    .map_err(|_| RecordError::AllocationFailed)?;
                first_input_by_node.insert(input.node, part.input_index);
            }
        }
        let mut ordered_nodes = Vec::new();
        ordered_nodes
            .try_reserve_exact(first_input_by_node.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        for (node, first_index) in first_input_by_node {
            ordered_nodes.push((first_index, node));
        }
        ordered_nodes.sort_unstable_by_key(|(first_index, _)| *first_index);
        let mut group_nodes = Vec::new();
        group_nodes
            .try_reserve_exact(ordered_nodes.len())
            .map_err(|_| RecordError::AllocationFailed)?;
        for (_, node) in ordered_nodes {
            group_nodes.push(node);
        }
        result.push(group_nodes);
    }
    Ok(result)
}

pub(super) fn add_receipt_edges(
    case: &mut Case,
    receipt_node: u64,
    analysis: &Analysis,
) -> Result<(), Box<dyn Error>> {
    let mut count_nodes = BTreeSet::new();
    for input in &analysis.inputs {
        if let Some(source) = &input.count_source {
            count_nodes.insert(source.node);
        }
    }
    let mut rejected = analysis.rejected_inputs.iter().peekable();
    for (input_index, input) in analysis.inputs.iter().enumerate() {
        let is_rejected = rejected
            .peek()
            .is_some_and(|item| item.input_index == input_index);
        if is_rejected {
            rejected.next();
        }
        case.add_edge(Edge {
            from: input.node,
            to: receipt_node,
            relation: if is_rejected {
                "record_parse_rejected".to_owned()
            } else {
                "parsed_by".to_owned()
            },
            status: if is_rejected {
                EvidenceStatus::ConstraintFailed
            } else {
                EvidenceStatus::Observed
            },
            reason: if is_rejected {
                "The strict record parser found a contradiction for this ordered input".to_owned()
            } else {
                "The receipt records an explicit record schema, exact input digest, parsed ranges, and complete per-part consumption".to_owned()
            },
        })?;
    }
    for node in count_nodes {
        case.add_edge(Edge {
            from: node,
            to: receipt_node,
            relation: "supplied_record_count".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The receipt records the exact retained byte range, byte order, digest, and decoded count applied to its ordered input part".to_owned(),
        })?;
    }
    Ok(())
}

fn add_complete_group(
    case: &mut Case,
    context: &GroupContext<'_>,
    bytes: &[u8],
) -> Result<u64, Box<dyn Error>> {
    let object = case.add_bytes_node("record_object", bytes, Vec::new(), group_details(context))?;
    file_signatures::add(case, object, bytes)?;
    for input_node in context.input_nodes {
        case.add_edge(Edge {
            from: *input_node,
            to: object,
            relation: "assembled_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The parse receipt maps this source's exact payload ranges to intervals in the complete assembled object".to_owned(),
        })?;
    }
    case.add_edge(Edge {
        from: context.receipt_node,
        to: object,
        relation: "produced".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The complete group receipt maps every output interval to one parsed input part and payload range".to_owned(),
    })?;
    Ok(object)
}

fn add_candidate_group(
    case: &mut Case,
    context: &GroupContext<'_>,
    bytes: &[u8],
) -> Result<u64, Box<dyn Error>> {
    let candidate = case.add_bytes_node(
        "record_candidate",
        bytes,
        Vec::new(),
        group_details(context),
    )?;
    file_signatures::add(case, candidate, bytes)?;
    for input_node in context.input_nodes {
        case.add_edge(Edge {
            from: *input_node,
            to: candidate,
            relation: "candidate_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The parse receipt maps the retained candidate bytes to observed payload ranges from this source".to_owned(),
        })?;
    }
    case.add_edge(Edge {
        from: context.receipt_node,
        to: candidate,
        relation: "retained_candidate".to_owned(),
        status: EvidenceStatus::Unresolved,
        reason: "Observed payloads are preserved for downstream checks without establishing a complete object boundary".to_owned(),
    })?;
    Ok(candidate)
}

fn add_group_issue(case: &mut Case, context: &GroupContext<'_>) -> Result<u64, Box<dyn Error>> {
    let issue = case.add_node(
        "record_group_issue",
        None,
        Vec::new(),
        json!({
            "receipt_node":context.receipt_node,
            "group_index":context.group_index,
            "input_node":(context.input_nodes.len() == 1)
                .then(|| context.input_nodes.first().copied())
                .flatten(),
            "input_count":context.input_nodes.len(),
            "identifier_length":context.receipt.identifier.len(),
            "identifier_sha256":l2_workbench::sha256(&context.receipt.identifier),
            "record_count":context.receipt.record_count,
            "sequence_base":context.receipt.sequence_base,
            "terminal_sequence":context.terminal_sequence,
            "completion_basis":completion_basis(context.terminal_sequence),
            "minimum_sequence":context.receipt.minimum_sequence,
            "maximum_sequence":context.receipt.maximum_sequence,
            "missing_sequence_count":context.receipt.missing_sequence_count,
            "duplicate_sequence_count":context.receipt.duplicate_sequences.len()
                + context.receipt.omitted_duplicate_sequences,
            "sequences_before_base_count":context.receipt.sequences_before_base.len()
                + context.receipt.omitted_sequences_before_base,
            "sequences_after_terminal_count":context.receipt.sequences_after_terminal.len()
                + context.receipt.omitted_sequences_after_terminal,
            "omitted_missing_sequences":context.receipt.omitted_missing_sequences,
            "omitted_duplicate_sequences":context.receipt.omitted_duplicate_sequences,
            "omitted_sequences_before_base":context.receipt.omitted_sequences_before_base,
            "omitted_sequences_after_terminal":context.receipt.omitted_sequences_after_terminal
        }),
    )?;
    for input_node in context.input_nodes {
        case.add_edge(Edge {
            from: *input_node,
            to: issue,
            relation: "observed_in_group".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "This input contains one or more records in the diagnosed identifier group"
                .to_owned(),
        })?;
    }
    case.add_edge(Edge {
        from: context.receipt_node,
        to: issue,
        relation: "reported".to_owned(),
        status: EvidenceStatus::Unresolved,
        reason: if context.terminal_sequence.is_none() {
            "No operator-supplied terminal sequence establishes an end; observed payload bytes remain a prefix candidate".to_owned()
        } else {
            "Missing, repeated, pre-base, or beyond-terminal sequence evidence prevents complete object assembly".to_owned()
        },
    })?;
    Ok(issue)
}

fn group_details(context: &GroupContext<'_>) -> serde_json::Value {
    let preview_length = context.receipt.identifier.len().min(32);
    let preview = context
        .receipt
        .identifier
        .get(..preview_length)
        .unwrap_or_default();
    json!({
        "input_node":(context.input_nodes.len() == 1)
            .then(|| context.input_nodes.first().copied())
            .flatten(),
        "input_count":context.input_nodes.len(),
        "receipt_node":context.receipt_node,
        "group_index":context.group_index,
        "identifier_length":context.receipt.identifier.len(),
        "identifier_sha256":l2_workbench::sha256(&context.receipt.identifier),
        "identifier_preview":preview,
        "record_count":context.receipt.record_count,
        "group_complete":context.receipt.complete && !context.force_unresolved,
        "assembly_complete":context.receipt.complete && !context.force_unresolved,
        "sequence_base":context.receipt.sequence_base,
        "terminal_sequence":context.terminal_sequence,
        "completion_basis":completion_basis(context.terminal_sequence),
        "minimum_sequence":context.receipt.minimum_sequence,
        "maximum_sequence":context.receipt.maximum_sequence,
        "output_length":context.receipt.output_length,
        "output_sha256":context.receipt.output_sha256
    })
}

const fn completion_basis(terminal_sequence: Option<u64>) -> &'static str {
    if terminal_sequence.is_some() {
        "operator_terminal_sequence"
    } else {
        "observed_prefix_only"
    }
}
