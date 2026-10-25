//! Explicit concatenation of retained byte nodes with a durable part receipt

use super::{file_signatures, load, selected};
use crate::arguments::ConcatenateArgs;
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, MAX_EDGES};
use serde::Serialize;
use serde_json::json;
use std::{error::Error, io::Write};

const DETAILS_PART_PREVIEW: usize = 16;

#[derive(Serialize)]
struct ConcatenationPart {
    index: usize,
    input_node: u64,
    input_blob: String,
    input_sha256: String,
    input_length: usize,
    output_offset: usize,
    output_length: usize,
}

#[derive(Serialize)]
struct ConcatenationReceipt<'a> {
    schema_version: u32,
    parts: &'a [ConcatenationPart],
    output_length: usize,
    output_sha256: &'a str,
    interpretation: &'static str,
}

pub(super) fn run(args: &ConcatenateArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    if args.nodes.len()
        > MAX_EDGES
            .saturating_sub(case.edges().len())
            .saturating_sub(1)
    {
        return Err("concatenation parts exceed the remaining evidence relationship budget".into());
    }
    let (bytes, parts) = collect(&case, &args.nodes, args.max_output_bytes.get())?;
    let output_sha256 = l2_workbench::sha256(&bytes);
    let receipt = serde_json::to_vec(&ConcatenationReceipt {
        schema_version: 1,
        parts: &parts,
        output_length: bytes.len(),
        output_sha256: &output_sha256,
        interpretation: "caller_selected_byte_node_order",
    })?;
    let receipt_node = case.add_bytes_node(
        "concatenation_receipt",
        &receipt,
        Vec::new(),
        json!({
            "part_count":parts.len(),
            "output_length":bytes.len(),
            "output_sha256":output_sha256,
            "representation":"json_blob"
        }),
    )?;
    let preview = parts.iter().take(DETAILS_PART_PREVIEW).collect::<Vec<_>>();
    let object = case.add_bytes_node(
        "concatenated_object",
        &bytes,
        Vec::new(),
        json!({
            "receipt_node":receipt_node,
            "part_count":parts.len(),
            "parts":preview,
            "omitted_part_previews":parts.len().saturating_sub(preview.len()),
            "output_length":bytes.len(),
            "output_sha256":output_sha256
        }),
    )?;
    case.add_edge(Edge {
        from: receipt_node,
        to: object,
        relation: "describes".to_owned(),
        status: EvidenceStatus::Observed,
        reason:
            "The receipt records every selected input blob and its exact half-open output interval"
                .to_owned(),
    })?;
    for part in &parts {
        case.add_edge(Edge {
            from: part.input_node,
            to: object,
            relation: "concatenated_into".to_owned(),
            status: EvidenceStatus::Observed,
            reason: format!(
                "Input part {} occupies output offset {} for {} bytes",
                part.index, part.output_offset, part.output_length
            ),
        })?;
    }
    file_signatures::add(&mut case, object, &bytes)?;
    case.add_limitation(
        "Concatenation order is caller supplied; the receipt establishes exact byte construction but not protocol meaning",
    )?;
    case.write_json(output)?;
    Ok(case.collection_complete())
}

fn collect(
    case: &Case,
    nodes: &[u64],
    maximum: usize,
) -> Result<(Vec<u8>, Vec<ConcatenationPart>), Box<dyn Error>> {
    let mut total = 0_usize;
    let mut selected_inputs = Vec::new();
    selected_inputs.try_reserve(nodes.len())?;
    for node in nodes {
        let (evidence, bytes) = selected::bytes(case, *node)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("concatenated output length overflow")?;
        if total > maximum {
            return Err(
                format!("concatenated output has {total} bytes; maximum is {maximum}").into(),
            );
        }
        selected_inputs.push((*node, evidence, bytes));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(total)?;
    let mut parts = Vec::new();
    parts.try_reserve(nodes.len())?;
    for (index, (node, evidence, bytes)) in selected_inputs.into_iter().enumerate() {
        let blob = evidence
            .blob
            .clone()
            .ok_or("concatenation input has no retained byte blob")?;
        let output_offset = output.len();
        output.extend_from_slice(bytes);
        let length = bytes.len();
        parts.push(ConcatenationPart {
            index,
            input_node: node,
            input_blob: blob,
            input_sha256: l2_workbench::sha256(bytes),
            input_length: length,
            output_offset,
            output_length: length,
        });
    }
    Ok((output, parts))
}
