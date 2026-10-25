//! Canonical DER inventory and primitive-value extraction

use super::{ExpansionService, WorkItem};
use l2_workbench::{
    artifact::{DerError, DerLimits, DerReport, DerTagClass, FileRange, parse_der},
    evidence::EvidenceStatus,
};
use serde_json::json;
use std::error::Error;

pub(super) fn try_expand(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    bytes: &[u8],
) -> Result<bool, Box<dyn Error>> {
    let limits = DerLimits {
        max_object_bytes: expansion.limits.input_bytes,
        max_depth: l2_workbench::artifact::MAX_DER_DEPTH,
        max_nodes: expansion.limits.objects,
        max_value_preview_bytes: 32,
    };
    let report = match parse_der(
        bytes,
        FileRange {
            offset: 0,
            length: bytes.len(),
        },
        limits,
    ) {
        Ok(report) => report,
        Err(DerError::InvalidDer) => return Ok(false),
        Err(DerError::NodeLimitExceeded { maximum }) => {
            expansion.omit(item.node, "der_node_limit", &json!({"maximum":maximum}))?;
            return Ok(true);
        }
        Err(DerError::DepthLimitExceeded { maximum }) => {
            expansion.omit(item.node, "der_depth_limit", &json!({"maximum":maximum}))?;
            return Ok(true);
        }
        Err(DerError::ObjectTooLarge { length, maximum }) => {
            expansion.omit(
                item.node,
                "der_input_byte_limit",
                &json!({"length":length,"maximum":maximum}),
            )?;
            return Ok(true);
        }
        Err(error) => return Err(error.into()),
    };
    let Some(structure) = expansion.reference_node(
        "der_structure",
        item.node,
        json!({
            "input_node":item.node,
            "depth":item.depth,
            "value_count":report.nodes.len(),
            "boundary_range":report.boundary_range
        }),
    )?
    else {
        return Ok(true);
    };
    expansion.edge(
        item.node,
        structure,
        "parsed_as",
        EvidenceStatus::Observed,
        "The exact retained boundary contains one complete DER encoding; supported universal primitive values passed canonical checks and tagged content remains schema-dependent",
    )?;

    add_values(expansion, item, bytes, structure, &report)?;
    Ok(true)
}

fn add_values(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    bytes: &[u8],
    structure: u64,
    report: &DerReport,
) -> Result<(), Box<dyn Error>> {
    let mut evidence_nodes = Vec::new();
    evidence_nodes.try_reserve(report.nodes.len())?;
    for (index, value) in report.nodes.iter().enumerate() {
        let parent = value
            .parent_index
            .and_then(|parent_index| evidence_nodes.get(parent_index).copied())
            .unwrap_or(structure);
        let details = json!({
            "der_node":item.node,
            "structure_node":structure,
            "value_index":index,
            "parent_index":value.parent_index,
            "depth":value.depth,
            "tag_class":tag_class(value.tag.class),
            "tag_number":value.tag.number,
            "constructed":value.tag.constructed,
            "encoded_range":value.encoded_range,
            "value_range":value.value_range,
            "oid":value.oid,
            "integer":value.integer.map(|metadata| json!({
                "negative":metadata.negative,
                "unsigned_value":metadata.unsigned_value,
                "length":value.value_range.length
            })),
            "octet_string":value.octet_string.map(|metadata| json!({"length":metadata.length})),
            "value_preview":value.value_preview,
            "preview_truncated":value.preview_truncated()
        });
        let evidence = if value.tag.constructed {
            expansion.reference_node("der_value", item.node, details)?
        } else {
            let start = value.value_range.offset;
            let end = start
                .checked_add(value.value_range.length)
                .ok_or("DER value range overflow")?;
            let raw = bytes
                .get(start..end)
                .ok_or("DER value range outside input")?;
            expansion.byte_node("der_value", item.node, raw, details)?
        };
        let Some(evidence) = evidence else {
            break;
        };
        expansion.edge(
            parent,
            evidence,
            "contains_der_value",
            EvidenceStatus::Observed,
            "Canonical DER tag and length fields bind this exact value range to its parent",
        )?;
        if !value.tag.constructed && value.value_range.length != 0 {
            expansion.enqueue(evidence, item.depth.saturating_add(1));
        }
        evidence_nodes.push(evidence);
    }
    Ok(())
}

const fn tag_class(class: DerTagClass) -> &'static str {
    match class {
        DerTagClass::Universal => "universal",
        DerTagClass::Application => "application",
        DerTagClass::ContextSpecific => "context_specific",
        DerTagClass::Private => "private",
    }
}
