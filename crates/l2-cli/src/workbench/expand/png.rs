//! PNG chunk extraction with CRC-checked object-relative ranges

use super::{CandidateRejection, ExpansionError, ExpansionService, WorkItem};
use l2_workbench::{
    artifact::{PngError, PngLimits, PngReport, parse_png},
    evidence::EvidenceStatus,
};
use serde_json::json;
use std::error::Error;

pub(super) fn expand(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    bytes: &[u8],
) -> Result<(), ExpansionError> {
    let report = match parse_png(
        bytes,
        PngLimits {
            max_input_bytes: expansion.limits.input_bytes,
            max_chunks: expansion.limits.objects,
        },
    ) {
        Ok(report) => report,
        Err(PngError::TooManyChunks { maximum }) => {
            expansion.omit(item.node, "png_chunk_limit", &json!({"maximum":maximum}))?;
            return Ok(());
        }
        Err(PngError::InputTooLarge { length, maximum }) => {
            expansion.omit(
                item.node,
                "png_input_byte_limit",
                &json!({"length":length,"maximum":maximum}),
            )?;
            return Ok(());
        }
        // Invalid parser configuration is a service failure, not a rejected candidate
        Err(error @ PngError::InvalidLimits) => {
            return Err(ExpansionError::invariant(error));
        }
        Err(error) => {
            return Err(ExpansionError::Rejected(CandidateRejection {
                node: item.node,
                format: "png",
                message: error.to_string(),
            }));
        }
    };
    // Keep the checked signature-to-IEND envelope separate from later carrier bytes
    // Pixel decoding remains an independent operation with its own resource budgets
    let png_length = report.bytes_after_iend_range.offset;
    let png_bytes = bytes
        .get(..png_length)
        .ok_or("validated PNG boundary is outside the retained input")?;
    let Some(structure) = expansion.byte_node(
        "png_structure",
        item.node,
        png_bytes,
        json!({
            "input_node":item.node,
            "depth":item.depth,
            "chunk_count":report.chunks.len(),
            "bytes_after_iend":report.bytes_after_iend.len(),
            "iend_end_offset":png_length,
            "object_range":{"offset":0,"length":png_length}
        }),
    )?
    else {
        return Ok(());
    };
    expansion.edge(
        item.node,
        structure,
        "parsed_as",
        EvidenceStatus::Observed,
        "The retained bytes have the PNG signature, checked chunk boundaries and type-code bits, matching chunk CRCs, one leading 13-byte IHDR, and an empty IEND; image-data validity was not tested",
    )?;

    add_chunks(expansion, item, structure, &report)?;
    add_trailer(expansion, item, structure, &report)?;
    Ok(())
}

fn add_chunks(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    structure: u64,
    report: &PngReport<'_>,
) -> Result<(), Box<dyn Error>> {
    for (index, chunk) in report.chunks.iter().enumerate() {
        if chunk.payload.is_empty() {
            continue;
        }
        let type_code = std::str::from_utf8(&chunk.type_code).unwrap_or("????");
        let Some(payload) = expansion.byte_node(
            "png_chunk_payload",
            item.node,
            chunk.payload,
            json!({
                "png_node":item.node,
                "structure_node":structure,
                "chunk_index":index,
                "type_code":type_code,
                "critical":chunk.is_critical(),
                "private":chunk.is_private(),
                "safe_to_copy":chunk.is_safe_to_copy(),
                "chunk_range":chunk.chunk_range,
                "payload_range":chunk.payload_range,
                "crc_range":chunk.crc_range,
                "stored_crc32":chunk.stored_crc32
            }),
        )?
        else {
            continue;
        };
        expansion.edge(
            structure,
            payload,
            "contains_chunk_payload",
            EvidenceStatus::Observed,
            "The PNG length and CRC fields bind the exact retained payload bytes to this chunk",
        )?;
        expansion.enqueue(payload, item.depth.saturating_add(1));
    }
    Ok(())
}

fn add_trailer(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    structure: u64,
    report: &PngReport<'_>,
) -> Result<(), Box<dyn Error>> {
    if !report.bytes_after_iend.is_empty()
        && let Some(trailer) = expansion.byte_node(
            "png_trailing_data",
            item.node,
            report.bytes_after_iend,
            json!({
                "png_node":item.node,
                "structure_node":structure,
                "range":report.bytes_after_iend_range,
                "length":report.bytes_after_iend.len(),
                "sha256":l2_workbench::sha256(report.bytes_after_iend)
            }),
        )?
    {
        expansion.edge(
            structure,
            trailer,
            "followed_by",
            EvidenceStatus::Observed,
            "These bytes begin immediately after the CRC-checked PNG IEND boundary",
        )?;
        expansion.enqueue(trailer, item.depth.saturating_add(1));
    }
    Ok(())
}
