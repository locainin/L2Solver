//! ZIP member expansion without writing archive paths to the filesystem

use super::{
    CandidateRejection, ExpansionError, ExpansionService, WorkItem, ZIP_MEMBER_NAME_PREVIEW_BYTES,
    encode_hex,
};
use l2_workbench::{
    artifact::zip::{
        ZipArtifactEntry, ZipArtifactError, ZipArtifactLimits, ZipArtifactOmission,
        ZipArtifactOmissionReason, ZipArtifactReport, inspect_zip_at_depth_with_operation_budget,
    },
    evidence::EvidenceStatus,
};
use serde_json::json;
use std::error::Error;

pub(super) fn expand(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    bytes: &[u8],
) -> Result<(), ExpansionError> {
    let limits = ZipArtifactLimits {
        max_archive_bytes: expansion.limits.input_bytes,
        max_entries: expansion.limits.archive_entries,
        max_entry_expanded_bytes: expansion.limits.member_bytes,
        max_total_expanded_bytes: expansion.limits.zip_work_bytes,
        max_depth: expansion.limits.depth,
    };
    let mut report = inspect_archive(expansion, item, bytes, limits)?;
    // These limits are checked before the parser opens and validates the central directory
    let directory_checks_skipped =
        item.depth > limits.max_depth || report.entry_count > limits.max_entries;
    let parsed_edge_reason = parsed_edge_reason(&report, directory_checks_skipped);
    let operation_budget_exhausted = report
        .omissions
        .iter()
        .any(|omission| omission.reason == ZipArtifactOmissionReason::OperationExpandedByteLimit);
    if report.omitted_entry_count > 0 || directory_checks_skipped {
        expansion.complete = false;
        let limitation_reason = if operation_budget_exhausted {
            format!(
                "Recursive ZIP expansion exhausted the operation-wide ZIP work limit of {} declared byte(s); skipped members are recorded individually",
                expansion.limits.zip_work_bytes
            )
        } else if directory_checks_skipped {
            String::from("ZIP member inspection stopped at a configured depth or entry-count limit")
        } else {
            String::from(
                "ZIP expansion omitted members because of configured limits, unsupported features, or member data that could not be validated",
            )
        };
        expansion.case.mark_incomplete(&limitation_reason)?;
    }
    let Some(structure) = expansion.reference_node(
        "archive_structure",
        item.node,
        json!({
            "input_node":item.node,
            "format":"zip",
            "depth":item.depth,
            "archive_sha256":report.archive_sha256,
            "archive_size":report.archive_size,
            "entry_count":report.entry_count,
            "extracted_entry_count":report.extracted_entry_count,
            "expanded_byte_count":report.expanded_byte_count,
            "expanded_work_byte_count":report.expanded_work_byte_count,
            "omitted_entry_count":report.omitted_entry_count
        }),
    )?
    else {
        return Ok(());
    };
    expansion.edge(
        item.node,
        structure,
        "parsed_as",
        if directory_checks_skipped {
            EvidenceStatus::Unresolved
        } else {
            EvidenceStatus::Observed
        },
        &parsed_edge_reason,
    )?;

    let entries = std::mem::take(&mut report.entries);
    expand_entries(expansion, item, structure, entries)?;
    add_omission_summary(expansion, item.node, structure, &report)?;
    Ok(())
}

fn inspect_archive(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    bytes: &[u8],
    limits: ZipArtifactLimits,
) -> Result<ZipArtifactReport, ExpansionError> {
    // Structural failures reject a candidate; operational failures keep their error category
    let operation_limit = expansion.limit_zip_work();
    let mut operation_remaining = operation_limit;
    let result = inspect_zip_at_depth_with_operation_budget(
        bytes,
        limits,
        item.depth,
        &mut operation_remaining,
    );
    let work_used = operation_limit
        .checked_sub(operation_remaining)
        .ok_or("ZIP operation work allowance increased unexpectedly")?;
    expansion.retain_zip_work(work_used)?;
    result.map_err(|error| match error {
        error @ (ZipArtifactError::InvalidArchive | ZipArtifactError::AmbiguousEndRecords) => {
            ExpansionError::Rejected(CandidateRejection {
                node: item.node,
                format: "zip",
                message: error.to_string(),
            })
        }
        error @ (ZipArtifactError::ArchiveTooLarge { .. }
        | ZipArtifactError::EntryCountOutOfRange { .. }
        | ZipArtifactError::AllocationFailure) => ExpansionError::resource(error),
        error => ExpansionError::invariant(error),
    })
}

fn expand_entries(
    expansion: &mut ExpansionService<'_>,
    item: WorkItem,
    structure: u64,
    entries: Vec<ZipArtifactEntry>,
) -> Result<(), Box<dyn Error>> {
    for entry in entries {
        let name_preview_length = entry
            .metadata
            .raw_name
            .len()
            .min(ZIP_MEMBER_NAME_PREVIEW_BYTES);
        let name_preview = entry
            .metadata
            .raw_name
            .get(..name_preview_length)
            .unwrap_or_default();
        let details = json!({
            "archive_node":item.node,
            "structure_node":structure,
            "entry_index":entry.metadata.index,
            "raw_name_length":entry.metadata.raw_name.len(),
            "raw_name_sha256":l2_workbench::sha256(&entry.metadata.raw_name),
            "raw_name_hex":encode_hex(name_preview),
            "raw_name_truncated":name_preview_length != entry.metadata.raw_name.len(),
            "utf8_name":std::str::from_utf8(&entry.metadata.raw_name).ok().filter(|name| name.len() <= 256),
            "is_directory":entry.metadata.is_directory,
            "compression_method":entry.metadata.compression_method,
            "encrypted":entry.metadata.encrypted,
            "compressed_size":entry.metadata.compressed_size,
            "expanded_size":entry.metadata.expanded_size,
            "crc32":entry.metadata.crc32,
            "local_header_offset":entry.metadata.local_header_offset,
            "unix_mode":entry.metadata.unix_mode
        });
        if let Some(content) = entry.content {
            let Some(member) =
                expansion.byte_node("archive_member", item.node, &content, details)?
            else {
                continue;
            };
            expansion.edge(
                item.node,
                member,
                "contains_member",
                EvidenceStatus::Observed,
                "ZIP metadata, the matching local header, any data descriptor, decompression, expanded length, and CRC identify these exact member bytes",
            )?;
            expansion.enqueue(member, item.depth.saturating_add(1));
        } else if let Some(reason) = entry.omission
            && let Some(metadata) = expansion.reference_node(
                "archive_member_omission",
                item.node,
                json!({"entry":details,"zip_reason":reason}),
            )?
        {
            expansion.edge(
                item.node,
                metadata,
                "describes_omitted_member",
                EvidenceStatus::Unresolved,
                "The ZIP central directory identifies the member, while the aggregate omission records why expanded bytes were unavailable",
            )?;
        }
    }
    Ok(())
}

fn add_omission_summary(
    expansion: &mut ExpansionService<'_>,
    archive_node: u64,
    structure: u64,
    report: &ZipArtifactReport,
) -> Result<(), Box<dyn Error>> {
    if report.omitted_entry_count > 0
        && let Some(summary) =
            expansion.reference_node("zip_aggregate_omission", archive_node, {
                // Per-member nodes retain indexes and failures; the summary counts omission classes
                let counts = aggregate_omission_counts(&report.omissions);
                json!({
                    "archive_node":archive_node,
                    "structure_node":structure,
                    "omitted_entry_count":report.omitted_entry_count,
                    "omission_counts":{
                        "encrypted":counts.encrypted,
                        "unsupported_compression":counts.unsupported_compression,
                        "byte_limit":counts.byte_limit,
                        "operation_expanded_byte_limit":counts.operation_expanded_byte_limit,
                        "entry_count_limit":counts.entry_count_limit,
                        "depth_limit":counts.depth_limit,
                        "member_data_failure":counts.member_data_failure
                    }
                })
            })?
    {
        expansion.edge(
            structure,
            summary,
            "summarizes_member_omissions",
            EvidenceStatus::Unresolved,
            "Counts by reason summarize members without retained expanded bytes",
        )?;
    }
    Ok(())
}

#[derive(Default)]
struct ZipOmissionCounts {
    encrypted: usize,
    unsupported_compression: usize,
    byte_limit: usize,
    operation_expanded_byte_limit: usize,
    entry_count_limit: usize,
    depth_limit: usize,
    member_data_failure: usize,
}

fn aggregate_omission_counts(omissions: &[ZipArtifactOmission]) -> ZipOmissionCounts {
    let mut counts = ZipOmissionCounts::default();
    for omission in omissions {
        match omission.reason {
            ZipArtifactOmissionReason::Encrypted => counts.encrypted += omission.count,
            ZipArtifactOmissionReason::UnsupportedCompression { .. } => {
                counts.unsupported_compression += omission.count;
            }
            ZipArtifactOmissionReason::EntryExpandedByteLimit
            | ZipArtifactOmissionReason::TotalExpandedByteLimit => {
                counts.byte_limit += omission.count;
            }
            ZipArtifactOmissionReason::OperationExpandedByteLimit => {
                counts.byte_limit += omission.count;
                counts.operation_expanded_byte_limit += omission.count;
            }
            ZipArtifactOmissionReason::EntryCountLimit => {
                counts.entry_count_limit += omission.count;
            }
            ZipArtifactOmissionReason::DepthLimit => counts.depth_limit += omission.count,
            ZipArtifactOmissionReason::EntryDataFailure { .. } => {}
        }
    }
    counts.member_data_failure = member_data_failure_count(omissions);
    counts
}

fn member_data_failure_count(omissions: &[ZipArtifactOmission]) -> usize {
    omissions
        .iter()
        .filter_map(|omission| {
            matches!(
                omission.reason,
                ZipArtifactOmissionReason::EntryDataFailure { .. }
            )
            .then_some(omission.count)
        })
        .sum()
}

fn parsed_edge_reason(report: &ZipArtifactReport, directory_checks_skipped: bool) -> String {
    let member_data_issue_count = member_data_failure_count(&report.omissions);

    if directory_checks_skipped {
        return format!(
            "The ZIP directory declares {} member(s), while configured depth or entry-count limits prevented full header and member validation",
            report.entry_count
        );
    }
    if report.omitted_entry_count == 0 {
        if report.entry_count == 0 {
            return "The ZIP directory was valid; no members were present".to_owned();
        }
        return format!(
            "The ZIP directory was valid; all {} member(s) passed local-header, descriptor when present, size, boundary, and CRC checks",
            report.extracted_entry_count
        );
    }

    let unvalidated_member_count =
        report.entry_count - report.extracted_entry_count - member_data_issue_count;
    format!(
        "The ZIP directory was valid; {} member(s) passed local-header, descriptor when present, size, boundary, and CRC checks, {} failed or could not complete per-member checks, and {} were omitted before data validation",
        report.extracted_entry_count, member_data_issue_count, unvalidated_member_count
    )
}
