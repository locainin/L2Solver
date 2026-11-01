//! Select validated archives and regular members with their parent context

use super::super::expand::{ZIP_MEMBER_NAME_PREVIEW_BYTES, encode_hex};
use super::{
    naming::archive_member_name,
    selection::{ExportSpec, node_bytes},
    validation::{
        SelectionValidation, StructuralValidation, StructuralValidationStatus, complete_range,
        retain_validation_attempt, validation_format_label,
    },
};
use l2_workbench::{
    artifact::{
        ArtifactBoundaryEvidence, ArtifactStructure, ArtifactValidationFormat,
        ArtifactValidationOutcome,
        zip::{ZipArtifactEntry, ZipArtifactEntryMetadata, ZipArtifactReport},
    },
    evidence::{Case, EvidenceStatus, Node},
    job::MemoryError,
};
use std::collections::{HashMap, HashSet};

pub(super) fn add_validated_archives<'a>(
    case: &'a Case,
    validation: &mut SelectionValidation<'_, 'a>,
    specs: &mut HashMap<u64, ExportSpec>,
) -> Result<(), MemoryError> {
    let structures_by_archive = archive_structures(case);
    let members_by_archive = archive_members(case);
    for (archive_id, structures) in structures_by_archive {
        let Some(archive) = case.node(archive_id) else {
            continue;
        };
        let Some(archive_bytes) = node_bytes(case, archive) else {
            continue;
        };
        let Some(blob_id) = archive.blob.as_deref() else {
            continue;
        };
        let report = match validated_zip_report(validation, blob_id, archive_bytes)? {
            Ok(report) => {
                retain_validation_attempt(
                    specs,
                    archive_id,
                    StructuralValidation::validated("zip_structure", None),
                );
                report
            }
            Err(validation) => {
                retain_validation_attempt(specs, archive_id, validation);
                continue;
            }
        };
        let structures: Vec<&Node> = structures
            .into_iter()
            .filter(|structure| has_archive_structure_evidence(structure, archive, report))
            .collect();
        if structures.is_empty() {
            continue;
        }

        let validation_evidence_node = structures.first().map(|structure| structure.id);
        if let Some(spec) = specs.get_mut(&archive_id) {
            spec.structural_validation =
                StructuralValidation::validated("zip_structure", validation_evidence_node);
        } else {
            specs.insert(
                archive_id,
                ExportSpec {
                    file_name: format!("artifact-{archive_id}-archive-input.zip"),
                    archive_path: None,
                    structural_validation: StructuralValidation::validated(
                        "zip_structure",
                        validation_evidence_node,
                    ),
                    extension_evidence_node: None,
                },
            );
        }

        add_validated_archive_members(
            case,
            archive_id,
            &structures,
            &members_by_archive,
            report,
            specs,
        );
    }
    Ok(())
}

fn archive_structures(case: &Case) -> HashMap<u64, Vec<&Node>> {
    let mut structures_by_archive: HashMap<u64, Vec<&Node>> = HashMap::new();
    for structure in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_structure")
    {
        let Some(archive_id) = structure
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !case.has_edge(
            archive_id,
            structure.id,
            "parsed_as",
            EvidenceStatus::Observed,
        ) {
            continue;
        }
        let Some(archive) = case.node(archive_id) else {
            continue;
        };
        if structure.blob != archive.blob {
            continue;
        }
        structures_by_archive
            .entry(archive_id)
            .or_default()
            .push(structure);
    }
    structures_by_archive
}

fn archive_members(case: &Case) -> HashMap<u64, Vec<&Node>> {
    let mut members_by_archive: HashMap<u64, Vec<&Node>> = HashMap::new();
    for member in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "archive_member")
    {
        let Some(archive_id) = member
            .details
            .get("archive_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        members_by_archive
            .entry(archive_id)
            .or_default()
            .push(member);
    }
    members_by_archive
}

pub(super) fn add_validated_archive_members(
    case: &Case,
    archive_id: u64,
    structures: &[&Node],
    members_by_archive: &HashMap<u64, Vec<&Node>>,
    report: &ZipArtifactReport,
    specs: &mut HashMap<u64, ExportSpec>,
) {
    let structure_ids: HashSet<u64> = structures.iter().map(|node| node.id).collect();
    let Some(members) = members_by_archive.get(&archive_id) else {
        return;
    };
    let entries_by_index: HashMap<usize, &ZipArtifactEntry> = report
        .entries
        .iter()
        .map(|entry| (entry.metadata.index, entry))
        .collect();
    for member in members {
        if !case.has_edge(
            archive_id,
            member.id,
            "contains_member",
            EvidenceStatus::Observed,
        ) {
            continue;
        }
        let Some(structure_id) = member
            .details
            .get("structure_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !structure_ids.contains(&structure_id) {
            continue;
        }
        let Some(entry_index) = member
            .details
            .get("entry_index")
            .and_then(serde_json::Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
        else {
            continue;
        };
        let Some(entry) = entries_by_index.get(&entry_index).copied() else {
            continue;
        };
        let Some(member_bytes) = node_bytes(case, member) else {
            continue;
        };
        if !archive_member_matches(member, entry, member_bytes) {
            continue;
        }

        let archive_path = validated_archive_path(&entry.metadata.raw_name);
        specs.insert(
            member.id,
            ExportSpec {
                file_name: archive_member_name(member.id, archive_path.as_deref()),
                archive_path,
                structural_validation: StructuralValidation::validated(
                    "zip_member",
                    Some(structure_id),
                ),
                extension_evidence_node: None,
            },
        );
    }
}

fn has_archive_structure_evidence(
    structure: &Node,
    archive: &Node,
    report: &ZipArtifactReport,
) -> bool {
    let details = &structure.details;
    if details
        .get("depth")
        .and_then(serde_json::Value::as_u64)
        .is_none()
    {
        return false;
    }

    structure.blob == archive.blob
        && details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
            == Some(archive.id)
        && details.get("format").and_then(serde_json::Value::as_str) == Some("zip")
        && details
            .get("archive_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(report.archive_sha256.as_str())
        && count_detail_matches(details, "archive_size", report.archive_size)
        && count_detail_matches(details, "entry_count", report.entry_count)
        && count_detail_matches(
            details,
            "extracted_entry_count",
            report.extracted_entry_count,
        )
        && count_detail_matches(details, "expanded_byte_count", report.expanded_byte_count)
        && count_detail_matches(
            details,
            "expanded_work_byte_count",
            report.expanded_work_byte_count,
        )
        && count_detail_matches(details, "omitted_entry_count", report.omitted_entry_count)
}

fn count_detail_matches(details: &serde_json::Value, field: &str, expected: usize) -> bool {
    u64::try_from(expected).is_ok_and(|expected| {
        details.get(field).and_then(serde_json::Value::as_u64) == Some(expected)
    })
}

fn archive_member_matches(member: &Node, entry: &ZipArtifactEntry, bytes: &[u8]) -> bool {
    if entry.metadata.is_directory
        || entry
            .metadata
            .unix_mode
            .is_some_and(|mode| mode & 0o170_000 == 0o120_000)
        || entry.content.as_deref() != Some(bytes)
    {
        return false;
    }

    archive_member_details_match(&member.details, &entry.metadata)
}

fn archive_member_details_match(
    details: &serde_json::Value,
    metadata: &ZipArtifactEntryMetadata,
) -> bool {
    let raw_name_length = u64::try_from(metadata.raw_name.len()).ok();
    let unix_mode = metadata.unix_mode.map(u64::from);
    let utf8_name = validated_archive_path(&metadata.raw_name);
    let preview_length = metadata.raw_name.len().min(ZIP_MEMBER_NAME_PREVIEW_BYTES);
    let Some(name_preview) = metadata.raw_name.get(..preview_length) else {
        return false;
    };
    let raw_name_sha256 = l2_workbench::sha256(&metadata.raw_name);
    let raw_name_hex = encode_hex(name_preview);
    let raw_name_truncated = metadata.raw_name.len() > ZIP_MEMBER_NAME_PREVIEW_BYTES;

    details
        .get("raw_name_length")
        .and_then(serde_json::Value::as_u64)
        == raw_name_length
        && details
            .get("raw_name_sha256")
            .and_then(serde_json::Value::as_str)
            == Some(raw_name_sha256.as_str())
        && details
            .get("raw_name_hex")
            .and_then(serde_json::Value::as_str)
            == Some(raw_name_hex.as_str())
        && details
            .get("raw_name_truncated")
            .and_then(serde_json::Value::as_bool)
            == Some(raw_name_truncated)
        && details
            .get("is_directory")
            .and_then(serde_json::Value::as_bool)
            == Some(metadata.is_directory)
        && details
            .get("compression_method")
            .and_then(serde_json::Value::as_u64)
            == Some(u64::from(metadata.compression_method))
        && details
            .get("encrypted")
            .and_then(serde_json::Value::as_bool)
            == Some(metadata.encrypted)
        && details.get("unix_mode").and_then(serde_json::Value::as_u64) == unix_mode
        && details.get("utf8_name").and_then(serde_json::Value::as_str) == utf8_name.as_deref()
        && details
            .get("compressed_size")
            .and_then(serde_json::Value::as_u64)
            == Some(metadata.compressed_size)
        && details
            .get("expanded_size")
            .and_then(serde_json::Value::as_u64)
            == Some(metadata.expanded_size)
        && details.get("crc32").and_then(serde_json::Value::as_u64)
            == Some(u64::from(metadata.crc32))
        && details
            .get("local_header_offset")
            .and_then(serde_json::Value::as_u64)
            == Some(metadata.local_header_offset)
}

fn validated_archive_path(raw_name: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(raw_name).ok()?;
    (name.len() <= 256).then(|| name.to_owned())
}

fn validated_zip_report<'cache, 'case>(
    validation: &'cache mut SelectionValidation<'_, 'case>,
    blob_id: &'case str,
    bytes: &'case [u8],
) -> Result<Result<&'cache ZipArtifactReport, StructuralValidation>, MemoryError> {
    Ok(
        match validation.validate_as(blob_id, ArtifactValidationFormat::Zip, bytes)? {
            ArtifactValidationOutcome::Validated {
                format: ArtifactValidationFormat::Zip,
                range,
                boundary: ArtifactBoundaryEvidence::ZipEndRecord,
                structure: ArtifactStructure::Zip(report),
            } if *range == complete_range(bytes) => Ok(report),
            ArtifactValidationOutcome::Validated { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unknown,
                Some("zip_structure"),
                None,
            )),
            ArtifactValidationOutcome::BoundaryUnproven { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::BoundaryUnproven,
                    Some(validation_format_label(*format, "zip_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Rejected { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Rejected,
                    Some(validation_format_label(*format, "zip_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Unsupported { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unsupported,
                Some("zip_structure"),
                None,
            )),
            ArtifactValidationOutcome::Omitted { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Omitted,
                    Some((*format).map_or("zip_structure", |format| {
                        validation_format_label(format, "zip_structure")
                    })),
                    None,
                ))
            }
        },
    )
}
