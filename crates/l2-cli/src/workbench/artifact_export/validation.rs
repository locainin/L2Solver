//! Verify structural evidence and cache format decisions for shared byte inputs

use super::selection::{ExportSpec, node_bytes};
use l2_workbench::{
    artifact::{
        ArtifactBoundaryEvidence, ArtifactStructure, ArtifactValidationFormat,
        ArtifactValidationOutcome, ArtifactValidator, DerReport, FileRange,
    },
    evidence::{Case, EvidenceStatus, Node},
    job::{MemoryBudget, MemoryClass, MemoryError, MemoryLease},
};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralValidationStatus {
    NotChecked,
    Validated,
    Rejected,
    BoundaryUnproven,
    Unsupported,
    Omitted,
    Unknown,
}

impl StructuralValidationStatus {
    pub const fn human_label(self) -> &'static str {
        match self {
            Self::NotChecked => "not checked",
            Self::Validated => "validated",
            Self::Rejected => "rejected",
            Self::BoundaryUnproven => "boundary unproven",
            Self::Unsupported => "unsupported",
            Self::Omitted => "omitted",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StructuralValidation {
    NotChecked,
    Validated {
        format: &'static str,
        evidence_node: Option<u64>,
    },
    Rejected {
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    },
    BoundaryUnproven {
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    },
    Unsupported {
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    },
    Omitted {
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    },
    Unknown {
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    },
}

impl StructuralValidation {
    pub(super) const fn not_checked() -> Self {
        Self::NotChecked
    }

    pub(super) const fn validated(format: &'static str, evidence_node: Option<u64>) -> Self {
        Self::Validated {
            format,
            evidence_node,
        }
    }

    pub(super) fn outcome(
        status: StructuralValidationStatus,
        format: Option<&'static str>,
        evidence_node: Option<u64>,
    ) -> Self {
        match status {
            StructuralValidationStatus::NotChecked => Self::NotChecked,
            StructuralValidationStatus::Validated => Self::Validated {
                format: format.unwrap_or("unknown"),
                evidence_node,
            },
            StructuralValidationStatus::Rejected => Self::Rejected {
                format,
                evidence_node,
            },
            StructuralValidationStatus::BoundaryUnproven => Self::BoundaryUnproven {
                format,
                evidence_node,
            },
            StructuralValidationStatus::Unsupported => Self::Unsupported {
                format,
                evidence_node,
            },
            StructuralValidationStatus::Omitted => Self::Omitted {
                format,
                evidence_node,
            },
            StructuralValidationStatus::Unknown => Self::Unknown {
                format,
                evidence_node,
            },
        }
    }

    pub const fn status(&self) -> StructuralValidationStatus {
        match self {
            Self::NotChecked => StructuralValidationStatus::NotChecked,
            Self::Validated { .. } => StructuralValidationStatus::Validated,
            Self::Rejected { .. } => StructuralValidationStatus::Rejected,
            Self::BoundaryUnproven { .. } => StructuralValidationStatus::BoundaryUnproven,
            Self::Unsupported { .. } => StructuralValidationStatus::Unsupported,
            Self::Omitted { .. } => StructuralValidationStatus::Omitted,
            Self::Unknown { .. } => StructuralValidationStatus::Unknown,
        }
    }

    pub const fn format(&self) -> Option<&'static str> {
        match self {
            Self::NotChecked => None,
            Self::Validated { format, .. } => Some(*format),
            Self::Rejected { format, .. }
            | Self::BoundaryUnproven { format, .. }
            | Self::Unsupported { format, .. }
            | Self::Omitted { format, .. }
            | Self::Unknown { format, .. } => *format,
        }
    }

    pub(super) const fn evidence_node(&self) -> Option<u64> {
        match self {
            Self::Validated { evidence_node, .. }
            | Self::Rejected { evidence_node, .. }
            | Self::BoundaryUnproven { evidence_node, .. }
            | Self::Unsupported { evidence_node, .. }
            | Self::Omitted { evidence_node, .. }
            | Self::Unknown { evidence_node, .. } => *evidence_node,
            Self::NotChecked => None,
        }
    }
}

pub(super) fn retain_validation_attempt(
    specs: &mut HashMap<u64, ExportSpec>,
    node_id: u64,
    validation: StructuralValidation,
) {
    let Some(spec) = specs.get_mut(&node_id) else {
        return;
    };
    if validation.status() == StructuralValidationStatus::Validated
        || spec.structural_validation.status() == StructuralValidationStatus::NotChecked
    {
        spec.structural_validation = validation;
    }
}

#[derive(Default)]
pub(super) struct SelectionWorkCache<'a> {
    text_by_blob: HashMap<&'a str, bool>,
    validation_by_blob_format: HashMap<(&'a str, &'static str), CachedValidation<'a>>,
    memory: Option<MemoryBudget>,
    #[cfg(test)]
    pub(super) counts: SelectionWorkCounts,
}

struct CachedValidation<'a> {
    outcome: ArtifactValidationOutcome<'a>,
    // The parser report drops before its shared charge
    _memory: Option<MemoryLease>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct SelectionWorkCounts {
    pub(super) text_classifications: usize,
    pub(super) validation_calls: usize,
    pub(super) validation_cache_hits: usize,
}

impl<'a> SelectionWorkCache<'a> {
    pub(super) fn new(memory: Option<&MemoryBudget>) -> Self {
        Self {
            memory: memory.cloned(),
            ..Self::default()
        }
    }

    pub(super) fn is_plain_text(&mut self, blob_id: &'a str, bytes: &'a [u8]) -> bool {
        if let Some(is_text) = self.text_by_blob.get(blob_id) {
            return *is_text;
        }

        let is_text = is_plain_utf8_text(bytes);
        self.text_by_blob.insert(blob_id, is_text);
        #[cfg(test)]
        {
            self.counts.text_classifications += 1;
        }
        is_text
    }

    pub(super) fn validate_as(
        &mut self,
        validator: &ArtifactValidator,
        blob_id: &'a str,
        format: ArtifactValidationFormat,
        bytes: &'a [u8],
    ) -> Result<&ArtifactValidationOutcome<'a>, MemoryError> {
        let key = (blob_id, validation_cache_label(format));
        match self.validation_by_blob_format.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                #[cfg(test)]
                {
                    self.counts.validation_cache_hits += 1;
                }
                Ok(&entry.into_mut().outcome)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut memory = self
                    .memory
                    .as_ref()
                    .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
                    .transpose()?;
                let outcome = if let Some(lease) = &mut memory {
                    validator.validate_as_with_memory(format, bytes, lease)?
                } else {
                    validator.validate_as(format, bytes)
                };
                #[cfg(test)]
                {
                    self.counts.validation_calls += 1;
                }
                Ok(&entry
                    .insert(CachedValidation {
                        outcome,
                        _memory: memory,
                    })
                    .outcome)
            }
        }
    }
}

pub(super) struct SelectionValidation<'context, 'case> {
    pub(super) validator: &'context ArtifactValidator,
    pub(super) work: &'context mut SelectionWorkCache<'case>,
}

impl<'case> SelectionValidation<'_, 'case> {
    pub(super) fn is_plain_text(&mut self, blob_id: &'case str, bytes: &'case [u8]) -> bool {
        self.work.is_plain_text(blob_id, bytes)
    }

    pub(super) fn validate_as(
        &mut self,
        blob_id: &'case str,
        format: ArtifactValidationFormat,
        bytes: &'case [u8],
    ) -> Result<&ArtifactValidationOutcome<'case>, MemoryError> {
        self.work
            .validate_as(self.validator, blob_id, format, bytes)
    }
}

const fn validation_cache_label(format: ArtifactValidationFormat) -> &'static str {
    match format {
        ArtifactValidationFormat::Der => "der",
        ArtifactValidationFormat::Elf => "elf",
        ArtifactValidationFormat::PortableExecutable => "portable_executable",
        ArtifactValidationFormat::Png => "png",
        ArtifactValidationFormat::Zip => "zip",
    }
}
pub(super) fn add_validated_inputs<'a>(
    case: &'a Case,
    validation: &mut SelectionValidation<'_, 'a>,
    specs: &mut HashMap<u64, ExportSpec>,
) -> Result<(), MemoryError> {
    for structure in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "der_structure")
    {
        let Some(input_id) = structure
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !case.has_edge(
            input_id,
            structure.id,
            "parsed_as",
            EvidenceStatus::Observed,
        ) {
            continue;
        }
        let Some(input) = case.node(input_id) else {
            continue;
        };
        if structure.blob != input.blob {
            continue;
        }
        let Some(bytes) = node_bytes(case, input) else {
            continue;
        };
        let Some(blob_id) = input.blob.as_deref() else {
            continue;
        };
        let report = match validated_der_report(validation, blob_id, bytes)? {
            Ok(report) => {
                retain_validation_attempt(
                    specs,
                    input.id,
                    StructuralValidation::validated("der_structure", None),
                );
                report
            }
            Err(validation) => {
                retain_validation_attempt(specs, input.id, validation);
                continue;
            }
        };
        if !has_der_structure_evidence(structure, report) {
            continue;
        }
        let spec = specs.entry(input.id).or_insert_with(|| ExportSpec {
            file_name: format!("artifact-{}-der-input.der", input.id),
            archive_path: None,
            structural_validation: StructuralValidation::not_checked(),
            extension_evidence_node: None,
        });
        spec.structural_validation =
            StructuralValidation::validated("der_structure", Some(structure.id));
    }
    Ok(())
}

fn validated_der_report<'cache, 'case>(
    validation: &'cache mut SelectionValidation<'_, 'case>,
    blob_id: &'case str,
    bytes: &'case [u8],
) -> Result<Result<&'cache DerReport, StructuralValidation>, MemoryError> {
    Ok(
        match validation.validate_as(blob_id, ArtifactValidationFormat::Der, bytes)? {
            ArtifactValidationOutcome::Validated {
                format: ArtifactValidationFormat::Der,
                range,
                boundary: ArtifactBoundaryEvidence::DerEncodedLength,
                structure: ArtifactStructure::Der(report),
            } if *range == complete_range(bytes) => Ok(report),
            ArtifactValidationOutcome::Validated { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unknown,
                Some("der_structure"),
                None,
            )),
            ArtifactValidationOutcome::BoundaryUnproven { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::BoundaryUnproven,
                    Some(validation_format_label(*format, "der_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Rejected { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Rejected,
                    Some(validation_format_label(*format, "der_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Unsupported { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unsupported,
                Some("der_structure"),
                None,
            )),
            ArtifactValidationOutcome::Omitted { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Omitted,
                    Some((*format).map_or("der_structure", |format| {
                        validation_format_label(format, "der_structure")
                    })),
                    None,
                ))
            }
        },
    )
}

fn has_der_structure_evidence(structure: &Node, report: &DerReport) -> bool {
    let details = &structure.details;
    let Ok(value_count) = u64::try_from(report.nodes.len()) else {
        return false;
    };

    details
        .get("depth")
        .and_then(serde_json::Value::as_u64)
        .is_some()
        && details
            .get("value_count")
            .and_then(serde_json::Value::as_u64)
            == Some(value_count)
        && detail_range_matches(details, "boundary_range", report.boundary_range)
}

fn detail_range_matches(details: &serde_json::Value, field: &str, expected: FileRange) -> bool {
    let Ok(offset) = u64::try_from(expected.offset) else {
        return false;
    };
    let Ok(length) = u64::try_from(expected.length) else {
        return false;
    };
    details
        .get(field)
        .and_then(serde_json::Value::as_object)
        .is_some_and(|range| {
            range.get("offset").and_then(serde_json::Value::as_u64) == Some(offset)
                && range.get("length").and_then(serde_json::Value::as_u64) == Some(length)
        })
}

pub(super) fn add_validated_png_structures<'a>(
    case: &'a Case,
    validation: &mut SelectionValidation<'_, 'a>,
    specs: &mut HashMap<u64, ExportSpec>,
) -> Result<(), MemoryError> {
    let trailers_by_structure = png_trailers(case);
    for structure in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "png_structure")
    {
        let Some(input_id) = structure
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        if !case.has_edge(
            input_id,
            structure.id,
            "parsed_as",
            EvidenceStatus::Observed,
        ) || specs.contains_key(&structure.id)
        {
            continue;
        }
        let Some(input) = case.node(input_id) else {
            continue;
        };
        let Some(input_bytes) = node_bytes(case, input) else {
            continue;
        };
        let Some(structure_bytes) = node_bytes(case, structure) else {
            continue;
        };
        let Some(blob_id) = structure.blob.as_deref() else {
            continue;
        };
        let parsed_chunk_count =
            match validated_png_chunk_count(validation, blob_id, structure_bytes)? {
                Ok(chunk_count) => {
                    let validation = if structure_bytes == input_bytes {
                        StructuralValidation::validated("png_structure", None)
                    } else {
                        StructuralValidation::outcome(
                            StructuralValidationStatus::Unknown,
                            Some("png_structure"),
                            None,
                        )
                    };
                    retain_validation_attempt(specs, input.id, validation);
                    chunk_count
                }
                Err(validation) => {
                    retain_validation_attempt(specs, input.id, validation);
                    continue;
                }
            };
        if !has_png_structure_evidence(structure, structure_bytes, input_bytes, parsed_chunk_count)
        {
            continue;
        }

        specs.insert(
            structure.id,
            ExportSpec {
                file_name: format!("artifact-{}-png.png", structure.id),
                archive_path: None,
                structural_validation: StructuralValidation::validated(
                    "png_structure",
                    Some(structure.id),
                ),
                extension_evidence_node: None,
            },
        );
        if let Some(trailers) = trailers_by_structure.get(&structure.id) {
            add_validated_png_trailers(case, structure, input, input_bytes, trailers, specs);
        }
    }
    Ok(())
}

fn png_trailers(case: &Case) -> HashMap<u64, Vec<&Node>> {
    let mut trailers_by_structure: HashMap<u64, Vec<&Node>> = HashMap::new();
    for trailer in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "png_trailing_data")
    {
        if let Some(structure_id) = trailer
            .details
            .get("structure_node")
            .and_then(serde_json::Value::as_u64)
        {
            trailers_by_structure
                .entry(structure_id)
                .or_default()
                .push(trailer);
        }
    }
    trailers_by_structure
}

fn add_validated_png_trailers(
    case: &Case,
    structure: &Node,
    input: &Node,
    input_bytes: &[u8],
    trailers: &[&Node],
    specs: &mut HashMap<u64, ExportSpec>,
) {
    let Some(structure_bytes) = node_bytes(case, structure) else {
        return;
    };
    for trailer in trailers {
        if !case.has_edge(
            structure.id,
            trailer.id,
            "followed_by",
            EvidenceStatus::Observed,
        ) {
            continue;
        }
        let Some(trailer_bytes) = node_bytes(case, trailer) else {
            continue;
        };
        if !has_png_trailing_data_evidence(
            trailer,
            structure.id,
            input.id,
            structure_bytes,
            input_bytes,
            trailer_bytes,
        ) {
            continue;
        }
        specs.insert(
            trailer.id,
            ExportSpec {
                file_name: format!("artifact-{}-png-trailing-data.bin", trailer.id),
                archive_path: None,
                structural_validation: StructuralValidation::validated(
                    "png_trailing_data",
                    Some(structure.id),
                ),
                extension_evidence_node: None,
            },
        );
    }
}

fn has_png_trailing_data_evidence(
    trailer: &Node,
    structure_id: u64,
    input_id: u64,
    structure_bytes: &[u8],
    input_bytes: &[u8],
    trailer_bytes: &[u8],
) -> bool {
    let Ok(offset) = u64::try_from(structure_bytes.len()) else {
        return false;
    };
    let Ok(length) = u64::try_from(trailer_bytes.len()) else {
        return false;
    };

    !trailer_bytes.is_empty()
        && input_bytes.get(structure_bytes.len()..) == Some(trailer_bytes)
        && trailer
            .details
            .get("png_node")
            .and_then(serde_json::Value::as_u64)
            == Some(input_id)
        && trailer
            .details
            .get("structure_node")
            .and_then(serde_json::Value::as_u64)
            == Some(structure_id)
        && trailer
            .details
            .get("length")
            .and_then(serde_json::Value::as_u64)
            == Some(length)
        && trailer
            .details
            .pointer("/range/offset")
            .and_then(serde_json::Value::as_u64)
            == Some(offset)
        && trailer
            .details
            .pointer("/range/length")
            .and_then(serde_json::Value::as_u64)
            == Some(length)
}

fn has_png_structure_evidence(
    structure: &Node,
    bytes: &[u8],
    input_bytes: &[u8],
    parsed_chunk_count: usize,
) -> bool {
    let Ok(byte_length) = u64::try_from(bytes.len()) else {
        return false;
    };
    let Some(trailer_length) = input_bytes.len().checked_sub(bytes.len()) else {
        return false;
    };
    let Ok(trailer_length) = u64::try_from(trailer_length) else {
        return false;
    };
    let chunk_count = structure
        .details
        .get("chunk_count")
        .and_then(serde_json::Value::as_u64);
    let input_trailer_length = structure
        .details
        .get("bytes_after_iend")
        .and_then(serde_json::Value::as_u64);
    let Ok(parsed_chunk_count) = u64::try_from(parsed_chunk_count) else {
        return false;
    };

    input_bytes.starts_with(bytes)
        && chunk_count == Some(parsed_chunk_count)
        && input_trailer_length == Some(trailer_length)
        && structure
            .details
            .get("iend_end_offset")
            .and_then(serde_json::Value::as_u64)
            == Some(byte_length)
        && structure
            .details
            .pointer("/object_range/offset")
            .and_then(serde_json::Value::as_u64)
            == Some(0)
        && structure
            .details
            .pointer("/object_range/length")
            .and_then(serde_json::Value::as_u64)
            == Some(byte_length)
}

fn validated_png_chunk_count<'a>(
    validation: &mut SelectionValidation<'_, 'a>,
    blob_id: &'a str,
    bytes: &'a [u8],
) -> Result<Result<usize, StructuralValidation>, MemoryError> {
    Ok(
        match validation.validate_as(blob_id, ArtifactValidationFormat::Png, bytes)? {
            ArtifactValidationOutcome::Validated {
                format: ArtifactValidationFormat::Png,
                range,
                boundary: ArtifactBoundaryEvidence::PngIend,
                structure: ArtifactStructure::Png(report),
            } if *range == complete_range(bytes) => Ok(report.chunks.len()),
            ArtifactValidationOutcome::Validated { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unknown,
                Some("png_structure"),
                None,
            )),
            ArtifactValidationOutcome::BoundaryUnproven { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::BoundaryUnproven,
                    Some(validation_format_label(*format, "png_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Rejected { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Rejected,
                    Some(validation_format_label(*format, "png_structure")),
                    None,
                ))
            }
            ArtifactValidationOutcome::Unsupported { .. } => Err(StructuralValidation::outcome(
                StructuralValidationStatus::Unsupported,
                Some("png_structure"),
                None,
            )),
            ArtifactValidationOutcome::Omitted { format, .. } => {
                Err(StructuralValidation::outcome(
                    StructuralValidationStatus::Omitted,
                    Some((*format).map_or("png_structure", |format| {
                        validation_format_label(format, "png_structure")
                    })),
                    None,
                ))
            }
        },
    )
}

pub(super) const fn complete_range(bytes: &[u8]) -> FileRange {
    FileRange {
        offset: 0,
        length: bytes.len(),
    }
}

fn is_exactly_validated(
    validator: &ArtifactValidator,
    format: ArtifactValidationFormat,
    bytes: &[u8],
    memory: Option<&MemoryBudget>,
) -> Result<bool, MemoryError> {
    let mut lease = memory
        .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
        .transpose()?;
    let outcome = if let Some(lease) = lease.as_mut() {
        validator.validate_as_with_memory(format, bytes, lease)?
    } else {
        validator.validate_as(format, bytes)
    };
    Ok(matches!(
        outcome,
        ArtifactValidationOutcome::Validated {
            format: validated_format,
            range,
            boundary,
            ..
        } if validated_format == format
            && range == complete_range(bytes)
            && boundary_matches_format(format, boundary)
    ))
}

pub(super) const fn boundary_matches_format(
    format: ArtifactValidationFormat,
    boundary: ArtifactBoundaryEvidence,
) -> bool {
    matches!(
        (format, boundary),
        (
            ArtifactValidationFormat::Der,
            ArtifactBoundaryEvidence::DerEncodedLength
        ) | (
            ArtifactValidationFormat::Png,
            ArtifactBoundaryEvidence::PngIend
        ) | (
            ArtifactValidationFormat::Zip,
            ArtifactBoundaryEvidence::ZipEndRecord
        )
    )
}

pub(super) const fn validation_format_label(
    format: ArtifactValidationFormat,
    fallback: &'static str,
) -> &'static str {
    match format {
        ArtifactValidationFormat::Der => "der_structure",
        ArtifactValidationFormat::Png => "png_structure",
        ArtifactValidationFormat::Zip => "zip_structure",
        ArtifactValidationFormat::Elf | ArtifactValidationFormat::PortableExecutable => fallback,
    }
}

/// Return an extension only when the complete input passes its canonical parser
///
/// # Errors
/// Returns a shared-memory admission failure from a metered parser
pub fn validated_extension(
    bytes: &[u8],
    memory: Option<&MemoryBudget>,
) -> Result<Option<&'static str>, MemoryError> {
    let validator = ArtifactValidator::default();
    let detected_extension = {
        let mut lease = memory
            .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
            .transpose()?;
        let outcome = if let Some(lease) = lease.as_mut() {
            validator.validate_with_memory(bytes, lease)?
        } else {
            validator.validate(bytes)
        };
        match outcome {
            ArtifactValidationOutcome::Validated {
                format,
                range,
                boundary,
                ..
            } if range == complete_range(bytes) && boundary_matches_format(format, boundary) => {
                match format {
                    ArtifactValidationFormat::Png => Some("png"),
                    ArtifactValidationFormat::Zip => Some("zip"),
                    ArtifactValidationFormat::Der
                    | ArtifactValidationFormat::Elf
                    | ArtifactValidationFormat::PortableExecutable => None,
                }
            }
            ArtifactValidationOutcome::Validated { .. }
            | ArtifactValidationOutcome::BoundaryUnproven { .. }
            | ArtifactValidationOutcome::Rejected { .. }
            | ArtifactValidationOutcome::Unsupported { .. }
            | ArtifactValidationOutcome::Omitted { .. } => None,
        }
    };
    if detected_extension.is_some() {
        return Ok(detected_extension);
    }
    // The automatic report and lease are dropped before DER fallback starts
    Ok(
        is_exactly_validated(&validator, ArtifactValidationFormat::Der, bytes, memory)?
            .then_some("der"),
    )
}

fn is_plain_utf8_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
    })
}
