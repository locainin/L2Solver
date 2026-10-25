//! Keep signature observations separate from validated filename extensions

use super::{
    naming::safe_extension,
    selection::{node_bytes, observed_edges},
    validation::{
        SelectionValidation, StructuralValidation, StructuralValidationStatus,
        boundary_matches_format, complete_range, validation_format_label,
    },
};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationOutcome},
    evidence::{Case, Node},
};
use std::collections::HashMap;

pub(super) struct SignatureExtension {
    pub(super) extension: Option<String>,
    pub(super) structural_validation: StructuralValidation,
    pub(super) evidence_node: u64,
}

struct SignatureSourceEvidence {
    sha256: String,
    canonical_matches: Vec<serde_json::Value>,
}
pub(super) fn record_signature_extensions<'a>(
    case: &'a Case,
    nodes_by_id: &HashMap<u64, &'a Node>,
    bytes_by_id: &HashMap<&'a str, &'a [u8]>,
    validation: &mut SelectionValidation<'_, 'a>,
) -> HashMap<u64, SignatureExtension> {
    let mut extensions_by_node: HashMap<u64, SignatureExtension> = HashMap::new();
    let contains_signature_edges = observed_edges(case, "contains_signature");
    let mut signature_sources: HashMap<&str, SignatureSourceEvidence> = HashMap::new();
    for evidence in case.nodes().iter().filter(|candidate| {
        candidate.kind == "file_signature_match"
            && candidate
                .details
                .get("ambiguous")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            && candidate
                .details
                .pointer("/range/offset")
                .and_then(serde_json::Value::as_u64)
                == Some(0)
    }) {
        let Some(node_id) = evidence
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let Some(input) = nodes_by_id.get(&node_id).copied() else {
            continue;
        };
        if !contains_signature_edges.contains(&(input.id, evidence.id)) {
            continue;
        }
        let Some(blob_id) = input.blob.as_deref() else {
            continue;
        };
        let Some(bytes) = node_bytes(input, bytes_by_id) else {
            continue;
        };
        let source_evidence = signature_sources.entry(blob_id).or_insert_with(|| {
            let report = l2_workbench::artifact::scan_file_signatures(bytes);
            let sha256 = report.source_sha256;
            let canonical_matches = serde_json::to_value(report.matches)
                .ok()
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            SignatureSourceEvidence {
                sha256,
                canonical_matches,
            }
        });
        if !signature_evidence_matches_input(evidence, blob_id, source_evidence) {
            continue;
        }
        let (extension, candidate_validation) =
            signature_extension_validation(evidence, blob_id, bytes, validation);

        match extensions_by_node.get_mut(&node_id) {
            Some(existing) if existing.extension.is_none() && extension.is_some() => {
                existing.extension = extension;
                existing.structural_validation = candidate_validation;
                existing.evidence_node = evidence.id;
            }
            Some(_) => {}
            None => {
                extensions_by_node.insert(
                    node_id,
                    SignatureExtension {
                        extension,
                        structural_validation: candidate_validation,
                        evidence_node: evidence.id,
                    },
                );
            }
        }
    }
    extensions_by_node
}

fn signature_extension_validation<'a>(
    evidence: &'a Node,
    blob_id: &'a str,
    bytes: &'a [u8],
    validation: &mut SelectionValidation<'_, 'a>,
) -> (Option<String>, StructuralValidation) {
    let mut extension = None;
    let mut validation_result = StructuralValidation::not_checked();
    for candidate in evidence
        .details
        .get("extensions")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter_map(safe_extension)
    {
        let (validated_extension, candidate_validation) =
            validate_signature_extension(blob_id, &candidate, bytes, validation);
        if validated_extension.is_some() {
            extension = validated_extension;
            validation_result = candidate_validation;
            break;
        }
        if validation_result.status() == StructuralValidationStatus::NotChecked
            && candidate_validation.status() != StructuralValidationStatus::NotChecked
        {
            validation_result = candidate_validation;
        }
    }
    (extension, validation_result)
}

fn signature_evidence_matches_input(
    evidence: &Node,
    blob_id: &str,
    source_evidence: &SignatureSourceEvidence,
) -> bool {
    if evidence.blob.as_deref() != Some(blob_id)
        || evidence
            .details
            .get("input_blob")
            .and_then(serde_json::Value::as_str)
            != Some(blob_id)
        || evidence
            .details
            .get("input_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(source_evidence.sha256.as_str())
        || evidence
            .details
            .get("coordinate_base")
            .and_then(serde_json::Value::as_str)
            != Some("zero_based_from_byte_0_of_input_blob")
        || evidence
            .details
            .pointer("/range/offset")
            .and_then(serde_json::Value::as_u64)
            != Some(0)
    {
        return false;
    }

    source_evidence
        .canonical_matches
        .iter()
        .any(|canonical| signature_fields_match(&evidence.details, canonical))
}

fn signature_fields_match(evidence: &serde_json::Value, canonical: &serde_json::Value) -> bool {
    const SIGNATURE_FIELDS: &[&str] = &[
        "ambiguous",
        "description",
        "extensions",
        "interpretation",
        "match_kind",
        "media_types",
        "pattern_hex",
        "possible_formats",
        "range",
        "reference",
        "rule_id",
        "observed_hex",
    ];

    SIGNATURE_FIELDS
        .iter()
        .all(|field| evidence.get(*field) == canonical.get(*field))
}

fn validate_signature_extension<'a>(
    blob_id: &'a str,
    candidate: &str,
    bytes: &'a [u8],
    validation: &mut SelectionValidation<'_, 'a>,
) -> (Option<String>, StructuralValidation) {
    let (format, format_name) = match candidate {
        "der" => (ArtifactValidationFormat::Der, "der_structure"),
        "png" => (ArtifactValidationFormat::Png, "png_structure"),
        "zip" => (ArtifactValidationFormat::Zip, "zip_structure"),
        _ => return (None, StructuralValidation::not_checked()),
    };
    match validation.validate_as(blob_id, format, bytes) {
        ArtifactValidationOutcome::Validated {
            format: validated_format,
            range,
            boundary,
            ..
        } if *validated_format == format
            && *range == complete_range(bytes)
            && boundary_matches_format(format, *boundary) =>
        {
            (
                Some(candidate.to_owned()),
                StructuralValidation::validated(format_name, None),
            )
        }
        ArtifactValidationOutcome::Validated { .. } => (
            None,
            StructuralValidation::outcome(
                StructuralValidationStatus::Unknown,
                Some(format_name),
                None,
            ),
        ),
        ArtifactValidationOutcome::BoundaryUnproven { format, .. } => (
            None,
            StructuralValidation::outcome(
                StructuralValidationStatus::BoundaryUnproven,
                Some(validation_format_label(*format, format_name)),
                None,
            ),
        ),
        ArtifactValidationOutcome::Rejected { format, .. } => (
            None,
            StructuralValidation::outcome(
                StructuralValidationStatus::Rejected,
                Some(validation_format_label(*format, format_name)),
                None,
            ),
        ),
        ArtifactValidationOutcome::Unsupported { .. } => (
            None,
            StructuralValidation::outcome(
                StructuralValidationStatus::Unsupported,
                Some(format_name),
                None,
            ),
        ),
        ArtifactValidationOutcome::Omitted { format, .. } => (
            None,
            StructuralValidation::outcome(
                StructuralValidationStatus::Omitted,
                Some((*format).map_or(format_name, |format| {
                    validation_format_label(format, format_name)
                })),
                None,
            ),
        ),
    }
}
