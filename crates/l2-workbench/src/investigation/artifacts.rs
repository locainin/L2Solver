//! Static PE/ELF header checks for already retained byte candidates

use super::{
    graph::{Context, MappedRange, clip},
    network::value_node,
};
use crate::{
    artifact::{self, ArtifactError, ArtifactFormat},
    evidence::EvidenceStatus,
};
use serde_json::{Map, Value, json};
use std::error::Error;

const LIMITATION: &str = "Executable header inspection stopped at a configured format-parser limit; omitted metadata was not interpreted";
const INTERPRETATION: &str = "This is a bounded static header check on one selected byte object; it does not establish a complete file boundary, delivery, runtime behavior, execution, or malicious intent";

pub(super) fn add(
    context: &mut Context<'_>,
    input_node: u64,
    bytes: &[u8],
    mappings: &[MappedRange],
) -> Result<(), Box<dyn Error>> {
    let signature_report = artifact::scan_file_signatures(bytes);
    let format = artifact::candidate_executable_format(bytes);
    if signature_report.matches.is_empty() && format.is_none() {
        return Ok(());
    }
    // The report hash and catalogue revision bind every retained signature finding
    let input_sha256 = &signature_report.source_sha256;
    add_signatures(context, input_node, &signature_report, mappings)?;
    let Some(format) = format else {
        return Ok(());
    };
    // A magic prefix selects a parser without assigning protocol or file identity
    let inspection = artifact::inspect(bytes);
    let (details, incomplete) = check_details(input_node, format, input_sha256, inspection);
    if incomplete {
        context.incomplete = true;
        context.case.add_limitation(LIMITATION)?;
    }
    let check = value_node(context, "artifact_header_checks", details, mappings)?;
    context.edge(
        input_node,
        check,
        "tested_by",
        EvidenceStatus::Observed,
        "The bounded PE/ELF header inspector tested this selected byte object",
    )?;
    Ok(())
}

fn add_signatures(
    context: &mut Context<'_>,
    input_node: u64,
    report: &artifact::FileSignatureReport,
    mappings: &[MappedRange],
) -> Result<(), Box<dyn Error>> {
    for evidence in report.evidence_matches() {
        let signature = evidence.signature();
        let signature_mappings = clip(mappings, signature.range.offset, signature.range.length)?;
        let mut details = serde_json::to_value(evidence)?;
        let object = details
            .as_object_mut()
            .ok_or("file signature did not serialize as an object")?;
        object.insert("input_node".to_owned(), json!(input_node));
        object.insert("input_sha256".to_owned(), json!(report.source_sha256));
        object.insert(
            "input_blob".to_owned(),
            json!(format!("sha256:{}", report.source_sha256)),
        );
        object.insert(
            "coordinate_base".to_owned(),
            json!("zero_based_from_byte_0_of_input_blob"),
        );
        object.insert(
            "unproven".to_owned(),
            json!([
                "complete_file_boundary",
                "structural_validity",
                "container_subtype",
                "delivery",
                "execution",
                "malicious_intent"
            ]),
        );
        let node = value_node(
            context,
            "file_signature_match",
            details,
            &signature_mappings,
        )?;
        context.edge(
            input_node,
            node,
            "contains_signature",
            EvidenceStatus::Observed,
            artifact::FILE_SIGNATURE_RELATION_REASON,
        )?;
    }
    Ok(())
}

fn source_details(
    input_node: u64,
    format: ArtifactFormat,
    input_sha256: &str,
) -> Map<String, Value> {
    Map::from_iter([
        ("input_node".to_owned(), json!(input_node)),
        ("input_sha256".to_owned(), json!(input_sha256)),
        (
            "input_blob".to_owned(),
            json!(format!("sha256:{input_sha256}")),
        ),
        ("candidate_format".to_owned(), json!(format)),
        (
            "coordinate_base".to_owned(),
            json!("zero_based_from_byte_0_of_input_blob"),
        ),
        (
            "unproven".to_owned(),
            json!([
                "complete_file_boundary",
                "runtime_behavior",
                "execution",
                "malicious_intent"
            ]),
        ),
    ])
}

fn check_details(
    input_node: u64,
    format: ArtifactFormat,
    input_sha256: &str,
    inspection: Result<artifact::ArtifactReport, ArtifactError>,
) -> (Value, bool) {
    let mut details = source_details(input_node, format, input_sha256);
    match inspection {
        Ok(report) => {
            details.insert("result".to_owned(), json!("validated_metadata"));
            details.insert("interpretation".to_owned(), json!(INTERPRETATION));
            details.insert("report".to_owned(), json!(report));
            (Value::Object(details), false)
        }
        Err(error) => {
            let (reason, incomplete) = rejection_reason(&error);
            details.insert("result".to_owned(), json!("rejected_header"));
            details.insert("reason".to_owned(), reason);
            details.insert(
                "interpretation".to_owned(),
                json!("The selected bytes did not produce validated metadata in this bounded parser; a rejection is not proof of a complete object boundary, corruption, or malicious intent"),
            );
            (Value::Object(details), incomplete)
        }
    }
}

fn rejection_reason(error: &ArtifactError) -> (Value, bool) {
    match error {
        ArtifactError::InvalidRange {
            offset,
            length,
            total,
        } => (
            json!({"kind": "invalid_range", "offset": offset, "length": length, "total": total}),
            false,
        ),
        ArtifactError::LimitExceeded { field, maximum } => (
            json!({"kind": "entry_limit", "field": field, "maximum": maximum}),
            true,
        ),
        ArtifactError::InvalidHeader { field } => {
            (json!({"kind": "invalid_header", "field": field}), false)
        }
        ArtifactError::InvalidName { offset } => {
            (json!({"kind": "invalid_name", "offset": offset}), false)
        }
        ArtifactError::UnmappedAddress { address, length } => (
            json!({"kind": "unmapped_address", "address": address, "length": length}),
            false,
        ),
        ArtifactError::AmbiguousAddress { address } => (
            json!({"kind": "ambiguous_address", "address": address}),
            false,
        ),
        // An unexpected inspector error is evidence of an analysis omission
        _ => (json!({"kind": "unexpected_inspector_error"}), true),
    }
}
