//! Select exportable byte objects and preserve each retained origin

use super::{
    archives::add_validated_archives,
    provenance::{ArtifactProvenance, reconstruction_status},
    signatures::{SignatureExtension, record_signature_extensions},
    validation::{
        SelectionValidation, SelectionWorkCache, StructuralValidation, add_validated_inputs,
        add_validated_png_structures,
    },
};
use l2_workbench::artifact::ArtifactValidator;
use l2_workbench::artifact::{
    AnalysisBoundary, AnalysisFormat, ArtifactValidationState, FileRange, ValidationSummary,
};
use l2_workbench::evidence::{Case, EvidenceStatus, Node};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};

/// One exact byte object selected for export, with every retained source reference
pub struct SelectedArtifact<'a> {
    bytes: &'a [u8],
    content_sha256: &'a str,
    file_name: String,
    provenance: Vec<ArtifactProvenance>,
}

/// Existing analyzer validation bound to the exact case blob it inspected
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalyzerValidationReceipt<'a> {
    node_id: u64,
    sha256: &'a str,
    byte_length: usize,
    summary: ValidationSummary,
}

impl<'a> AnalyzerValidationReceipt<'a> {
    /// Bind a validation summary to the analyzed node, digest, and byte length
    pub const fn new(
        node_id: u64,
        sha256: &'a str,
        byte_length: usize,
        summary: ValidationSummary,
    ) -> Self {
        Self {
            node_id,
            sha256,
            byte_length,
            summary,
        }
    }
}

struct AnalyzerExportValidation {
    extension: String,
    validation: StructuralValidation,
}

#[derive(Clone, Copy)]
struct ExportEdges<'a> {
    parsed: &'a HashSet<(u64, u64)>,
    contains_member: &'a HashSet<(u64, u64)>,
    followed_by: &'a HashSet<(u64, u64)>,
}

impl SelectedArtifact<'_> {
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub(crate) const fn sha256(&self) -> &str {
        self.content_sha256
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn provenance(&self) -> &[ArtifactProvenance] {
        &self.provenance
    }
}
pub(super) struct ExportSpec {
    pub(super) file_name: String,
    pub(super) archive_path: Option<String>,
    pub(super) structural_validation: StructuralValidation,
    pub(super) extension_evidence_node: Option<u64>,
}

/// Choose complete export objects and group only byte-for-byte duplicates
pub fn select_artifacts(case: &Case) -> Result<Vec<SelectedArtifact<'_>>, Box<dyn Error>> {
    let mut work = SelectionWorkCache::default();
    select_artifacts_with_cache(case, &mut work)
}

/// Reuse trusted analyzer validation when publishing the same case blobs
pub fn select_artifacts_with_analyzer_receipts<'a>(
    case: &'a Case,
    receipts: &[AnalyzerValidationReceipt<'_>],
) -> Result<Vec<SelectedArtifact<'a>>, Box<dyn Error>> {
    let mut work = SelectionWorkCache::default();
    select_artifacts_with_receipts_and_cache(case, receipts, &mut work)
}

pub(super) fn select_artifacts_with_cache<'a>(
    case: &'a Case,
    work: &mut SelectionWorkCache<'a>,
) -> Result<Vec<SelectedArtifact<'a>>, Box<dyn Error>> {
    select_artifacts_with_receipts_and_cache(case, &[], work)
}

fn select_artifacts_with_receipts_and_cache<'a>(
    case: &'a Case,
    receipts: &[AnalyzerValidationReceipt<'_>],
    work: &mut SelectionWorkCache<'a>,
) -> Result<Vec<SelectedArtifact<'a>>, Box<dyn Error>> {
    // Indexes resolve node references without rescanning the case for each object
    let nodes_by_id: HashMap<u64, &Node> =
        case.nodes().iter().map(|node| (node.id, node)).collect();
    let bytes_by_id: HashMap<&str, &[u8]> = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect();
    let validator = ArtifactValidator::default();
    let mut validation = SelectionValidation {
        validator: &validator,
        work,
    };
    let parsed_edges = observed_parse_edges(case);
    let contains_member_edges = observed_edges(case, "contains_member");
    let followed_by_edges = observed_edges(case, "followed_by");
    let receipts_by_node = analyzer_receipts_by_node(receipts)?;
    let specs = export_specs(
        case,
        &nodes_by_id,
        &bytes_by_id,
        ExportEdges {
            parsed: &parsed_edges,
            contains_member: &contains_member_edges,
            followed_by: &followed_by_edges,
        },
        &receipts_by_node,
        &mut validation,
    );

    // Validated blob identifiers provide the content key without hashing every byte per node
    let mut artifact_by_blob: HashMap<&str, usize> = HashMap::new();
    let mut artifacts: Vec<SelectedArtifact<'_>> = Vec::new();

    for node in case.nodes() {
        let Some(spec) = specs.get(&node.id) else {
            continue;
        };
        let blob_id = node
            .blob
            .as_deref()
            .ok_or("recovered artifact node has no retained bytes")?;
        let content_sha256 = blob_id
            .strip_prefix("sha256:")
            .ok_or("recovered artifact blob ID is not a SHA-256 identity")?;
        let bytes = bytes_by_id
            .get(blob_id)
            .copied()
            .ok_or("recovered artifact node bytes are missing")?;
        let provenance = ArtifactProvenance {
            id: node.id,
            kind: node.kind.clone(),
            archive_path: spec.archive_path.clone(),
            completion_basis: node
                .details
                .get("completion_basis")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            reconstruction_status: reconstruction_status(node),
            structural_validation: spec.structural_validation.clone(),
            extension_evidence_node: spec.extension_evidence_node,
        };

        if let Some(index) = artifact_by_blob.get(blob_id).copied() {
            // Keep every source visible while storing identical content once
            artifacts
                .get_mut(index)
                .ok_or("artifact index is missing")?
                .provenance
                .push(provenance);
            continue;
        }

        let index = artifacts.len();
        artifact_by_blob.insert(blob_id, index);
        artifacts.push(SelectedArtifact {
            bytes,
            content_sha256,
            file_name: spec.file_name.clone(),
            provenance: vec![provenance],
        });
    }
    Ok(artifacts)
}

fn analyzer_receipts_by_node<'a, 'digest>(
    receipts: &'a [AnalyzerValidationReceipt<'digest>],
) -> Result<HashMap<u64, &'a AnalyzerValidationReceipt<'digest>>, Box<dyn Error>> {
    let mut by_node = HashMap::new();
    by_node.try_reserve(receipts.len())?;
    for receipt in receipts {
        by_node.insert(receipt.node_id, receipt);
    }
    Ok(by_node)
}

fn export_specs<'a>(
    case: &'a Case,
    nodes_by_id: &HashMap<u64, &'a Node>,
    bytes_by_id: &HashMap<&'a str, &'a [u8]>,
    edges: ExportEdges<'_>,
    analysis_receipts: &HashMap<u64, &AnalyzerValidationReceipt<'_>>,
    validation: &mut SelectionValidation<'_, 'a>,
) -> HashMap<u64, ExportSpec> {
    let signature_extensions =
        record_signature_extensions(case, nodes_by_id, bytes_by_id, validation);
    let mut specs = direct_export_specs(
        case,
        &signature_extensions,
        bytes_by_id,
        analysis_receipts,
        validation,
    );
    add_validated_inputs(
        case,
        nodes_by_id,
        bytes_by_id,
        edges.parsed,
        validation,
        &mut specs,
    );
    add_validated_archives(
        case,
        nodes_by_id,
        bytes_by_id,
        edges.parsed,
        edges.contains_member,
        validation,
        &mut specs,
    );
    add_validated_png_structures(
        case,
        nodes_by_id,
        bytes_by_id,
        edges.parsed,
        edges.followed_by,
        validation,
        &mut specs,
    );
    specs
}

fn direct_export_specs<'a>(
    case: &'a Case,
    signature_extensions: &HashMap<u64, SignatureExtension>,
    bytes_by_id: &HashMap<&'a str, &'a [u8]>,
    analysis_receipts: &HashMap<u64, &AnalyzerValidationReceipt<'_>>,
    validation: &mut SelectionValidation<'_, 'a>,
) -> HashMap<u64, ExportSpec> {
    let mut specs = HashMap::new();

    for node in case.nodes() {
        let spec = match node.kind.as_str() {
            "record_object" => {
                let signature = signature_extensions.get(&node.id);
                let analyzed = analysis_receipts
                    .get(&node.id)
                    .copied()
                    .and_then(|receipt| analyzer_export_validation(node, receipt, bytes_by_id));
                let extension = analyzed
                    .as_ref()
                    .map(|matched| matched.extension.clone())
                    .or_else(|| signature.and_then(|matched| matched.extension.clone()))
                    .or_else(|| {
                        let blob_id = node.blob.as_deref()?;
                        let bytes = node_bytes(node, bytes_by_id)?;
                        validation
                            .is_plain_text(blob_id, bytes)
                            .then(|| String::from("txt"))
                    });
                let structural_validation = analyzed
                    .as_ref()
                    .map(|matched| matched.validation.clone())
                    .or_else(|| signature.map(|matched| matched.structural_validation.clone()))
                    .unwrap_or_else(StructuralValidation::not_checked);
                let extension_evidence_node = signature
                    .filter(|matched| {
                        analyzed.as_ref().is_none_or(|receipt| {
                            matched
                                .extension
                                .as_ref()
                                .is_some_and(|candidate| candidate == &receipt.extension)
                        })
                    })
                    .map(|matched| matched.evidence_node);
                Some(ExportSpec {
                    file_name: format!(
                        "artifact-{}-record.{}",
                        node.id,
                        extension.as_deref().unwrap_or("bin")
                    ),
                    archive_path: None,
                    structural_validation,
                    extension_evidence_node,
                })
            }
            _ => None,
        };
        if let Some(spec) = spec {
            specs.insert(node.id, spec);
        }
    }
    specs
}

fn analyzer_export_validation(
    node: &Node,
    receipt: &AnalyzerValidationReceipt<'_>,
    bytes_by_id: &HashMap<&str, &[u8]>,
) -> Option<AnalyzerExportValidation> {
    let blob_id = node.blob.as_deref()?;
    if blob_id.strip_prefix("sha256:")? != receipt.sha256 {
        return None;
    }
    let bytes = node_bytes(node, bytes_by_id)?;
    if bytes.len() != receipt.byte_length
        || receipt.summary.state != ArtifactValidationState::Validated
        || receipt.summary.range
            != Some(FileRange {
                offset: 0,
                length: bytes.len(),
            })
    {
        return None;
    }

    let (extension, format) = match (receipt.summary.format?, receipt.summary.boundary?) {
        (AnalysisFormat::Der, AnalysisBoundary::DerEncodedLength) => ("der", "der_structure"),
        (AnalysisFormat::Png, AnalysisBoundary::PngIend) => ("png", "png_structure"),
        (AnalysisFormat::Zip, AnalysisBoundary::ZipEndRecord) => ("zip", "zip_structure"),
        (AnalysisFormat::Der, AnalysisBoundary::PngIend | AnalysisBoundary::ZipEndRecord)
        | (
            AnalysisFormat::Png,
            AnalysisBoundary::DerEncodedLength | AnalysisBoundary::ZipEndRecord,
        )
        | (AnalysisFormat::Zip, AnalysisBoundary::DerEncodedLength | AnalysisBoundary::PngIend)
        | (AnalysisFormat::Elf | AnalysisFormat::PortableExecutable, _) => return None,
    };
    Some(AnalyzerExportValidation {
        extension: extension.to_owned(),
        validation: StructuralValidation::validated(format, None),
    })
}

fn observed_parse_edges(case: &Case) -> HashSet<(u64, u64)> {
    observed_edges(case, "parsed_as")
}

pub(super) fn observed_edges(case: &Case, relation: &str) -> HashSet<(u64, u64)> {
    case.edges()
        .iter()
        .filter(|edge| edge.relation == relation && edge.status == EvidenceStatus::Observed)
        .map(|edge| (edge.from, edge.to))
        .collect()
}

pub(super) fn node_bytes<'a>(
    node: &Node,
    bytes_by_id: &HashMap<&str, &'a [u8]>,
) -> Option<&'a [u8]> {
    node.blob
        .as_deref()
        .and_then(|blob_id| bytes_by_id.get(blob_id).copied())
}
