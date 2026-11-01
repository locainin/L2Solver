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
use l2_workbench::evidence::{Case, Node};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError, MemoryLease};
use std::{collections::HashMap, error::Error, ops::Deref};

/// One exact byte object selected for export, with every retained source reference
pub struct SelectedArtifact<'a> {
    bytes: &'a [u8],
    content_sha256: &'a str,
    file_name: String,
    provenance: Vec<ArtifactProvenance>,
}

/// Selected artifacts and the charge for their retained names and provenance
pub struct SelectedArtifacts<'a> {
    artifacts: Vec<SelectedArtifact<'a>>,
    // Drop the selected data before releasing its shared charge
    _memory: Option<MemoryLease>,
}

impl<'a> Deref for SelectedArtifacts<'a> {
    type Target = [SelectedArtifact<'a>];

    fn deref(&self) -> &Self::Target {
        &self.artifacts
    }
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
pub fn select_artifacts<'a>(
    case: &'a Case,
    memory: Option<&MemoryBudget>,
) -> Result<SelectedArtifacts<'a>, Box<dyn Error>> {
    let mut work = SelectionWorkCache::new(memory);
    select_artifacts_with_receipts_and_cache(case, &[], &mut work, memory)
}

/// Reuse trusted analyzer validation when publishing the same case blobs
pub fn select_artifacts_with_analyzer_receipts<'a>(
    case: &'a Case,
    receipts: &[AnalyzerValidationReceipt<'_>],
    memory: Option<&MemoryBudget>,
) -> Result<SelectedArtifacts<'a>, Box<dyn Error>> {
    let mut work = SelectionWorkCache::new(memory);
    select_artifacts_with_receipts_and_cache(case, receipts, &mut work, memory)
}

#[cfg(test)]
pub(super) fn select_artifacts_with_cache<'a>(
    case: &'a Case,
    work: &mut SelectionWorkCache<'a>,
) -> Result<SelectedArtifacts<'a>, Box<dyn Error>> {
    select_artifacts_with_receipts_and_cache(case, &[], work, None)
}

fn select_artifacts_with_receipts_and_cache<'a>(
    case: &'a Case,
    receipts: &[AnalyzerValidationReceipt<'_>],
    work: &mut SelectionWorkCache<'a>,
    memory: Option<&MemoryBudget>,
) -> Result<SelectedArtifacts<'a>, Box<dyn Error>> {
    let mut retained = memory
        .map(|budget| budget.try_reserve(MemoryClass::Publication, 0))
        .transpose()?;
    let validator = ArtifactValidator::default();
    let mut validation = SelectionValidation {
        validator: &validator,
        work,
    };
    let receipts_by_node = analyzer_receipts_by_node(receipts)?;
    let specs = export_specs(case, &receipts_by_node, &mut validation)?;

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
        let bytes = case
            .blob(blob_id)
            .map(|blob| blob.bytes.as_slice())
            .ok_or("recovered artifact node bytes are missing")?;
        let provenance = ArtifactProvenance {
            id: node.id,
            kind: crate::retained_memory::copy_optional(&node.kind, &mut retained)?,
            archive_path: spec
                .archive_path
                .as_deref()
                .map(|path| crate::retained_memory::copy_optional(path, &mut retained))
                .transpose()?,
            completion_basis: node
                .details
                .get("completion_basis")
                .and_then(serde_json::Value::as_str)
                .map(|basis| crate::retained_memory::copy_optional(basis, &mut retained))
                .transpose()?,
            reconstruction_status: reconstruction_status(node),
            structural_validation: spec.structural_validation.clone(),
            extension_evidence_node: spec.extension_evidence_node,
        };

        if let Some(index) = artifact_by_blob.get(blob_id).copied() {
            // Keep every source visible while storing identical content once
            let origins = &mut artifacts
                .get_mut(index)
                .ok_or("artifact index is missing")?
                .provenance;
            crate::retained_memory::grow_vec_optional(origins, &mut retained, 1)?;
            origins.push(provenance);
            continue;
        }

        let index = artifacts.len();
        artifact_by_blob.try_reserve(1)?;
        crate::retained_memory::grow_vec_optional(&mut artifacts, &mut retained, 1)?;
        let mut origins = Vec::new();
        crate::retained_memory::grow_vec_optional(&mut origins, &mut retained, 1)?;
        origins.push(provenance);
        let file_name = crate::retained_memory::copy_optional(&spec.file_name, &mut retained)?;
        artifact_by_blob.insert(blob_id, index);
        artifacts.push(SelectedArtifact {
            bytes,
            content_sha256,
            file_name,
            provenance: origins,
        });
    }
    Ok(SelectedArtifacts {
        artifacts,
        _memory: retained,
    })
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
    analysis_receipts: &HashMap<u64, &AnalyzerValidationReceipt<'_>>,
    validation: &mut SelectionValidation<'_, 'a>,
) -> Result<HashMap<u64, ExportSpec>, MemoryError> {
    let signature_extensions = record_signature_extensions(case, validation)?;
    let mut specs = direct_export_specs(case, &signature_extensions, analysis_receipts, validation);
    add_validated_inputs(case, validation, &mut specs)?;
    add_validated_archives(case, validation, &mut specs)?;
    add_validated_png_structures(case, validation, &mut specs)?;
    Ok(specs)
}

fn direct_export_specs<'a>(
    case: &'a Case,
    signature_extensions: &HashMap<u64, SignatureExtension>,
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
                    .and_then(|receipt| analyzer_export_validation(case, node, receipt));
                let extension = analyzed
                    .as_ref()
                    .map(|matched| matched.extension.clone())
                    .or_else(|| signature.and_then(|matched| matched.extension.clone()))
                    .or_else(|| {
                        let blob_id = node.blob.as_deref()?;
                        let bytes = node_bytes(case, node)?;
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
    case: &Case,
    node: &Node,
    receipt: &AnalyzerValidationReceipt<'_>,
) -> Option<AnalyzerExportValidation> {
    let blob_id = node.blob.as_deref()?;
    if blob_id.strip_prefix("sha256:")? != receipt.sha256 {
        return None;
    }
    let bytes = node_bytes(case, node)?;
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

pub(super) fn node_bytes<'a>(case: &'a Case, node: &Node) -> Option<&'a [u8]> {
    node.blob
        .as_deref()
        .and_then(|blob_id| case.blob(blob_id))
        .map(|blob| blob.bytes.as_slice())
}
