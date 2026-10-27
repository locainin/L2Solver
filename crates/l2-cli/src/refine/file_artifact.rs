//! Metadata for validated original ranges kept outside the in-memory Case blob store

use crate::workbench::artifact_export::{
    ArtifactProvenance, ReconstructionStatus, StructuralValidation,
};
use l2_workbench::artifact::{
    AnalysisBoundary, AnalysisFormat, ArtifactOrigin, ArtifactValidationState, EmbeddedFormat,
    FileRange, ValidationSummary,
};

pub(super) struct FileArtifact {
    pub(super) source_index: usize,
    pub(super) artifact_index: usize,
    pub(super) range: FileRange,
    pub(super) sha256: String,
    pub(super) validation: ValidationSummary,
    pub(super) origin: ArtifactOrigin,
    pub(super) file_name: String,
    pub(super) provenance: Vec<ArtifactProvenance>,
}

impl FileArtifact {
    pub(super) fn zip(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        length: usize,
        sha256: String,
        entry_count: usize,
    ) -> Self {
        Self {
            source_index,
            artifact_index,
            range: FileRange { offset: 0, length },
            sha256,
            validation: ValidationSummary {
                state: ArtifactValidationState::Validated,
                format: Some(AnalysisFormat::Zip),
                boundary: Some(AnalysisBoundary::ZipEndRecord),
                range: Some(FileRange { offset: 0, length }),
                structure_count: entry_count,
            },
            origin: ArtifactOrigin::SourceRange {
                range: FileRange { offset: 0, length },
                format: EmbeddedFormat::Zip,
            },
            file_name: format!("artifact-{node_id}-record.zip"),
            provenance: vec![ArtifactProvenance {
                id: node_id,
                kind: String::from("file_range_artifact"),
                archive_path: None,
                completion_basis: None,
                reconstruction_status: ReconstructionStatus::Unknown,
                structural_validation: StructuralValidation::Validated {
                    format: "zip_structure",
                    evidence_node: None,
                },
                extension_evidence_node: None,
            }],
        }
    }
}
