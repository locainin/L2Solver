//! Metadata for validated original ranges kept outside the in-memory Case blob store

use crate::workbench::artifact_export::{
    ArtifactProvenance, ReconstructionStatus, StructuralValidation,
};
use l2_workbench::artifact::{
    AnalysisBoundary, AnalysisFormat, ArtifactOrigin, ArtifactValidationState, EmbeddedFormat,
    FileRange, StreamPngBoundary, ValidationSummary,
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
        Self::new(
            node_id,
            source_index,
            artifact_index,
            FileRange { offset: 0, length },
            sha256,
            entry_count,
            FileFormat::Zip,
        )
    }

    pub(super) fn png(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        boundary: StreamPngBoundary,
    ) -> Self {
        Self::new(
            node_id,
            source_index,
            artifact_index,
            boundary.range,
            boundary.sha256,
            boundary.chunk_count,
            FileFormat::Png,
        )
    }

    fn new(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        range: FileRange,
        sha256: String,
        structure_count: usize,
        kind: FileFormat,
    ) -> Self {
        let (format, boundary, embedded, extension, evidence) = match kind {
            FileFormat::Png => (
                AnalysisFormat::Png,
                AnalysisBoundary::PngIend,
                EmbeddedFormat::Png,
                "png",
                "png_structure",
            ),
            FileFormat::Zip => (
                AnalysisFormat::Zip,
                AnalysisBoundary::ZipEndRecord,
                EmbeddedFormat::Zip,
                "zip",
                "zip_structure",
            ),
        };
        Self {
            source_index,
            artifact_index,
            range,
            sha256,
            validation: ValidationSummary {
                state: ArtifactValidationState::Validated,
                format: Some(format),
                boundary: Some(boundary),
                range: Some(range),
                structure_count,
            },
            origin: ArtifactOrigin::SourceRange {
                range,
                format: embedded,
            },
            file_name: format!("artifact-{node_id}-record.{extension}"),
            provenance: vec![ArtifactProvenance {
                id: node_id,
                kind: String::from("file_range_artifact"),
                archive_path: None,
                completion_basis: None,
                reconstruction_status: ReconstructionStatus::Unknown,
                structural_validation: StructuralValidation::Validated {
                    format: evidence,
                    evidence_node: None,
                },
                extension_evidence_node: None,
            }],
        }
    }
}

#[derive(Clone, Copy)]
enum FileFormat {
    Png,
    Zip,
}
