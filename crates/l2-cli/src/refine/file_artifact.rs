//! Metadata for validated original ranges kept outside the in-memory Case blob store

use crate::workbench::artifact_export::{
    ArtifactProvenance, ReconstructionStatus, StructuralValidation,
};
use l2_workbench::artifact::{
    AnalysisBoundary, AnalysisFormat, ArtifactOrigin, ArtifactValidationState, EmbeddedFormat,
    FileRange, StreamPngBoundary, ValidationSummary,
};
use l2_workbench::derivation::StreamReceipt;
use l2_workbench::job::MemoryLease;
use serde::Serialize;
use std::fs::File;

pub(super) enum FileBacking {
    Source,
    Spool { file: File, _memory: MemoryLease },
}

pub(super) struct DerivedFile {
    pub(super) file: File,
    pub(super) memory: MemoryLease,
    pub(super) steps: Vec<StreamReceipt>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum FileOrigin {
    Source(ArtifactOrigin),
    Stream(StreamOrigin),
}

#[derive(Serialize)]
pub(super) struct StreamOrigin {
    kind: &'static str,
    input_range: FileRange,
    output_range: FileRange,
    steps: Vec<StreamReceipt>,
}

pub(super) struct FileArtifact {
    pub(super) source_index: usize,
    pub(super) artifact_index: usize,
    pub(super) range: FileRange,
    pub(super) sha256: String,
    pub(super) validation: ValidationSummary,
    pub(super) origin: FileOrigin,
    pub(super) backing: FileBacking,
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

    pub(super) fn derived_zip(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        archive: &l2_workbench::artifact::zip::ZipArtifactReport,
        source_length: usize,
        derived: DerivedFile,
    ) -> Self {
        Self::zip(
            node_id,
            source_index,
            artifact_index,
            archive.archive_size,
            archive.archive_sha256.clone(),
            archive.entry_count,
        )
        .with_derived(source_length, derived)
    }

    pub(super) fn derived_png(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        boundary: StreamPngBoundary,
        source_length: usize,
        derived: DerivedFile,
    ) -> Self {
        Self::png(node_id, source_index, artifact_index, boundary)
            .with_derived(source_length, derived)
    }

    fn with_derived(mut self, source_length: usize, derived: DerivedFile) -> Self {
        self.origin = FileOrigin::Stream(StreamOrigin {
            kind: "stream_transformation",
            input_range: FileRange {
                offset: 0,
                length: source_length,
            },
            output_range: self.range,
            steps: derived.steps,
        });
        self.backing = FileBacking::Spool {
            file: derived.file,
            _memory: derived.memory,
        };
        if let Some(provenance) = self.provenance.first_mut() {
            provenance.kind = String::from("stream_transformation_artifact");
        }
        self
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
            origin: FileOrigin::Source(ArtifactOrigin::SourceRange {
                range,
                format: embedded,
            }),
            backing: FileBacking::Source,
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
