//! Metadata for validated original ranges kept outside the in-memory Case blob store

use crate::workbench::artifact_export::{
    ArtifactProvenance, ReconstructionStatus, StructuralValidation,
};
use l2_workbench::artifact::{
    AnalysisBoundary, AnalysisFormat, AnalyzedArtifact, ArtifactOrigin, ArtifactValidationState,
    EmbeddedFormat, FileRange, StreamPngBoundary, ValidationSummary,
};
use l2_workbench::derivation::StreamReceipt;
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use serde::Serialize;
use std::{error::Error, fs::File, rc::Rc};

pub(super) const STREAM_METADATA_BYTES: u64 = 16 * 1024;

pub(super) enum FileBacking {
    Source,
    Spool(Rc<Spool>),
}

pub(super) struct Spool {
    pub(super) file: File,
    _memory: MemoryLease,
}

#[derive(Clone)]
pub(super) struct DerivedFile {
    pub(super) steps: Rc<Vec<StreamReceipt>>,
    pub(super) spool: Rc<Spool>,
}

impl DerivedFile {
    pub(super) fn new(file: File, memory: MemoryLease, steps: Vec<StreamReceipt>) -> Self {
        Self {
            steps: Rc::new(steps),
            spool: Rc::new(Spool {
                file,
                _memory: memory,
            }),
        }
    }
}

pub(super) struct DerivedArtifact {
    pub(super) file: DerivedFile,
    metadata: MemoryLease,
}

impl DerivedArtifact {
    pub(super) fn new(
        file: DerivedFile,
        memory: &MemoryBudget,
        origin_count: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let bytes = origin_count
            .checked_mul(std::mem::size_of::<FileOrigin>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(STREAM_METADATA_BYTES))
            .ok_or("derived metadata size overflows")?;
        Ok(Self {
            file,
            metadata: memory.try_reserve(MemoryClass::Executor, bytes)?,
        })
    }
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
    steps: Rc<Vec<StreamReceipt>>,
}

pub(super) struct FileArtifact {
    pub(super) source_index: usize,
    pub(super) artifact_index: usize,
    pub(super) range: FileRange,
    pub(super) sha256: String,
    pub(super) validation: ValidationSummary,
    pub(super) signature_match_count: usize,
    pub(super) signatures_scanned: bool,
    pub(super) origins: Vec<FileOrigin>,
    pub(super) backing: FileBacking,
    pub(super) file_name: String,
    pub(super) provenance: Vec<ArtifactProvenance>,
    derived_memory: Option<MemoryLease>,
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
        derived: DerivedArtifact,
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
        derived: DerivedArtifact,
    ) -> Self {
        Self::png(node_id, source_index, artifact_index, boundary)
            .with_derived(source_length, derived)
    }

    pub(super) fn derived_ranges(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        source_length: usize,
        artifact: &AnalyzedArtifact,
        mut derived: DerivedArtifact,
    ) -> Result<Self, Box<dyn Error>> {
        let format = match artifact.validation.format {
            Some(AnalysisFormat::Png) => FileFormat::Png,
            Some(AnalysisFormat::Zip) => FileFormat::Zip,
            _ => return Err("derived range format is unsupported".into()),
        };
        let mut origins = Vec::new();
        origins.try_reserve_exact(artifact.origins.len())?;
        let extra = origins
            .capacity()
            .saturating_sub(artifact.origins.len())
            .checked_mul(std::mem::size_of::<FileOrigin>())
            .ok_or("derived origin capacity overflows")?;
        let charge = derived
            .metadata
            .bytes()
            .checked_add(u64::try_from(extra)?)
            .ok_or("derived metadata charge overflows")?;
        derived.metadata.try_resize(charge)?;
        let mut first_range = None;
        for origin in &artifact.origins {
            let ArtifactOrigin::SourceRange { range, .. } = origin else {
                return Err("derived range origin is invalid".into());
            };
            first_range.get_or_insert(*range);
            origins.push(FileOrigin::Stream(StreamOrigin {
                kind: "stream_transformation",
                input_range: FileRange {
                    offset: 0,
                    length: source_length,
                },
                output_range: *range,
                steps: Rc::clone(&derived.file.steps),
            }));
        }
        let range = first_range.ok_or("derived range has no origin")?;
        let mut result = Self::new(
            node_id,
            source_index,
            artifact_index,
            range,
            artifact.sha256.clone(),
            artifact.validation.structure_count,
            format,
        )
        .with_derived(source_length, derived);
        result.origins = origins;
        result.validation = artifact.validation;
        result.signature_match_count = artifact.signature_match_count;
        result.signatures_scanned = artifact.signatures_scanned;
        Ok(result)
    }

    pub(super) fn merge_derived_ranges(
        &mut self,
        artifact: &AnalyzedArtifact,
        source_length: usize,
        derived: &DerivedFile,
    ) -> Result<bool, Box<dyn Error>> {
        let FileBacking::Spool(spool) = &self.backing else {
            return Ok(false);
        };
        if !Rc::ptr_eq(spool, &derived.spool)
            || !artifact.origins.iter().any(|origin| {
                matches!(origin, ArtifactOrigin::SourceRange { range, .. } if *range == self.range)
            })
        {
            return Ok(false);
        }
        if self.sha256 != artifact.sha256 || self.validation.format != artifact.validation.format {
            return Err("derived range identity is inconsistent".into());
        }
        let mut additional = 0_usize;
        for origin in &artifact.origins {
            let ArtifactOrigin::SourceRange { range, .. } = origin else {
                return Err("derived range origin is invalid".into());
            };
            if !self.contains_stream_range(*range) {
                additional += 1;
            }
        }
        let previous_capacity = self.origins.capacity();
        let available = previous_capacity - self.origins.len();
        let growth = additional.saturating_sub(available);
        self.charge_origin_growth(growth)?;
        self.origins.try_reserve_exact(additional)?;
        let extra = self.origins.capacity() - previous_capacity - growth;
        self.charge_origin_growth(extra)?;
        for origin in &artifact.origins {
            let ArtifactOrigin::SourceRange { range, .. } = origin else {
                return Err("derived range origin is invalid".into());
            };
            if !self.contains_stream_range(*range) {
                self.origins.push(FileOrigin::Stream(StreamOrigin {
                    kind: "stream_transformation",
                    input_range: FileRange {
                        offset: 0,
                        length: source_length,
                    },
                    output_range: *range,
                    steps: Rc::clone(&derived.steps),
                }));
            }
        }
        if !self.signatures_scanned && artifact.signatures_scanned {
            self.signatures_scanned = true;
            self.signature_match_count = artifact.signature_match_count;
        }
        Ok(true)
    }

    pub(super) fn shares_spool(&self, derived: &DerivedFile) -> bool {
        matches!(&self.backing, FileBacking::Spool(spool) if Rc::ptr_eq(spool, &derived.spool))
    }

    fn contains_stream_range(&self, range: FileRange) -> bool {
        self.origins.iter().any(
            |origin| matches!(origin, FileOrigin::Stream(origin) if origin.output_range == range),
        )
    }

    fn charge_origin_growth(&mut self, growth: usize) -> Result<(), Box<dyn Error>> {
        let bytes = growth
            .checked_mul(std::mem::size_of::<FileOrigin>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or("derived origin capacity overflows")?;
        let memory = self
            .derived_memory
            .as_mut()
            .ok_or("derived metadata lease is missing")?;
        let total = memory
            .bytes()
            .checked_add(bytes)
            .ok_or("derived metadata charge overflows")?;
        memory.try_resize(total)?;
        Ok(())
    }

    fn with_derived(mut self, source_length: usize, derived: DerivedArtifact) -> Self {
        self.origins = vec![FileOrigin::Stream(StreamOrigin {
            kind: "stream_transformation",
            input_range: FileRange {
                offset: 0,
                length: source_length,
            },
            output_range: self.range,
            steps: derived.file.steps,
        })];
        self.backing = FileBacking::Spool(derived.file.spool);
        self.derived_memory = Some(derived.metadata);
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
            signature_match_count: 0,
            signatures_scanned: false,
            origins: vec![FileOrigin::Source(ArtifactOrigin::SourceRange {
                range,
                format: embedded,
            })],
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
            derived_memory: None,
        }
    }
}

#[derive(Clone, Copy)]
enum FileFormat {
    Png,
    Zip,
}
