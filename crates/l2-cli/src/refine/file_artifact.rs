//! Metadata for validated original ranges kept outside the in-memory Case blob store

use super::{analysis_memory as retained, input::AdmittedPngBoundary};
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
use std::{error::Error, fmt::Write, fs::File, mem::size_of, rc::Rc};

// This allowance covers stream metadata and derived names, digests and provenance
// Derived origin capacity and the shared file-artifact vector are charged separately
pub(super) const STREAM_METADATA_BYTES: u64 = 16 * 1024;
const FILE_ORIGIN_KIND: &str = "file_range_artifact";

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
    source_memory: Option<MemoryLease>,
}

impl FileArtifact {
    pub(super) fn zip(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        length: usize,
        sha256: &str,
        entry_count: usize,
        memory: &MemoryBudget,
    ) -> Result<Self, Box<dyn Error>> {
        let lease = source_metadata_lease(memory, node_id, sha256.len(), FileFormat::Zip)?;
        let digest = copy_text(sha256)?;
        let result = Self::new(
            node_id,
            source_index,
            artifact_index,
            FileRange { offset: 0, length },
            digest,
            entry_count,
            FileFormat::Zip,
        )?;
        result.with_source_memory(lease)
    }

    pub(super) fn png(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        mut admitted: AdmittedPngBoundary,
    ) -> Result<Self, Box<dyn Error>> {
        let required = source_metadata_bytes(
            node_id,
            admitted.boundary.sha256.capacity(),
            FileFormat::Png,
        )?;
        // Grow the existing digest charge without reserving the same bytes twice
        admitted.memory.try_resize(required)?;
        let AdmittedPngBoundary { boundary, memory } = admitted;
        let result = Self::new(
            node_id,
            source_index,
            artifact_index,
            boundary.range,
            boundary.sha256,
            boundary.chunk_count,
            FileFormat::Png,
        )?;
        result.with_source_memory(memory)
    }

    pub(super) fn derived_zip(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        archive: &l2_workbench::artifact::zip::ZipArtifactReport,
        source_length: usize,
        derived: DerivedArtifact,
    ) -> Result<Self, Box<dyn Error>> {
        let digest = copy_text(&archive.archive_sha256)?;
        Ok(Self::new(
            node_id,
            source_index,
            artifact_index,
            FileRange {
                offset: 0,
                length: archive.archive_size,
            },
            digest,
            archive.entry_count,
            FileFormat::Zip,
        )?
        .with_derived(source_length, derived))
    }

    pub(super) fn derived_png(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        boundary: StreamPngBoundary,
        source_length: usize,
        derived: DerivedArtifact,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self::new(
            node_id,
            source_index,
            artifact_index,
            boundary.range,
            boundary.sha256,
            boundary.chunk_count,
            FileFormat::Png,
        )?
        .with_derived(source_length, derived))
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
        )?
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
        let memory = self
            .derived_memory
            .as_mut()
            .ok_or("derived metadata lease is missing")?;
        // Both origin buffers remain charged until the old one has been dropped
        retained::grow_vec_exact(&mut self.origins, memory, additional)?;
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

    fn with_source_memory(mut self, mut memory: MemoryLease) -> Result<Self, Box<dyn Error>> {
        let actual = self
            .sha256
            .capacity()
            .checked_add(self.file_name.capacity())
            .and_then(|bytes| {
                bytes.checked_add(
                    self.origins
                        .capacity()
                        .checked_mul(size_of::<FileOrigin>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    self.provenance
                        .capacity()
                        .checked_mul(size_of::<ArtifactProvenance>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    self.provenance
                        .first()
                        .map_or(0, |origin| origin.kind.capacity()),
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok());
        let Some(actual) = actual else {
            drop(self);
            drop(memory);
            return Err("source artifact metadata size overflows".into());
        };
        if let Err(error) = memory.try_resize(actual) {
            drop(self);
            drop(memory);
            return Err(Box::new(error));
        }
        self.source_memory = Some(memory);
        Ok(self)
    }

    fn new(
        node_id: u64,
        source_index: usize,
        artifact_index: usize,
        range: FileRange,
        sha256: String,
        structure_count: usize,
        kind: FileFormat,
    ) -> Result<Self, Box<dyn Error>> {
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
        // Every source-owned buffer was admitted before reaching these allocations
        let mut origins = Vec::new();
        origins.try_reserve_exact(1)?;
        origins.push(FileOrigin::Source(ArtifactOrigin::SourceRange {
            range,
            format: embedded,
        }));
        let mut provenance = Vec::new();
        provenance.try_reserve_exact(1)?;
        provenance.push(ArtifactProvenance {
            id: node_id,
            kind: copy_text(FILE_ORIGIN_KIND)?,
            archive_path: None,
            completion_basis: None,
            reconstruction_status: ReconstructionStatus::Unknown,
            structural_validation: StructuralValidation::Validated {
                format: evidence,
                evidence_node: None,
            },
            extension_evidence_node: None,
        });
        let mut file_name = String::new();
        file_name.try_reserve_exact(file_name_length(node_id, extension)?)?;
        write!(&mut file_name, "artifact-{node_id}-record.{extension}")?;
        Ok(Self {
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
            origins,
            backing: FileBacking::Source,
            file_name,
            provenance,
            derived_memory: None,
            source_memory: None,
        })
    }
}

#[derive(Clone, Copy)]
enum FileFormat {
    Png,
    Zip,
}

fn file_name_length(node_id: u64, extension: &str) -> Result<usize, Box<dyn Error>> {
    let digits = if node_id == 0 {
        1
    } else {
        usize::try_from(node_id.ilog10() + 1)?
    };
    "artifact-"
        .len()
        .checked_add(digits)
        .and_then(|length| length.checked_add("-record.".len()))
        .and_then(|length| length.checked_add(extension.len()))
        .ok_or_else(|| "source artifact filename size overflows".into())
}

fn source_metadata_lease(
    memory: &MemoryBudget,
    node_id: u64,
    digest_bytes: usize,
    format: FileFormat,
) -> Result<MemoryLease, Box<dyn Error>> {
    Ok(memory.try_reserve(
        MemoryClass::Executor,
        source_metadata_bytes(node_id, digest_bytes, format)?,
    )?)
}

fn source_metadata_bytes(
    node_id: u64,
    digest_bytes: usize,
    format: FileFormat,
) -> Result<u64, Box<dyn Error>> {
    let extension = match format {
        FileFormat::Png => "png",
        FileFormat::Zip => "zip",
    };
    let bytes = digest_bytes
        .checked_add(file_name_length(node_id, extension)?)
        .and_then(|bytes| bytes.checked_add(FILE_ORIGIN_KIND.len()))
        .and_then(|bytes| bytes.checked_add(size_of::<FileOrigin>()))
        .and_then(|bytes| bytes.checked_add(size_of::<ArtifactProvenance>()))
        .ok_or("source artifact metadata size overflows")?;
    Ok(u64::try_from(bytes)?)
}

fn copy_text(value: &str) -> Result<String, Box<dyn Error>> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())?;
    copy.push_str(value);
    Ok(copy)
}
