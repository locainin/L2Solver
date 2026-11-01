//! Refinement identity, provenance manifest, and user-facing summaries

use super::{
    analysis::{
        CACHE_ANALYSIS_SCHEMA_VERSION, REFINE_ANALYZER_ALGORITHM_VERSION, recovery_profile_name,
    },
    analysis_memory,
    file_artifact::{FileArtifact, FileOrigin},
    input::LoadedSource,
    invalid_input,
    policy::RefinePolicy,
};
use crate::{
    arguments::RecoveryOptions,
    result_directory::{ResultIdentity, ResultKind},
    workbench::artifact_export::{self, SelectedArtifact},
};
use l2_workbench::{
    artifact::{AnalysisOmission, AnalysisStatus, ArtifactOrigin},
    job::{MemoryBudget, MemoryClass, MemoryLease, cache::SourceIdentity},
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
};
use serde::Serialize;
use serde_json::json;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

const REFINE_ALGORITHM_VERSION: u32 = 17;

#[derive(Serialize)]
pub(super) struct SourceRecord {
    pub(super) label: String,
    pub(super) sha256: Option<String>,
    pub(super) byte_length: usize,
    pub(super) status: AnalysisStatus,
    pub(super) omissions: Vec<AnalysisOmission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) work_bytes_charged: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) zip_expanded_work_bytes_charged: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<String>,
    // Hold the report charge until its retained omissions are dropped
    #[serde(skip)]
    pub(super) omission_memory: l2_workbench::job::MemoryLease,
}

pub(super) struct ArtifactRecord {
    pub(super) node_id: u64,
    pub(super) source_index: usize,
    pub(super) artifact_index: usize,
    pub(super) origin: ArtifactOrigin,
    pub(super) sha256: String,
    pub(super) byte_length: usize,
    pub(super) validation: l2_workbench::artifact::ValidationSummary,
    pub(super) signature_match_count: usize,
}

#[derive(Serialize)]
pub(super) struct RefineManifest<'a> {
    schema_version: u32,
    complete: bool,
    sources: &'a [SourceRecord],
    artifacts: Vec<PublishedArtifactRecord<'a>>,
    // Manifest records drop before their shared memory charge
    #[serde(skip)]
    _memory: MemoryLease,
}

#[derive(Serialize)]
struct PublishedArtifactRecord<'a> {
    file: &'a str,
    byte_length: usize,
    sha256: &'a str,
    origins: Vec<PublishedOriginRecord<'a>>,
    nodes: &'a [artifact_export::ArtifactProvenance],
}

#[derive(Serialize)]
struct PublishedOriginRecord<'a> {
    source_index: usize,
    source_label: &'a str,
    artifact_index: usize,
    origin: PublishedOrigin<'a>,
    validation: l2_workbench::artifact::ValidationSummary,
    signature_match_count: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PublishedOrigin<'a> {
    Analyzer(&'a ArtifactOrigin),
    File(&'a FileOrigin),
}

pub(super) fn result_identity(
    sources: &[LoadedSource],
    recovery: &RecoveryOptions,
    policy: &RefinePolicy,
) -> Result<ResultIdentity, Box<dyn Error>> {
    let mut writer = SourceIdentityWriter::new()?;
    for source in sources {
        let digest = source
            .digest()
            .ok_or_else(|| invalid_input("source digest is not available before analysis"))?;
        writer.push(u64::try_from(source.length())?, digest)?;
    }
    let source = SourceIdentity::from_sha256(writer.finish()?)?;
    result_identity_with_source(source, recovery, policy)
}

pub(super) fn result_identity_with_source(
    source: SourceIdentity,
    recovery: &RecoveryOptions,
    policy: &RefinePolicy,
) -> Result<ResultIdentity, Box<dyn Error>> {
    Ok(ResultIdentity {
        kind: ResultKind::Refine,
        algorithm_version: REFINE_ALGORITHM_VERSION,
        source,
        settings: json!({
            "analyzer_limits": policy.analyzer.limits,
            "recovery_mode": policy.analyzer.recovery,
            "profile": recovery_profile_name(recovery.profile),
            "memory_limit": u64::try_from(policy.memory_limit)?,
            "source_read_limit": policy.source_read_limit,
            "stream_output_limit": policy.stream_output_limit,
            "stream_work_limit": policy.stream_work_limit,
            "stream_expansion_ratio": super::policy::STREAM_EXPANSION_RATIO,
            "analyzer_algorithm_version": REFINE_ANALYZER_ALGORITHM_VERSION,
            "analysis_receipt_schema_version": CACHE_ANALYSIS_SCHEMA_VERSION,
            "transform_proposal_format_version": TRANSFORM_PROPOSAL_FORMAT_VERSION,
        }),
    })
}

/// Hash the ordered source lengths and SHA-256 values for one refinement input set
pub fn refine_source_identity_sha256<'a>(
    sources: impl IntoIterator<Item = (u64, &'a str)>,
) -> Result<String, Box<dyn Error>> {
    let mut writer = SourceIdentityWriter::new()?;
    for (byte_length, digest) in sources {
        writer.push(byte_length, digest)?;
    }
    writer.finish()
}

#[derive(Serialize)]
struct SourceIdentityPart<'a> {
    byte_length: u64,
    sha256: &'a str,
}

pub(super) struct SourceIdentityWriter {
    writer: super::hash::DigestWriter,
    first: bool,
}

impl SourceIdentityWriter {
    pub(super) fn new() -> io::Result<Self> {
        let mut writer = super::hash::DigestWriter::new();
        writer.write_all(b"[\"l2solver-refine-input-set-v1\",[")?;
        Ok(Self {
            writer,
            first: true,
        })
    }

    pub(super) fn push(&mut self, byte_length: u64, digest: &str) -> Result<(), Box<dyn Error>> {
        if !self.first {
            self.writer.write_all(b",")?;
        }
        self.first = false;
        serde_json::to_writer(
            &mut self.writer,
            &SourceIdentityPart {
                byte_length,
                sha256: digest,
            },
        )?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<String, Box<dyn Error>> {
        self.writer.write_all(b"]]")?;
        Ok(self.writer.finish())
    }
}

pub(super) fn write_reused_summary(
    output: &mut impl Write,
    destination: &Path,
    complete: bool,
    output_file_count: usize,
    dry_run: bool,
) -> Result<(), Box<dyn Error>> {
    if dry_run {
        writeln!(output, "Dry run: no files were written")?;
    }
    writeln!(
        output,
        "{} existing refined result at {} ({}; {} output file receipt(s))",
        if dry_run { "Would reuse" } else { "Reused" },
        destination.display().to_string().escape_debug(),
        if complete { "complete" } else { "incomplete" },
        output_file_count,
    )?;
    if !complete {
        writeln!(
            output,
            "Analysis is incomplete; the result is retained with status 3"
        )?;
    }
    Ok(())
}

pub(super) fn make_manifest<'a>(
    selected: &'a [SelectedArtifact<'a>],
    file_artifacts: &'a [FileArtifact],
    sources: &'a [SourceRecord],
    artifacts: &'a [ArtifactRecord],
    complete: bool,
    budget: &MemoryBudget,
) -> Result<RefineManifest<'a>, Box<dyn Error>> {
    let mut memory = budget.try_reserve(MemoryClass::Publication, 0)?;
    let mut published = Vec::new();
    let artifact_count = selected
        .len()
        .checked_add(file_artifacts.len())
        .ok_or_else(|| invalid_input("artifact count overflows"))?;
    analysis_memory::grow_vec_exact(&mut published, &mut memory, artifact_count)?;
    for selected_artifact in selected {
        let provenance = selected_artifact.provenance();
        let origin_count = provenance
            .iter()
            .try_fold(0_usize, |count, item| {
                count.checked_add(records_for_node(artifacts, item.id).count())
            })
            .ok_or_else(|| invalid_input("artifact origin count overflows"))?;
        let mut origins = Vec::new();
        analysis_memory::grow_vec_exact(&mut origins, &mut memory, origin_count)?;
        for item in provenance {
            for artifact in records_for_node(artifacts, item.id) {
                let source = sources
                    .get(artifact.source_index)
                    .ok_or_else(|| invalid_input("artifact source index is missing"))?;
                origins.push(PublishedOriginRecord {
                    source_index: artifact.source_index,
                    source_label: &source.label,
                    artifact_index: artifact.artifact_index,
                    origin: PublishedOrigin::Analyzer(&artifact.origin),
                    validation: artifact.validation,
                    signature_match_count: artifact.signature_match_count,
                });
            }
        }
        published.push(PublishedArtifactRecord {
            file: selected_artifact.file_name(),
            byte_length: selected_artifact.bytes().len(),
            sha256: selected_artifact.sha256(),
            origins,
            nodes: provenance,
        });
    }
    append_file_records(&mut published, file_artifacts, sources, &mut memory)?;
    Ok(RefineManifest {
        schema_version: if sources.iter().all(|source| source.sha256.is_some()) {
            1
        } else {
            2
        },
        complete,
        sources,
        artifacts: published,
        _memory: memory,
    })
}

fn records_for_node(
    artifacts: &[ArtifactRecord],
    node_id: u64,
) -> impl Iterator<Item = &ArtifactRecord> {
    // Analysis appends each node's records together in increasing node order
    let start = artifacts.partition_point(|artifact| artifact.node_id < node_id);
    artifacts
        .iter()
        .skip(start)
        .take_while(move |artifact| artifact.node_id == node_id)
}

fn append_file_records<'a>(
    published: &mut Vec<PublishedArtifactRecord<'a>>,
    file_artifacts: &'a [FileArtifact],
    sources: &'a [SourceRecord],
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    for artifact in file_artifacts {
        let source = sources
            .get(artifact.source_index)
            .ok_or_else(|| invalid_input("artifact source index is missing"))?;
        let mut origins = Vec::new();
        analysis_memory::grow_vec_exact(&mut origins, memory, artifact.origins.len())?;
        for origin in &artifact.origins {
            origins.push(PublishedOriginRecord {
                source_index: artifact.source_index,
                source_label: &source.label,
                artifact_index: artifact.artifact_index,
                origin: PublishedOrigin::File(origin),
                validation: artifact.validation,
                signature_match_count: artifact.signature_match_count,
            });
        }
        published.push(PublishedArtifactRecord {
            file: &artifact.file_name,
            byte_length: artifact.range.length,
            sha256: &artifact.sha256,
            origins,
            nodes: &artifact.provenance,
        });
    }
    Ok(())
}

pub(super) fn write_manifest(
    staging: &Path,
    manifest: &RefineManifest<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(staging.join("manifest.json"))?;
    serde_json::to_writer(&mut file, manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn write_summary_file(
    staging: &Path,
    destination: &Path,
    selected: &[SelectedArtifact<'_>],
    file_artifacts: &[FileArtifact],
    sources: &[SourceRecord],
    complete: bool,
) -> Result<(), Box<dyn Error>> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(staging.join("summary.txt"))?;
    let status = if complete { "complete" } else { "incomplete" };
    // Write each line directly so the full summary is never retained in memory
    writeln!(
        file,
        "Refined artifacts\nDirectory: {}\nSources: {}; files: {}; status: {status}",
        destination.to_string_lossy().escape_debug(),
        sources.len(),
        selected.len() + file_artifacts.len(),
    )?;
    for source in sources {
        let analysis = match source.status {
            AnalysisStatus::Complete => "complete",
            AnalysisStatus::Unsupported => "unsupported",
            AnalysisStatus::Partial => "partial",
        };
        write!(
            file,
            "Source: {}; SHA-256: {}; bytes: {}; analysis: {analysis}",
            source.label.escape_debug(),
            source.sha256.as_deref().unwrap_or("not read"),
            source.byte_length,
        )?;
        if let Some(reason) = &source.reason {
            write!(file, "; reason: {}", reason.escape_debug())?;
        }
        writeln!(file)?;
    }
    for artifact in selected {
        writeln!(
            file,
            "  {} <- {} source reference(s)",
            artifact.file_name(),
            artifact.provenance().len(),
        )?;
    }
    for artifact in file_artifacts {
        writeln!(file, "  {} <- 1 source reference(s)", artifact.file_name)?;
    }
    file.sync_all()?;
    Ok(())
}

pub(super) fn write_summary(
    output: &mut impl Write,
    destination: &Path,
    selected: &[SelectedArtifact<'_>],
    file_artifacts: &[FileArtifact],
    sources: &[SourceRecord],
    complete: bool,
    dry_run: bool,
) -> Result<(), Box<dyn Error>> {
    if dry_run {
        writeln!(output, "Dry run: no files were written")?;
    }
    writeln!(
        output,
        "{} {} source object(s) into {} artifact file(s) at {}",
        if dry_run { "Would refine" } else { "Refined" },
        sources.len(),
        selected.len() + file_artifacts.len(),
        destination.display().to_string().escape_debug()
    )?;
    if !complete {
        writeln!(
            output,
            "Analysis is incomplete; the result is retained with status 3"
        )?;
    }
    Ok(())
}

pub(super) fn default_output_path(input: &Path) -> PathBuf {
    let mut output = input.as_os_str().to_owned();
    output.push(".refined");
    PathBuf::from(output)
}
