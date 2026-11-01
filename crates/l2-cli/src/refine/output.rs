//! Refinement identity, provenance manifest, and user-facing summaries

use super::{
    analysis::{
        CACHE_ANALYSIS_SCHEMA_VERSION, REFINE_ANALYZER_ALGORITHM_VERSION, recovery_profile_name,
    },
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
    job::cache::SourceIdentity,
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
    sha256,
};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

const REFINE_ALGORITHM_VERSION: u32 = 16;

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
    pub(super) _omission_memory: l2_workbench::job::MemoryLease,
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
}

#[derive(Serialize)]
struct PublishedArtifactRecord<'a> {
    file: &'a str,
    byte_length: usize,
    sha256: String,
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
    let input_identities = sources
        .iter()
        .map(|source| {
            Ok((
                u64::try_from(source.length())?,
                source.digest().ok_or_else(|| {
                    invalid_input("source digest is not available before analysis")
                })?,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let source = SourceIdentity::from_sha256(refine_source_identity_sha256(input_identities)?)?;
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
    #[derive(Serialize)]
    struct SourceIdentityPart<'a> {
        byte_length: u64,
        sha256: &'a str,
    }

    let mut inputs = Vec::new();
    for (byte_length, digest) in sources {
        inputs
            .try_reserve(1)
            .map_err(|_| io::Error::other("source identity allocation failed"))?;
        inputs.push(SourceIdentityPart {
            byte_length,
            sha256: digest,
        });
    }
    let source_set = serde_json::to_vec(&("l2solver-refine-input-set-v1", inputs))?;
    Ok(sha256(&source_set))
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
) -> Result<RefineManifest<'a>, Box<dyn Error>> {
    let mut records_by_node: HashMap<u64, Vec<&ArtifactRecord>> = HashMap::new();
    records_by_node
        .try_reserve(artifacts.len())
        .map_err(|_| io::Error::other("manifest provenance allocation failed"))?;
    for artifact in artifacts {
        let records = records_by_node.entry(artifact.node_id).or_default();
        records
            .try_reserve(1)
            .map_err(|_| io::Error::other("manifest provenance allocation failed"))?;
        records.push(artifact);
    }

    let mut published = Vec::new();
    published
        .try_reserve_exact(
            selected
                .len()
                .checked_add(file_artifacts.len())
                .ok_or_else(|| invalid_input("artifact count overflows"))?,
        )
        .map_err(|_| io::Error::other("manifest artifact allocation failed"))?;
    for selected_artifact in selected {
        let provenance = selected_artifact.provenance();
        let origin_count = provenance
            .iter()
            .filter_map(|item| records_by_node.get(&item.id))
            .try_fold(0_usize, |count, records| count.checked_add(records.len()))
            .ok_or_else(|| invalid_input("artifact origin count overflows"))?;
        let mut origins = Vec::new();
        origins
            .try_reserve_exact(origin_count)
            .map_err(|_| io::Error::other("manifest origin allocation failed"))?;
        for item in provenance {
            let Some(records) = records_by_node.get(&item.id) else {
                continue;
            };
            for artifact in records {
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
            sha256: selected_artifact.sha256().to_owned(),
            origins,
            nodes: provenance,
        });
    }
    append_file_records(&mut published, file_artifacts, sources)?;
    Ok(RefineManifest {
        schema_version: if sources.iter().all(|source| source.sha256.is_some()) {
            1
        } else {
            2
        },
        complete,
        sources,
        artifacts: published,
    })
}

fn append_file_records<'a>(
    published: &mut Vec<PublishedArtifactRecord<'a>>,
    file_artifacts: &'a [FileArtifact],
    sources: &'a [SourceRecord],
) -> Result<(), Box<dyn Error>> {
    for artifact in file_artifacts {
        let source = sources
            .get(artifact.source_index)
            .ok_or_else(|| invalid_input("artifact source index is missing"))?;
        let mut origins = Vec::new();
        origins.try_reserve_exact(artifact.origins.len())?;
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
            sha256: artifact.sha256.clone(),
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

pub(super) fn write_summary_file(staging: &Path, summary: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(staging.join("summary.txt"))?;
    file.write_all(summary.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn format_summary(
    destination: &Path,
    selected: &[SelectedArtifact<'_>],
    file_artifacts: &[FileArtifact],
    sources: &[SourceRecord],
    complete: bool,
) -> String {
    let status = if complete { "complete" } else { "incomplete" };
    let mut summary = format!(
        "Refined artifacts\nDirectory: {}\nSources: {}; files: {}; status: {status}\n",
        destination.display().to_string().escape_debug(),
        sources.len(),
        selected.len() + file_artifacts.len(),
    );
    for source in sources {
        summary.push_str("Source: ");
        summary.push_str(&source.label.escape_debug().to_string());
        summary.push_str("; SHA-256: ");
        summary.push_str(source.sha256.as_deref().unwrap_or("not read"));
        summary.push_str("; bytes: ");
        summary.push_str(&source.byte_length.to_string());
        summary.push_str("; analysis: ");
        summary.push_str(match source.status {
            AnalysisStatus::Complete => "complete",
            AnalysisStatus::Unsupported => "unsupported",
            AnalysisStatus::Partial => "partial",
        });
        if let Some(reason) = &source.reason {
            summary.push_str("; reason: ");
            summary.push_str(&reason.escape_debug().to_string());
        }
        summary.push('\n');
    }
    for artifact in selected {
        summary.push_str("  ");
        summary.push_str(artifact.file_name());
        summary.push_str(" <- ");
        summary.push_str(&artifact.provenance().len().to_string());
        summary.push_str(" source reference(s)\n");
    }
    for artifact in file_artifacts {
        summary.push_str("  ");
        summary.push_str(&artifact.file_name);
        summary.push_str(" <- 1 source reference(s)\n");
    }
    summary
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
