//! Bounded artifact analysis, per-input caching, and evidence-case construction

use super::{
    input::LoadedSource,
    invalid_input,
    output::{ArtifactRecord, SourceRecord},
    policy::RefinePolicy,
};
use crate::arguments::{RecoveryOptions, RecoveryProfile};
use l2_workbench::{
    artifact::{
        AnalysisStatus, ArtifactAnalysisOptions, ArtifactOrigin,
        analyze_artifacts_with_source_sha256,
    },
    evidence::{Case, MAX_NODES},
    job::{
        Counter, Job, Phase,
        cache::{Cache, CacheEntry, CacheReadPolicy, Lease, SourceIdentity, StageKey, StageStatus},
    },
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
};

pub(super) const REFINE_ANALYZER_ALGORITHM_VERSION: u32 = 2;
pub(super) const CACHE_ANALYSIS_SCHEMA_VERSION: u32 = 1;
const MAX_CACHE_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn analyze_sources(
    sources: &[LoadedSource],
    policy: &RefinePolicy,
    recovery: &RecoveryOptions,
    cache: Option<&Cache>,
    cache_warnings: &mut Vec<String>,
    job: &Job,
) -> Result<AnalyzedSources, Box<dyn Error>> {
    let mut analysis = AnalyzedSources::new(policy.case_blob_limit, sources.len())?;
    for (source_index, source) in sources.iter().enumerate() {
        job.check_cancelled()?;
        job.set_current(
            Phase::TransformDiscovery,
            format!("analyzing {}", source.label.escape_debug()),
        )?;
        let report = analyze_source_cached(
            source,
            policy.analyzer,
            recovery,
            cache,
            cache_warnings,
            job,
        )?;
        analysis.append_source(source_index, source, report, job)?;
    }
    Ok(analysis)
}

pub(super) struct AnalyzedSources {
    pub(super) case: Case,
    pub(super) source_records: Vec<SourceRecord>,
    pub(super) artifact_records: Vec<ArtifactRecord>,
    pub(super) complete: bool,
}

impl AnalyzedSources {
    fn new(case_blob_limit: usize, source_count: usize) -> Result<Self, Box<dyn Error>> {
        let mut source_records = Vec::new();
        source_records
            .try_reserve_exact(source_count)
            .map_err(|_| io::Error::other("source report allocation failed"))?;
        Ok(Self {
            case: Case::with_blob_limit(case_blob_limit)?,
            source_records,
            artifact_records: Vec::new(),
            complete: true,
        })
    }

    fn append_source(
        &mut self,
        source_index: usize,
        source: &LoadedSource,
        report: l2_workbench::artifact::ArtifactAnalysis,
        job: &Job,
    ) -> Result<(), Box<dyn Error>> {
        let artifact_counts = self.append_artifacts(source_index, &report.artifacts)?;
        self.complete &= report.status == AnalysisStatus::Complete;
        self.source_records.push(SourceRecord {
            label: source.label.clone(),
            sha256: report.source_sha256.clone(),
            byte_length: report.source_length,
            status: report.status,
            omissions: report.omissions,
        });

        job.increment(
            Counter::CandidatesExamined,
            u64::try_from(report.artifacts.len())?,
        )?;
        job.increment(Counter::Transforms, artifact_counts.transforms)?;
        job.increment(Counter::ExpandedMembers, artifact_counts.archive_members)?;
        job.increment(Counter::ValidatedArtifacts, artifact_counts.validated)?;
        job.advance(Phase::Expansion, artifact_counts.archive_members)?;
        job.advance(Phase::TransformDiscovery, 1)?;
        Ok(())
    }

    fn append_artifacts(
        &mut self,
        source_index: usize,
        artifacts: &[l2_workbench::artifact::AnalyzedArtifact],
    ) -> Result<ArtifactCounts, Box<dyn Error>> {
        let origin_count = artifacts
            .iter()
            .try_fold(0_usize, |count, artifact| {
                count.checked_add(artifact.origins.len())
            })
            .ok_or_else(|| invalid_input("artifact origin count overflows"))?;
        if origin_count > MAX_NODES.saturating_sub(self.artifact_records.len()) {
            return Err(invalid_input(
                "refined output exceeds the provenance record limit",
            ));
        }
        self.artifact_records
            .try_reserve(origin_count)
            .map_err(|_| io::Error::other("artifact provenance allocation failed"))?;

        let mut counts = ArtifactCounts::default();
        for artifact in artifacts {
            if self.case.nodes().len() >= MAX_NODES {
                return Err(invalid_input(
                    "refined output exceeds the evidence node limit",
                ));
            }
            let node_id = self.case.add_bytes_node(
                "record_object",
                &artifact.bytes,
                Vec::new(),
                json!({"source_index":source_index,"artifact_index":artifact.index}),
            )?;
            for origin in &artifact.origins {
                match origin {
                    ArtifactOrigin::Transformation { .. } => counts.transforms += 1,
                    ArtifactOrigin::ArchiveMember { .. } => counts.archive_members += 1,
                    ArtifactOrigin::EmbeddedObject { .. } | ArtifactOrigin::Source => {}
                }
                self.artifact_records.push(ArtifactRecord {
                    node_id,
                    source_index,
                    artifact_index: artifact.index,
                    origin: origin.clone(),
                    validation: artifact.validation,
                    signature_match_count: artifact.signature_match_count,
                });
            }
            if artifact.validation.state
                == l2_workbench::artifact::ArtifactValidationState::Validated
            {
                counts.validated += 1;
            }
        }
        Ok(counts)
    }
}

#[derive(Default)]
struct ArtifactCounts {
    transforms: u64,
    archive_members: u64,
    validated: u64,
}

pub(super) fn analyze_source_cached(
    source: &LoadedSource,
    options: ArtifactAnalysisOptions,
    recovery: &RecoveryOptions,
    cache: Option<&Cache>,
    cache_warnings: &mut Vec<String>,
    job: &Job,
) -> Result<l2_workbench::artifact::ArtifactAnalysis, Box<dyn Error>> {
    let Some(cache) = cache else {
        return Ok(analyze_artifacts_with_source_sha256(
            &source.bytes,
            &source.sha256,
            options,
        )?);
    };

    let identity = SourceIdentity::from_sha256(source.sha256.clone())?;
    let policy = json!({
        "schema_version": CACHE_ANALYSIS_SCHEMA_VERSION,
        "transform_proposal_format_version": TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "analyzer": options,
        "profile": recovery_profile_name(recovery.profile),
    });
    let key = StageKey::new(
        "file_artifact_analysis",
        CACHE_ANALYSIS_SCHEMA_VERSION,
        format!("l2_artifact_analyzer_v{REFINE_ANALYZER_ALGORITHM_VERSION}"),
        &policy,
        &identity,
        &[],
    )?;

    if !recovery.refresh {
        match cache.lookup(&key, CacheReadPolicy::AllowPartial) {
            Ok(Some(entry)) => match load_cached_analysis(&entry, source, options) {
                Ok(report) => {
                    job.increment(Counter::CacheHits, 1)?;
                    return Ok(report);
                }
                Err(error) if recovery.strict_cache => return Err(error),
                Err(error) => record_cache_warning(
                    cache_warnings,
                    format!("cached file analysis was rejected: {error}"),
                ),
            },
            Ok(None) => {}
            Err(error) if recovery.strict_cache => return Err(error.into()),
            Err(error) => record_cache_warning(
                cache_warnings,
                format!("file analysis cache lookup failed: {error}"),
            ),
        }
    }
    job.increment(Counter::CacheMisses, 1)?;

    let lease = match cache.lease(&key) {
        Ok(lease) => Some(lease),
        Err(error) if recovery.strict_cache => return Err(error.into()),
        Err(error) => {
            record_cache_warning(
                cache_warnings,
                format!("file analysis cache write lease unavailable: {error}"),
            );
            None
        }
    };

    let report = analyze_artifacts_with_source_sha256(&source.bytes, &source.sha256, options)?;
    if let Some(lease) = lease
        && let Err(error) = store_cached_analysis(lease, &report)
    {
        if recovery.strict_cache {
            return Err(error);
        }
        record_cache_warning(
            cache_warnings,
            format!("file analysis cache commit failed: {error}"),
        );
    }
    Ok(report)
}

pub(super) const fn recovery_profile_name(profile: RecoveryProfile) -> &'static str {
    match profile {
        RecoveryProfile::Fast => "fast",
        RecoveryProfile::Normal => "normal",
        RecoveryProfile::Deep => "deep",
    }
}

pub(super) fn record_cache_warning(warnings: &mut Vec<String>, warning: String) {
    const MAX_WARNINGS: usize = 8;
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    } else if warnings.len() == MAX_WARNINGS {
        warnings.push(String::from("additional cache warnings suppressed"));
    }
}

#[derive(Serialize)]
struct CacheAnalysisReceiptRef<'a> {
    schema_version: u32,
    artifact_lengths: Vec<usize>,
    analysis: &'a l2_workbench::artifact::ArtifactAnalysis,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheAnalysisReceipt {
    schema_version: u32,
    artifact_lengths: Vec<usize>,
    analysis: l2_workbench::artifact::ArtifactAnalysis,
}

fn store_cached_analysis(
    lease: Lease,
    report: &l2_workbench::artifact::ArtifactAnalysis,
) -> Result<(), Box<dyn Error>> {
    let directory = lease.directory();
    let receipt = CacheAnalysisReceiptRef {
        schema_version: CACHE_ANALYSIS_SCHEMA_VERSION,
        artifact_lengths: report
            .artifacts
            .iter()
            .map(|artifact| artifact.bytes.len())
            .collect(),
        analysis: report,
    };
    let mut receipt_file = File::options()
        .write(true)
        .create_new(true)
        .open(directory.join("analysis.json"))?;
    serde_json::to_writer(&mut receipt_file, &receipt)?;
    receipt_file.write_all(b"\n")?;
    receipt_file.sync_all()?;

    for artifact in &report.artifacts {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(cache_artifact_file_name(artifact.index)))?;
        file.write_all(&artifact.bytes)?;
        file.sync_all()?;
    }
    File::open(directory)?.sync_all()?;

    let status = if report.status == AnalysisStatus::Partial {
        StageStatus::Partial
    } else {
        StageStatus::Complete
    };
    let metadata = json!({
        "schema_version": CACHE_ANALYSIS_SCHEMA_VERSION,
        "receipt": "analysis.json",
        "artifact_count": report.artifacts.len(),
    });
    drop(lease.commit(status, metadata)?);
    Ok(())
}

fn load_cached_analysis(
    entry: &CacheEntry,
    source: &LoadedSource,
    options: ArtifactAnalysisOptions,
) -> Result<l2_workbench::artifact::ArtifactAnalysis, Box<dyn Error>> {
    let receipt = read_cache_receipt(entry, source, options)?;
    let mut report = receipt.analysis;
    restore_cached_artifact_bytes(
        entry,
        &mut report,
        receipt.artifact_lengths,
        options.limits.max_total_output_bytes,
    )?;
    validate_cached_lineage(&report)?;
    validate_cached_source_artifact(&report, source)?;
    Ok(report)
}

fn read_cache_receipt(
    entry: &CacheEntry,
    source: &LoadedSource,
    options: ArtifactAnalysisOptions,
) -> Result<CacheAnalysisReceipt, Box<dyn Error>> {
    let metadata = entry.metadata();
    if metadata
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(CACHE_ANALYSIS_SCHEMA_VERSION))
        || metadata.get("receipt").and_then(serde_json::Value::as_str) != Some("analysis.json")
    {
        return Err(invalid_cache_entry(
            "file analysis cache metadata is invalid",
        ));
    }

    let receipt_path = entry.directory().join("analysis.json");
    let (receipt_bytes, _) = super::input::read_snapshot(
        crate::input::regular_no_follow(&receipt_path)?,
        MAX_CACHE_RECEIPT_BYTES,
        None,
        None,
    )?;
    let receipt: CacheAnalysisReceipt = serde_json::from_slice(&receipt_bytes)?;
    if receipt.schema_version != CACHE_ANALYSIS_SCHEMA_VERSION
        || metadata
            .get("artifact_count")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::try_from(receipt.analysis.artifacts.len())?)
        || receipt.artifact_lengths.len() != receipt.analysis.artifacts.len()
        || receipt.analysis.source_sha256 != source.sha256
        || receipt.analysis.source_length != source.bytes.len()
        || receipt.analysis.artifacts.len() > options.limits.max_artifacts
    {
        return Err(invalid_cache_entry(
            "file analysis cache receipt is inconsistent",
        ));
    }

    let expected_status = if receipt.analysis.status == AnalysisStatus::Partial {
        StageStatus::Partial
    } else {
        StageStatus::Complete
    };
    if entry.status() != expected_status {
        return Err(invalid_cache_entry(
            "file analysis cache status is inconsistent",
        ));
    }
    Ok(receipt)
}

fn restore_cached_artifact_bytes(
    entry: &CacheEntry,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    artifact_lengths: Vec<usize>,
    total_limit: usize,
) -> Result<(), Box<dyn Error>> {
    let mut output_bytes = 0_usize;
    for (index, (artifact, expected_length)) in report
        .artifacts
        .iter_mut()
        .zip(artifact_lengths)
        .enumerate()
    {
        if artifact.index != index {
            return Err(invalid_cache_entry(
                "file analysis artifact order is invalid",
            ));
        }
        let next_total = output_bytes
            .checked_add(expected_length)
            .ok_or_else(|| invalid_cache_entry("file analysis artifact byte total overflows"))?;
        if next_total > total_limit {
            return Err(invalid_cache_entry(
                "file analysis artifacts exceed their byte limit",
            ));
        }
        let artifact_path = entry
            .directory()
            .join(cache_artifact_file_name(artifact.index));
        let (bytes, digest) = super::input::read_snapshot(
            crate::input::regular_no_follow(&artifact_path)?,
            expected_length,
            Some(expected_length),
            Some(&artifact.sha256),
        )?;
        if digest != artifact.sha256 {
            return Err(invalid_cache_entry(
                "file analysis artifact hash is invalid",
            ));
        }
        artifact.bytes = bytes;
        output_bytes = next_total;
    }
    Ok(())
}

fn validate_cached_source_artifact(
    report: &l2_workbench::artifact::ArtifactAnalysis,
    source: &LoadedSource,
) -> Result<(), Box<dyn Error>> {
    if let Some(source_artifact) = report.artifacts.first()
        && source_artifact
            .origins
            .iter()
            .any(|origin| matches!(origin, ArtifactOrigin::Source))
        && source_artifact.bytes != source.bytes
    {
        return Err(invalid_cache_entry(
            "cached source artifact bytes do not match the input",
        ));
    }
    Ok(())
}

fn validate_cached_lineage(
    report: &l2_workbench::artifact::ArtifactAnalysis,
) -> Result<(), Box<dyn Error>> {
    for artifact in &report.artifacts {
        for origin in &artifact.origins {
            let (parent_index, range) = match origin {
                ArtifactOrigin::Source => continue,
                ArtifactOrigin::EmbeddedObject {
                    parent_index,
                    range,
                    ..
                }
                | ArtifactOrigin::Transformation {
                    parent_index,
                    input_range: range,
                    ..
                } => (*parent_index, *range),
                ArtifactOrigin::ArchiveMember {
                    parent_index,
                    archive_range,
                    ..
                } => (*parent_index, *archive_range),
            };
            let parent = report
                .artifacts
                .get(parent_index)
                .ok_or_else(|| invalid_cache_entry("cached artifact parent is missing"))?;
            let end = range
                .offset
                .checked_add(range.length)
                .ok_or_else(|| invalid_cache_entry("cached artifact source range overflows"))?;
            if end > parent.bytes.len() {
                return Err(invalid_cache_entry(
                    "cached artifact source range is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn cache_artifact_file_name(index: usize) -> String {
    format!("artifact-{index:08}.bin")
}

fn invalid_cache_entry(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
