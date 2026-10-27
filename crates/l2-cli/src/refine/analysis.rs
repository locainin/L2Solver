//! Bounded artifact analysis, per-input caching, and evidence-case construction

use super::{
    input::{InputSet, LoadedSource},
    invalid_input,
    output::{ArtifactRecord, SourceRecord},
    policy::RefinePolicy,
};
use crate::arguments::{RecoveryOptions, RecoveryProfile};
use crate::workbench::artifact_export::AnalyzerValidationReceipt;
use l2_workbench::{
    artifact::{
        AnalysisStatus, ArtifactAnalysisOptions, ArtifactOrigin, ArtifactValidationState,
        analyze_artifacts_with_source_sha256,
    },
    evidence::{Case, MAX_NODES},
    job::{
        CacheFallbackKind, CacheStage, Counter, Job, Phase,
        cache::{Cache, CacheEntry, CacheReadPolicy, Lease, SourceIdentity, StageKey, StageStatus},
    },
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    fs::File,
    io::{self, Write},
};

pub(super) const REFINE_ANALYZER_ALGORITHM_VERSION: u32 = 4;
pub(super) const CACHE_ANALYSIS_SCHEMA_VERSION: u32 = 1;
const MAX_CACHE_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn analyze_sources(
    sources: &[LoadedSource],
    input_set: &InputSet,
    policy: &RefinePolicy,
    recovery: &RecoveryOptions,
    cache: Option<&Cache>,
    job: &Job,
) -> Result<AnalyzedSources, Box<dyn Error>> {
    let mut analysis = AnalyzedSources::new(policy.case_blob_limit, sources.len())?;
    for (source_index, source) in sources.iter().enumerate() {
        job.check_cancelled()?;
        job.set_current(
            Phase::TransformDiscovery,
            format!("analyzing {}", source.label.escape_debug()),
        )?;
        // Every source shares the Case space left by earlier sources
        let remaining = policy
            .case_blob_limit
            .checked_sub(analysis.case.resource_usage().blob_bytes)
            .ok_or_else(|| invalid_input("case blob usage exceeds its limit"))?;
        let mut options = policy.analyzer;
        options.limits.max_total_output_bytes =
            options.limits.max_total_output_bytes.min(remaining);
        let report = if source.bytes().is_some() && remaining == 0 {
            no_case_space(source, policy.case_blob_limit)
        } else if source.bytes().is_some() {
            analyze_source_cached(source, options, recovery, cache, job)?
        } else {
            let report = source.analyze_ranges(input_set, source_index, options, job)?;
            record_analysis_work(job, &report)?;
            report
        };
        let expanded_members = report
            .artifacts
            .iter()
            .flat_map(|artifact| &artifact.origins)
            .filter(|origin| matches!(origin, ArtifactOrigin::ArchiveMember { .. }))
            .count();
        analysis.append_source(source_index, source, report)?;
        job.advance(Phase::Expansion, u64::try_from(expanded_members)?)?;
        job.advance(Phase::TransformDiscovery, 1)?;
    }
    Ok(analysis)
}

fn no_case_space(
    source: &LoadedSource,
    maximum: usize,
) -> l2_workbench::artifact::ArtifactAnalysis {
    l2_workbench::artifact::ArtifactAnalysis {
        source_sha256: source.sha256.clone(),
        source_length: source.length(),
        artifacts: Vec::new(),
        status: AnalysisStatus::Partial,
        omissions: vec![l2_workbench::artifact::AnalysisOmission::CaseBlobLimit { maximum }],
        region_transform_reports: Vec::new(),
        work_bytes: 0,
    }
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

    pub(super) fn analyzer_validation_receipts(
        &self,
    ) -> Result<Vec<AnalyzerValidationReceipt>, Box<dyn Error>> {
        let mut seen_nodes = HashSet::new();
        seen_nodes.try_reserve(self.artifact_records.len())?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(self.artifact_records.len())
            .map_err(|_| io::Error::other("artifact validation allocation failed"))?;

        for artifact in &self.artifact_records {
            if artifact.validation.state != ArtifactValidationState::Validated
                || !seen_nodes.insert(artifact.node_id)
            {
                continue;
            }
            receipts.push(AnalyzerValidationReceipt::new(
                artifact.node_id,
                artifact.sha256.clone(),
                artifact.byte_length,
                artifact.validation,
            ));
        }
        Ok(receipts)
    }

    fn append_source(
        &mut self,
        source_index: usize,
        source: &LoadedSource,
        report: l2_workbench::artifact::ArtifactAnalysis,
    ) -> Result<(), Box<dyn Error>> {
        let reason = analysis_reason(&report);
        self.append_artifacts(source_index, &report.artifacts)?;
        self.complete &= report.status == AnalysisStatus::Complete;
        self.source_records.push(SourceRecord {
            label: source.label.clone(),
            sha256: report.source_sha256.clone(),
            byte_length: report.source_length,
            status: report.status,
            omissions: report.omissions,
            reason,
        });
        Ok(())
    }

    fn append_artifacts(
        &mut self,
        source_index: usize,
        artifacts: &[l2_workbench::artifact::AnalyzedArtifact],
    ) -> Result<(), Box<dyn Error>> {
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
                self.artifact_records.push(ArtifactRecord {
                    node_id,
                    source_index,
                    artifact_index: artifact.index,
                    origin: origin.clone(),
                    sha256: artifact.sha256.clone(),
                    byte_length: artifact.bytes.len(),
                    validation: artifact.validation,
                    signature_match_count: artifact.signature_match_count,
                });
            }
        }
        Ok(())
    }
}

fn analysis_reason(report: &l2_workbench::artifact::ArtifactAnalysis) -> Option<String> {
    if let Some((max_object_bytes, omitted_candidates, signature_scans_omitted, uncovered_range)) =
        report.omissions.iter().find_map(|omission| {
            if let l2_workbench::artifact::AnalysisOmission::SourceRangeCoverage {
                max_object_bytes,
                omitted_candidates,
                signature_scans_omitted,
                uncovered_range,
                ..
            } = omission
            {
                Some((
                    *max_object_bytes,
                    *omitted_candidates,
                    *signature_scans_omitted,
                    *uncovered_range,
                ))
            } else {
                None
            }
        })
    {
        let uncovered_bytes = uncovered_range.map_or(0, |range| range.length);
        return Some(format!(
            "range analysis searches for embedded PNG and ZIP objects; objects up to {max_object_bytes} bytes fit across windows, subject to budgets; {uncovered_bytes} source bytes lacked complete range coverage, {omitted_candidates} candidates and {signature_scans_omitted} signature scans were omitted; whole-source validation, archive expansion, and transforms were not performed"
        ));
    }
    match report.status {
        AnalysisStatus::Complete => None,
        AnalysisStatus::Unsupported => Some(String::from(
            "no supported object or canonical derivation was found",
        )),
        AnalysisStatus::Partial if !report.omissions.is_empty() => Some(format!(
            "bounded analysis omitted work or outputs; see {} source omission(s)",
            report.omissions.len()
        )),
        AnalysisStatus::Partial => Some(region_analysis_reason(report)),
    }
}

fn region_analysis_reason(report: &l2_workbench::artifact::ArtifactAnalysis) -> String {
    let mut incomplete_report_count = 0_usize;
    let mut omitted_region_count = 0_usize;
    let mut omitted_region_bytes = 0_usize;
    let mut omitted_proposals = 0_usize;
    let mut omitted_assessments = 0_usize;
    for artifact_report in &report.region_transform_reports {
        let coverage = artifact_report.report.coverage;
        if !coverage.complete {
            incomplete_report_count = incomplete_report_count.saturating_add(1);
            omitted_region_count = omitted_region_count
                .saturating_add(coverage.omissions.regions)
                .saturating_add(coverage.omissions.cues)
                .saturating_add(coverage.omissions.invalid_cues)
                .saturating_add(coverage.omissions.incomplete_regions);
            omitted_region_bytes = omitted_region_bytes
                .saturating_add(coverage.omissions.scan_bytes)
                .saturating_add(coverage.omissions.region_bytes);
        }
        for region in &artifact_report.report.regions {
            omitted_proposals =
                omitted_proposals.saturating_add(region.proposal_report.omissions.candidates);
            omitted_assessments =
                omitted_assessments.saturating_add(region.proposal_report.omissions.reports);
        }
    }
    if incomplete_report_count > 0 {
        format!(
            "bounded region search was incomplete ({omitted_region_count} range or cue(s) and {omitted_region_bytes} byte(s) omitted)"
        )
    } else if omitted_proposals > 0 || omitted_assessments > 0 {
        format!(
            "bounded region syntax checks omitted {omitted_proposals} candidate(s) and {omitted_assessments} assessment(s)"
        )
    } else {
        String::from("one or more bounded analysis stages were incomplete")
    }
}

fn record_analysis_work(
    job: &Job,
    report: &l2_workbench::artifact::ArtifactAnalysis,
) -> Result<(), Box<dyn Error>> {
    let transforms = report
        .artifacts
        .iter()
        .flat_map(|artifact| &artifact.origins)
        .filter(|origin| matches!(origin, ArtifactOrigin::Transformation { .. }))
        .count();
    let expanded_members = report
        .artifacts
        .iter()
        .flat_map(|artifact| &artifact.origins)
        .filter(|origin| matches!(origin, ArtifactOrigin::ArchiveMember { .. }))
        .count();
    let validated = report
        .artifacts
        .iter()
        .filter(|artifact| artifact.validation.state == ArtifactValidationState::Validated)
        .count();
    job.increment(
        Counter::CandidatesExamined,
        u64::try_from(report.artifacts.len())?,
    )?;
    job.increment(Counter::Transforms, u64::try_from(transforms)?)?;
    job.increment(Counter::ExpandedMembers, u64::try_from(expanded_members)?)?;
    job.increment(Counter::ValidatedArtifacts, u64::try_from(validated)?)?;
    Ok(())
}

pub(super) fn analyze_source_cached(
    source: &LoadedSource,
    options: ArtifactAnalysisOptions,
    recovery: &RecoveryOptions,
    cache: Option<&Cache>,
    job: &Job,
) -> Result<l2_workbench::artifact::ArtifactAnalysis, Box<dyn Error>> {
    let bytes = source.bytes().ok_or_else(|| {
        invalid_input("file-backed source cannot use the in-memory analysis cache")
    })?;
    let Some(cache) = cache else {
        let report = analyze_artifacts_with_source_sha256(bytes, &source.sha256, options)?;
        record_analysis_work(job, &report)?;
        return Ok(report);
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
                Err(_) => note_cache_fallback(
                    job,
                    CacheFallbackKind::InvalidEntry,
                    format_args!("cached file analysis was rejected"),
                )?,
            },
            Ok(None) => {}
            Err(error) if recovery.strict_cache => return Err(error.into()),
            Err(_) => note_cache_fallback(
                job,
                CacheFallbackKind::LookupFailed,
                format_args!("file analysis cache lookup failed"),
            )?,
        }
    }
    job.increment(Counter::CacheMisses, 1)?;

    let lease = match cache.lease(&key) {
        Ok(lease) => Some(lease),
        Err(error) if recovery.strict_cache => return Err(error.into()),
        Err(_) => {
            note_cache_fallback(
                job,
                CacheFallbackKind::LeaseUnavailable,
                format_args!("file analysis cache write lease unavailable"),
            )?;
            None
        }
    };

    let report = analyze_artifacts_with_source_sha256(bytes, &source.sha256, options)?;
    record_analysis_work(job, &report)?;
    if let Some(lease) = lease
        && let Err(error) = store_cached_analysis(lease, &report)
    {
        if recovery.strict_cache {
            return Err(error);
        }
        note_cache_fallback(
            job,
            CacheFallbackKind::CommitFailed,
            format_args!("file analysis cache commit failed"),
        )?;
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

fn note_cache_fallback(
    job: &Job,
    kind: CacheFallbackKind,
    detail: fmt::Arguments<'_>,
) -> Result<(), Box<dyn Error>> {
    job.record_cache_fallback(CacheStage::ArtifactAnalysis, kind, detail)?;
    Ok(())
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
        || receipt.analysis.source_length != source.length()
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
        && source.bytes() != Some(source_artifact.bytes.as_slice())
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
                ArtifactOrigin::SourceRange { .. } => {
                    return Err(invalid_cache_entry(
                        "cached source-range reports are unsupported",
                    ));
                }
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
