//! Bounded artifact analysis, per-input caching, and evidence-case construction

use super::{
    file_artifact::{DerivedArtifact, FileArtifact},
    input::{InputSet, LoadedSource, ReadOmission, SourceData},
    invalid_input,
    output::{ArtifactRecord, SourceRecord},
    policy::RefinePolicy,
};
use crate::arguments::{RecoveryOptions, RecoveryProfile};
use crate::workbench::artifact_export::AnalyzerValidationReceipt;
use l2_workbench::{
    artifact::{
        AnalysisStatus, ArtifactAnalysisOptions, ArtifactOrigin, ArtifactValidationState,
        analyze_artifacts_with_memory,
    },
    evidence::{Case, MAX_NODES, SourceRange},
    job::{
        CacheFallbackKind, CacheStage, Counter, Job, MemoryBudget, MemoryClass, MemoryLease, Phase,
        cache::{Cache, CacheEntry, CacheReadPolicy, Lease, SourceIdentity, StageKey, StageStatus},
    },
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Write},
    ops::Deref,
};

pub(super) const REFINE_ANALYZER_ALGORITHM_VERSION: u32 = 14;
pub(super) const CACHE_ANALYSIS_SCHEMA_VERSION: u32 = 1;
const MAX_CACHE_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
#[path = "../../tests/refine/analysis_memory_lifetime.rs"]
mod memory_lifetime_tests;
#[cfg(test)]
#[path = "../../tests/refine/analysis_retained.rs"]
mod retained_tests;

// Report buffers must disappear before either of their live memory charges
struct SourceReport {
    report: l2_workbench::artifact::ArtifactAnalysis,
    _source_digest_memory: Option<MemoryLease>,
    _report_memory: Option<MemoryLease>,
    omission_memory: Option<MemoryLease>,
}

pub(super) fn analyze_sources(
    sources: &[LoadedSource],
    input_set: &InputSet,
    policy: &RefinePolicy,
    recovery: &RecoveryOptions,
    cache: Option<&Cache>,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<AnalyzedSources, Box<dyn Error>> {
    let mut analysis = AnalyzedSources::new(policy.case_blob_limit, sources.len(), memory)?;
    let mut streaming = super::range_transform::StreamingBudget::new(policy, sources)?;
    for (source_index, source) in sources.iter().enumerate() {
        job.check_cancelled()?;
        job.set_current(
            Phase::TransformDiscovery,
            format!("analyzing {}", source.label.escape_debug()),
        )?;
        if let SourceData::Skipped(omission) = &source.data {
            analysis.append_skipped_source(source, *omission, memory)?;
            job.advance(Phase::TransformDiscovery, 1)?;
            continue;
        }
        // Every source shares the Case space left by earlier sources
        let remaining = policy
            .case_blob_limit
            .checked_sub(analysis.case.resource_usage().blob_bytes)
            .ok_or_else(|| invalid_input("case blob usage exceeds its limit"))?;
        let mut options = policy.analyzer;
        options.limits.max_total_output_bytes =
            options.limits.max_total_output_bytes.min(remaining);
        options.limits.max_zip_expanded_bytes = streaming.zip_remaining();
        if source.bytes().is_some() {
            options.limits.max_total_work_bytes = options
                .limits
                .max_total_work_bytes
                .min(streaming.work_remaining());
        }
        let mut source_report = if source.bytes().is_some() && remaining == 0 {
            no_case_space(source, policy.case_blob_limit, memory)?
        } else if source.bytes().is_some() {
            let (report, lease) =
                analyze_source_cached(source, options, recovery, cache, job, memory)?;
            SourceReport {
                report,
                _source_digest_memory: None,
                _report_memory: Some(lease),
                omission_memory: None,
            }
        } else {
            analyze_file_source(FileAnalysis {
                analysis: &mut analysis,
                input: input_set,
                source_index,
                source,
                options,
                job,
                memory,
                streaming: &mut streaming,
                profile: recovery.profile,
            })?
        };
        let report = &mut source_report.report;
        if source.bytes().is_some() {
            streaming.charge_range_work(report.work_bytes)?;
            streaming.charge_zip_work(report.zip_expanded_work_bytes)?;
            // Source identity was reserved before analysis of any input began
            report.work_bytes = report
                .work_bytes
                .checked_add(source.length())
                .ok_or("source identity work overflows")?;
        }
        let expanded_members = report
            .artifacts
            .iter()
            .flat_map(|artifact| &artifact.origins)
            .filter(|origin| matches!(origin, ArtifactOrigin::ArchiveMember { .. }))
            .count();
        analysis.append_source(source_index, source, source_report, memory)?;
        job.advance(Phase::Expansion, u64::try_from(expanded_members)?)?;
        job.advance(Phase::TransformDiscovery, 1)?;
    }
    Ok(analysis)
}

struct FileAnalysis<'a> {
    analysis: &'a mut AnalyzedSources,
    input: &'a InputSet,
    source_index: usize,
    source: &'a LoadedSource,
    options: ArtifactAnalysisOptions,
    job: &'a Job,
    memory: &'a MemoryBudget,
    streaming: &'a mut super::range_transform::StreamingBudget,
    profile: RecoveryProfile,
}

fn analyze_file_source(context: FileAnalysis<'_>) -> Result<SourceReport, Box<dyn Error>> {
    let FileAnalysis {
        analysis,
        input,
        source_index,
        source,
        mut options,
        job,
        memory,
        streaming,
        profile,
    } = context;
    // The source observation remains live after its scanner buffers are released
    let _observation_memory = super::range_transform::reserve_stream_object(memory)?;
    let observation_work = streaming.reserve_observation(source.length())?;
    streaming.begin_source()?;
    options.limits.max_total_work_bytes = streaming.range_work_limit(
        source.length(),
        options.limits.max_total_work_bytes,
        profile,
    );
    let range = source.analyze_ranges(
        input,
        source_index,
        options,
        job,
        memory,
        observation_work.is_some(),
    )?;
    let retained =
        retain_source_formats(analysis, source_index, source, range, options, streaming)?;
    let mut source_report = SourceReport {
        report: retained.report,
        _source_digest_memory: Some(retained.source_digest_memory),
        _report_memory: Some(retained.report_memory),
        omission_memory: Some(retained.omission_memory),
    };
    let report = &mut source_report.report;
    let report_memory = source_report
        ._report_memory
        .as_mut()
        .ok_or("report memory is missing")?;
    let omission_memory = source_report
        .omission_memory
        .as_mut()
        .ok_or("omission memory is missing")?;
    let observation = retained.observation;
    // Source hashing is required even when syntax observation is skipped
    report.work_bytes = report
        .work_bytes
        .checked_add(source.length())
        .and_then(|work| work.checked_add(observation_work.unwrap_or(0)))
        .ok_or("stream observation work overflows")?;
    if let Some(observation) = observation {
        super::range_transform::append_streams(super::range_transform::StreamContext {
            analysis,
            input,
            source_index,
            source,
            observation,
            report,
            options,
            job,
            memory,
            report_memory,
            omission_memory,
            budget: streaming,
            profile,
        })?;
    } else {
        super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
        let reason = super::analysis_memory::copy_message(
            "stream observation work budget is exhausted",
            omission_memory,
        )?;
        report.omissions.push(
            l2_workbench::artifact::AnalysisOmission::SourceStreamTransform {
                operation: None,
                reason,
            },
        );
    }
    record_analysis_work(job, report)?;
    Ok(source_report)
}

struct RetainedSource {
    report: l2_workbench::artifact::ArtifactAnalysis,
    observation: Option<super::range_transform::Observation>,
    report_memory: MemoryLease,
    omission_memory: MemoryLease,
    source_digest_memory: MemoryLease,
}

fn retain_source_formats(
    analysis: &mut AnalyzedSources,
    source_index: usize,
    source: &LoadedSource,
    range: super::input::RangeAnalysis,
    options: ArtifactAnalysisOptions,
    streaming: &mut super::range_transform::StreamingBudget,
) -> Result<RetainedSource, Box<dyn Error>> {
    let mut omission_memory = range.omission_memory;
    let mut report = range.report;
    streaming.charge_range_work(report.work_bytes)?;
    let mut next_file_index = report.artifacts.len();
    if let Some(archive) = range.archive {
        if range.retain_source {
            let parent_index = next_file_index;
            next_file_index += 1;
            analysis.append_file_archive(
                source_index,
                parent_index,
                source,
                &report.source_sha256,
                &archive,
            )?;
            let previous_work = report.work_bytes;
            super::range_members::append_members(
                &mut report,
                archive,
                parent_index,
                options,
                &mut omission_memory,
            )?;
            streaming.charge_range_work(
                report
                    .work_bytes
                    .checked_sub(previous_work)
                    .ok_or("range member work decreased")?,
            )?;
        } else {
            record_unpublished_archive_members(&archive, &mut report, &mut omission_memory)?;
        }
    }
    if let Some(png) = range.png {
        let artifact_index = report
            .artifacts
            .iter()
            .map(|artifact| artifact.index)
            .max()
            .map_or(next_file_index, |index| next_file_index.max(index + 1));
        analysis.append_file_png(
            source_index,
            artifact_index,
            source,
            &report.source_sha256,
            png,
        )?;
    }
    streaming.charge_zip_work(report.zip_expanded_work_bytes)?;
    Ok(RetainedSource {
        report,
        observation: range.observation,
        report_memory: range.report_memory,
        omission_memory,
        source_digest_memory: range.source_digest_memory,
    })
}

fn record_unpublished_archive_members(
    archive: &l2_workbench::artifact::zip::ZipArtifactReport,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    use l2_workbench::artifact::{AnalysisOmission, FileRange};

    let range = FileRange {
        offset: 0,
        length: archive.archive_size,
    };
    let count = archive
        .entries
        .iter()
        .filter(|entry| entry.content.is_some())
        .count();
    if count > 0 {
        super::analysis_memory::reserve_omission(&mut report.omissions, memory)?;
        report
            .omissions
            .push(AnalysisOmission::SourceArchiveMembersOmitted { range, count });
    }
    for entry in &archive.entries {
        if let Some(reason) = entry.omission {
            super::analysis_memory::reserve_omission(&mut report.omissions, memory)?;
            report
                .omissions
                .push(AnalysisOmission::SourceArchiveMemberOmission {
                    range,
                    entry_index: entry.metadata.index,
                    reason,
                });
        }
    }
    Ok(())
}

fn no_case_space(
    source: &LoadedSource,
    maximum: usize,
    memory: &MemoryBudget,
) -> Result<SourceReport, Box<dyn Error>> {
    let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
    let source_sha256 = super::analysis_memory::copy_message(
        source
            .digest()
            .ok_or_else(|| invalid_input("memory source digest is missing"))?,
        &mut lease,
    )?;
    let mut omissions = Vec::new();
    super::analysis_memory::grow_vec_exact(&mut omissions, &mut lease, 1)?;
    omissions.push(l2_workbench::artifact::AnalysisOmission::CaseBlobLimit { maximum });
    let report = l2_workbench::artifact::ArtifactAnalysis {
        source_sha256,
        source_length: source.length(),
        artifacts: Vec::new(),
        status: AnalysisStatus::Partial,
        omissions,
        region_transform_reports: Vec::new(),
        work_bytes: 0,
        zip_expanded_work_bytes: 0,
    };
    Ok(SourceReport {
        report,
        _source_digest_memory: None,
        _report_memory: Some(lease),
        omission_memory: None,
    })
}

pub(super) struct AnalyzedSources {
    pub(super) case: Case,
    pub(super) source_records: Vec<SourceRecord>,
    pub(super) artifact_records: Vec<ArtifactRecord>,
    pub(super) file_artifacts: Vec<FileArtifact>,
    pub(super) complete: bool,
    pub(super) _source_records_memory: MemoryLease,
    memory: MemoryBudget,
    // Retained metadata vectors drop before this shared charge
    retained_memory: MemoryLease,
}

pub(super) struct AnalyzerValidationReceipts<'a> {
    receipts: Vec<AnalyzerValidationReceipt<'a>>,
    // The vector drops before its shared memory charge
    _memory: MemoryLease,
}

impl<'a> Deref for AnalyzerValidationReceipts<'a> {
    type Target = [AnalyzerValidationReceipt<'a>];

    fn deref(&self) -> &Self::Target {
        &self.receipts
    }
}

impl AnalyzedSources {
    pub(super) fn new(
        case_blob_limit: usize,
        source_count: usize,
        memory: &MemoryBudget,
    ) -> Result<Self, Box<dyn Error>> {
        let bytes = source_count
            .checked_mul(std::mem::size_of::<SourceRecord>())
            .ok_or("source record memory overflows")?;
        let mut source_records_memory =
            memory.try_reserve(MemoryClass::Executor, u64::try_from(bytes)?)?;
        let mut source_records = Vec::new();
        source_records
            .try_reserve_exact(source_count)
            .map_err(|_| io::Error::other("source report allocation failed"))?;
        super::analysis_memory::charge(
            &mut source_records_memory,
            (source_records.capacity() - source_count) * std::mem::size_of::<SourceRecord>(),
        )?;
        Ok(Self {
            case: Case::with_blob_limit_and_memory_budget(case_blob_limit, memory)?,
            source_records,
            artifact_records: Vec::new(),
            file_artifacts: Vec::new(),
            complete: true,
            _source_records_memory: source_records_memory,
            memory: memory.clone(),
            retained_memory: memory.try_reserve(MemoryClass::Executor, 0)?,
        })
    }

    fn append_file_archive(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        archive: &l2_workbench::artifact::zip::ZipArtifactReport,
    ) -> Result<(), Box<dyn Error>> {
        let range = l2_workbench::artifact::FileRange {
            offset: 0,
            length: archive.archive_size,
        };
        let node_id =
            self.append_file_node(source_index, artifact_index, source, source_sha256, range)?;
        super::analysis_memory::grow_vec(&mut self.file_artifacts, &mut self.retained_memory, 1)?;
        self.file_artifacts.push(FileArtifact::zip(
            node_id,
            source_index,
            artifact_index,
            archive.archive_size,
            &archive.archive_sha256,
            archive.entry_count,
            &self.memory,
        )?);
        Ok(())
    }

    pub(super) fn append_stream_archive(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        archive: &l2_workbench::artifact::zip::ZipArtifactReport,
        derived: DerivedArtifact,
    ) -> Result<(), Box<dyn Error>> {
        let node_id = self.append_stream_node(
            source_index,
            artifact_index,
            source,
            source_sha256,
            &derived.file.steps,
        )?;
        super::analysis_memory::grow_vec(&mut self.file_artifacts, &mut self.retained_memory, 1)?;
        self.file_artifacts.push(FileArtifact::derived_zip(
            node_id,
            source_index,
            artifact_index,
            archive,
            source.length(),
            derived,
        )?);
        Ok(())
    }

    pub(super) fn append_stream_png(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        boundary: l2_workbench::artifact::StreamPngBoundary,
        derived: DerivedArtifact,
    ) -> Result<(), Box<dyn Error>> {
        let node_id = self.append_stream_node(
            source_index,
            artifact_index,
            source,
            source_sha256,
            &derived.file.steps,
        )?;
        super::analysis_memory::grow_vec(&mut self.file_artifacts, &mut self.retained_memory, 1)?;
        self.file_artifacts.push(FileArtifact::derived_png(
            node_id,
            source_index,
            artifact_index,
            boundary,
            source.length(),
            derived,
        )?);
        Ok(())
    }

    pub(super) fn append_stream_ranges(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        artifact: &l2_workbench::artifact::AnalyzedArtifact,
        derived: DerivedArtifact,
    ) -> Result<(), Box<dyn Error>> {
        let node_id = self.append_stream_node(
            source_index,
            artifact_index,
            source,
            source_sha256,
            &derived.file.steps,
        )?;
        let file = FileArtifact::derived_ranges(
            node_id,
            source_index,
            artifact_index,
            source.length(),
            artifact,
            derived,
        )?;
        super::analysis_memory::grow_vec(&mut self.file_artifacts, &mut self.retained_memory, 1)?;
        self.file_artifacts.push(file);
        Ok(())
    }

    fn append_stream_node(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        steps: &[l2_workbench::derivation::StreamReceipt],
    ) -> Result<u64, Box<dyn Error>> {
        let length = u64::try_from(source.length())?;
        let source_id = self.case.add_source(
            &format!("refine-source-{source_index}"),
            "file",
            length,
            source_sha256,
            None,
        )?;
        let node_id = self.case.add_node(
            "stream_transformation_artifact",
            None,
            vec![SourceRange {
                source: source_id,
                packet: None,
                offset: 0,
                length,
            }],
            json!({"source_index":source_index,"artifact_index":artifact_index,"steps": steps}),
        )?;
        Ok(node_id)
    }

    fn append_file_png(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        source_sha256: &str,
        boundary: super::input::AdmittedPngBoundary,
    ) -> Result<(), Box<dyn Error>> {
        let node_id = self.append_file_node(
            source_index,
            artifact_index,
            source,
            source_sha256,
            boundary.boundary.range,
        )?;
        super::analysis_memory::grow_vec(&mut self.file_artifacts, &mut self.retained_memory, 1)?;
        self.file_artifacts.push(FileArtifact::png(
            node_id,
            source_index,
            artifact_index,
            boundary,
        )?);
        Ok(())
    }

    fn append_file_node(
        &mut self,
        source_index: usize,
        artifact_index: usize,
        source: &LoadedSource,
        sha256: &str,
        range: l2_workbench::artifact::FileRange,
    ) -> Result<u64, Box<dyn Error>> {
        let length = u64::try_from(source.length())?;
        let source_id = self.case.add_source(
            &format!("refine-source-{source_index}"),
            "file",
            length,
            sha256,
            None,
        )?;
        let node_id = self.case.add_node(
            "file_range_artifact",
            None,
            vec![SourceRange {
                source: source_id,
                packet: None,
                offset: u64::try_from(range.offset)?,
                length: u64::try_from(range.length)?,
            }],
            json!({"source_index":source_index,"artifact_index":artifact_index}),
        )?;
        Ok(node_id)
    }

    pub(super) fn analyzer_validation_receipts(
        &self,
    ) -> Result<AnalyzerValidationReceipts<'_>, Box<dyn Error>> {
        let mut memory = self.memory.try_reserve(MemoryClass::Publication, 0)?;
        let mut receipts = Vec::new();
        // append_artifacts adds each node's origins together in increasing node order
        for group in self
            .artifact_records
            .chunk_by(|left, right| left.node_id == right.node_id)
        {
            let Some(artifact) = group
                .iter()
                .find(|artifact| artifact.validation.state == ArtifactValidationState::Validated)
            else {
                continue;
            };
            super::analysis_memory::grow_vec(&mut receipts, &mut memory, 1)?;
            receipts.push(AnalyzerValidationReceipt::new(
                artifact.node_id,
                &artifact.sha256,
                artifact.byte_length,
                artifact.validation,
            ));
        }
        Ok(AnalyzerValidationReceipts {
            receipts,
            _memory: memory,
        })
    }

    fn append_skipped_source(
        &mut self,
        source: &LoadedSource,
        omission: ReadOmission,
        memory: &MemoryBudget,
    ) -> Result<(), Box<dyn Error>> {
        let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
        let mut omissions = Vec::new();
        super::analysis_memory::reserve_omission(&mut omissions, &mut lease)?;
        omissions.push(l2_workbench::artifact::AnalysisOmission::SourceReadLimit {
            length: u64::try_from(omission.length)?,
            required: omission.required,
            remaining: omission.remaining,
            maximum: omission.maximum,
        });
        let label = super::analysis_memory::copy_message(&source.label, &mut lease)?;
        let reason = super::analysis_memory::copy_message(
            "source read limit prevented analysis",
            &mut lease,
        )?;
        self.complete = false;
        self.source_records.push(SourceRecord {
            label,
            sha256: None,
            byte_length: omission.length,
            status: AnalysisStatus::Partial,
            omissions,
            work_bytes_charged: None,
            zip_expanded_work_bytes_charged: None,
            reason: Some(reason),
            _omission_memory: lease,
        });
        Ok(())
    }

    fn append_source(
        &mut self,
        source_index: usize,
        source: &LoadedSource,
        mut source_report: SourceReport,
        memory: &MemoryBudget,
    ) -> Result<(), Box<dyn Error>> {
        self.append_artifacts(source_index, &mut source_report)?;
        let report = &source_report.report;
        if source_report.omission_memory.is_none() {
            let bytes = u64::try_from(super::analysis_memory::omissions_owned_bytes(
                &report.omissions,
            )?)?;
            let lease = if let Some(report_memory) = &mut source_report._report_memory {
                report_memory
                    .split_off(bytes)
                    .ok_or("omission charge is missing from the report")?
            } else {
                let mut lease = memory.try_reserve(MemoryClass::Executor, 0)?;
                super::analysis_memory::charge_existing_omissions(&report.omissions, &mut lease)?;
                lease
            };
            source_report.omission_memory = Some(lease);
        }
        let omission_memory = source_report
            .omission_memory
            .as_mut()
            .ok_or("source omission memory is missing")?;
        let label = super::analysis_memory::copy_message(&source.label, omission_memory)?;
        let sha256 = super::analysis_memory::copy_message(&report.source_sha256, omission_memory)?;
        // The fixed scratch bound covers the short formatted reason during construction
        let reason_scratch = memory.try_reserve(MemoryClass::Executor, 1024)?;
        let reason = analysis_reason(report);
        if let Some(reason) = &reason {
            super::analysis_memory::charge(omission_memory, reason.capacity())?;
        }
        drop(reason_scratch);
        self.complete &= report.status == AnalysisStatus::Complete;
        let retained = super::analysis_memory::omissions_owned_bytes(&report.omissions)?
            .checked_add(label.capacity())
            .and_then(|bytes| bytes.checked_add(sha256.capacity()))
            .and_then(|bytes| bytes.checked_add(reason.as_ref().map_or(0, String::capacity)))
            .ok_or("source record memory overflows")?;
        let omission_memory = source_report
            .omission_memory
            .take()
            .ok_or("source omission memory is missing")?;
        self.source_records.push(SourceRecord {
            label,
            sha256: Some(sha256),
            byte_length: report.source_length,
            status: report.status,
            work_bytes_charged: Some(report.work_bytes),
            zip_expanded_work_bytes_charged: Some(report.zip_expanded_work_bytes),
            omissions: std::mem::take(&mut source_report.report.omissions),
            reason,
            _omission_memory: omission_memory,
        });
        // The report's buffers are gone before returning unused child-analysis credit
        drop(source_report);
        let record = self
            .source_records
            .last_mut()
            .ok_or("source record is missing")?;
        if record._omission_memory.bytes() < u64::try_from(retained)? {
            return Err("source record memory charge is incomplete".into());
        }
        record
            ._omission_memory
            .try_resize(u64::try_from(retained)?)?;
        Ok(())
    }

    fn append_artifacts(
        &mut self,
        source_index: usize,
        source_report: &mut SourceReport,
    ) -> Result<(), Box<dyn Error>> {
        let protected = u64::try_from(super::analysis_memory::omissions_owned_bytes(
            &source_report.report.omissions,
        )?)?;
        let artifacts = std::mem::take(&mut source_report.report.artifacts);
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
        super::analysis_memory::grow_vec(
            &mut self.artifact_records,
            &mut self.retained_memory,
            origin_count,
        )?;
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
            let origin_total = artifact.origins.len();
            let mut digest = Some(artifact.sha256);
            for (index, origin) in artifact.origins.into_iter().enumerate() {
                let mut transferred = origin
                    .owned_heap_bytes()
                    .ok_or("artifact origin size overflows")?;
                let sha256 = if index + 1 == origin_total {
                    let value = digest.take().ok_or("artifact digest is missing")?;
                    transferred = transferred
                        .checked_add(value.capacity())
                        .ok_or("artifact metadata size overflows")?;
                    value
                } else {
                    super::analysis_memory::copy_message(
                        digest.as_deref().ok_or("artifact digest is missing")?,
                        &mut self.retained_memory,
                    )?
                };
                transfer_report_memory(
                    source_report,
                    &mut self.retained_memory,
                    transferred,
                    protected,
                )?;
                self.artifact_records.push(ArtifactRecord {
                    node_id,
                    source_index,
                    artifact_index: artifact.index,
                    origin,
                    sha256,
                    byte_length: artifact.bytes.len(),
                    validation: artifact.validation,
                    signature_match_count: artifact.signature_match_count,
                });
            }
        }
        Ok(())
    }
}

fn transfer_report_memory(
    report: &mut SourceReport,
    target: &mut MemoryLease,
    bytes: usize,
    protected: u64,
) -> Result<(), Box<dyn Error>> {
    let mut remaining = u64::try_from(bytes)?;
    let omissions_separate = report.omission_memory.is_some();
    if let Some(source) = &mut report._report_memory {
        let keep = if omissions_separate { 0 } else { protected };
        remaining -= transfer_lease(source, target, remaining, keep)?;
    }
    if let Some(source) = &mut report.omission_memory {
        remaining -= transfer_lease(source, target, remaining, protected)?;
    }
    if remaining != 0 {
        return Err("artifact metadata charge is missing from the report".into());
    }
    Ok(())
}

fn transfer_lease(
    source: &mut MemoryLease,
    target: &mut MemoryLease,
    requested: u64,
    keep: u64,
) -> Result<u64, Box<dyn Error>> {
    let available = source
        .bytes()
        .checked_sub(keep)
        .ok_or("report omission charge is incomplete")?;
    let amount = available.min(requested);
    let part = source
        .split_off(amount)
        .ok_or("report metadata charge is missing")?;
    if let Err(part) = target.try_absorb(part) {
        source
            .try_absorb(part)
            .map_err(|_| "split charge could not be restored")?;
        return Err("report metadata memory scope differs from its owner".into());
    }
    Ok(amount)
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
            "range analysis searches for embedded PNG and ZIP objects; objects up to {max_object_bytes} bytes fit across windows, subject to budgets; ZIP end observation is subject to work and candidate limits; {uncovered_bytes} source bytes lacked complete range coverage, {omitted_candidates} candidates and {signature_scans_omitted} signature scans were omitted; streaming whole-source transforms cover only selected encodings and compression; see artifact validation and member omissions for structural and expansion results"
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
    memory: &MemoryBudget,
) -> Result<(l2_workbench::artifact::ArtifactAnalysis, MemoryLease), Box<dyn Error>> {
    let bytes = source.bytes().ok_or_else(|| {
        invalid_input("file-backed source cannot use the in-memory analysis cache")
    })?;
    let digest = source
        .digest()
        .ok_or_else(|| invalid_input("memory source digest is missing"))?;
    let mut report_memory = memory.try_reserve(MemoryClass::Executor, 0)?;
    let Some(cache) = cache else {
        let report =
            analyze_artifacts_with_memory(bytes, Some(digest), options, &mut report_memory)?;
        record_analysis_work(job, &report)?;
        return Ok((report, report_memory));
    };

    let key = analysis_cache_key(digest, options, recovery.profile)?;

    if !recovery.refresh {
        match cache.lookup(&key, CacheReadPolicy::AllowPartial) {
            Ok(Some(entry)) => {
                match load_cached_analysis(&entry, source, options, memory, &mut report_memory) {
                    Ok(report) => {
                        job.increment(Counter::CacheHits, 1)?;
                        return Ok((report, report_memory));
                    }
                    Err(error)
                        if recovery.strict_cache
                            || crate::memory_error::find(error.as_ref()).is_some() =>
                    {
                        return Err(error);
                    }
                    Err(_) => {
                        // The rejected receipt and every partially restored blob are gone
                        report_memory.try_resize(0)?;
                        note_cache_fallback(
                            job,
                            CacheFallbackKind::InvalidEntry,
                            format_args!("cached file analysis was rejected"),
                        )?;
                    }
                }
            }
            Ok(None) => {}
            Err(error) if recovery.strict_cache || crate::memory_error::find(&error).is_some() => {
                return Err(error.into());
            }
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
        Err(error) if recovery.strict_cache || crate::memory_error::find(&error).is_some() => {
            return Err(error.into());
        }
        Err(_) => {
            note_cache_fallback(
                job,
                CacheFallbackKind::LeaseUnavailable,
                format_args!("file analysis cache write lease unavailable"),
            )?;
            None
        }
    };

    let report = analyze_artifacts_with_memory(bytes, Some(digest), options, &mut report_memory)?;
    record_analysis_work(job, &report)?;
    if let Some(lease) = lease
        && let Err(error) = store_cached_analysis(lease, &report, memory)
    {
        if recovery.strict_cache || crate::memory_error::find(error.as_ref()).is_some() {
            return Err(error);
        }
        note_cache_fallback(
            job,
            CacheFallbackKind::CommitFailed,
            format_args!("file analysis cache commit failed"),
        )?;
    }
    Ok((report, report_memory))
}

fn analysis_cache_key(
    digest: &str,
    options: ArtifactAnalysisOptions,
    profile: RecoveryProfile,
) -> Result<StageKey, Box<dyn Error>> {
    let identity = SourceIdentity::from_sha256(digest.to_owned())?;
    let policy = json!({
        "schema_version": CACHE_ANALYSIS_SCHEMA_VERSION,
        "transform_proposal_format_version": TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "analyzer": options,
        "profile": recovery_profile_name(profile),
    });
    Ok(StageKey::new(
        "file_artifact_analysis",
        CACHE_ANALYSIS_SCHEMA_VERSION,
        format!("l2_artifact_analyzer_v{REFINE_ANALYZER_ALGORITHM_VERSION}"),
        &policy,
        &identity,
        &[],
    )?)
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
    memory: &MemoryBudget,
) -> Result<(), Box<dyn Error>> {
    let directory = lease.directory();
    let _scratch = memory.try_reserve(MemoryClass::Executor, 4096)?;
    let mut lengths_memory = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut artifact_lengths = Vec::new();
    super::analysis_memory::grow_vec_exact(
        &mut artifact_lengths,
        &mut lengths_memory,
        report.artifacts.len(),
    )?;
    artifact_lengths.extend(report.artifacts.iter().map(|artifact| artifact.bytes.len()));
    let receipt = CacheAnalysisReceiptRef {
        schema_version: CACHE_ANALYSIS_SCHEMA_VERSION,
        artifact_lengths,
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
    memory: &MemoryBudget,
    report_memory: &mut MemoryLease,
) -> Result<l2_workbench::artifact::ArtifactAnalysis, Box<dyn Error>> {
    let receipt = read_cache_receipt(entry, source, options, memory, report_memory)?;
    let mut report = receipt.analysis;
    restore_cached_artifact_bytes(
        entry,
        &mut report,
        receipt.artifact_lengths,
        options.limits.max_total_output_bytes,
        report_memory,
    )?;
    validate_cached_lineage(&report)?;
    validate_cached_source_artifact(&report, source)?;
    Ok(report)
}

fn read_cache_receipt(
    entry: &CacheEntry,
    source: &LoadedSource,
    options: ArtifactAnalysisOptions,
    memory: &MemoryBudget,
    report_memory: &mut MemoryLease,
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
    let before = report_memory.bytes();
    let (receipt_bytes, receipt_sha256) = super::input::read_snapshot_with_memory(
        crate::input::regular_no_follow(&receipt_path)?,
        MAX_CACHE_RECEIPT_BYTES,
        None,
        None,
        report_memory,
    )?;
    let read_charge = report_memory.bytes() - before;
    let admission = l2_workbench::job::admit_json(&receipt_bytes, memory, MemoryClass::Executor)?;
    let receipt: CacheAnalysisReceipt = serde_json::from_slice(&receipt_bytes)?;
    let retained = admission.into_retained();
    if let Err(retained) = report_memory.try_absorb(retained) {
        drop(receipt);
        drop(retained);
        return Err("cache JSON memory scope differs from its report".into());
    }
    drop(receipt_bytes);
    drop(receipt_sha256);
    let remaining = report_memory
        .bytes()
        .checked_sub(read_charge)
        .ok_or("cache receipt memory charge is inconsistent")?;
    report_memory.try_resize(remaining)?;
    if receipt.schema_version != CACHE_ANALYSIS_SCHEMA_VERSION
        || metadata
            .get("artifact_count")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::try_from(receipt.analysis.artifacts.len())?)
        || receipt.artifact_lengths.len() != receipt.analysis.artifacts.len()
        || Some(receipt.analysis.source_sha256.as_str()) != source.digest()
        || receipt.analysis.source_length != source.length()
        || receipt.analysis.artifacts.len() > options.limits.max_artifacts
        || receipt.analysis.work_bytes > options.limits.max_total_work_bytes
        || receipt.analysis.zip_expanded_work_bytes > options.limits.max_zip_expanded_bytes
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
    report_memory: &mut MemoryLease,
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
        let before = report_memory.bytes();
        let (bytes, digest) = super::input::read_snapshot_with_memory(
            crate::input::regular_no_follow(&artifact_path)?,
            expected_length,
            Some(expected_length),
            Some(&artifact.sha256),
            report_memory,
        )?;
        if digest != artifact.sha256 {
            return Err(invalid_cache_entry(
                "file analysis artifact hash is invalid",
            ));
        }
        let retained = before
            .checked_add(u64::try_from(bytes.capacity())?)
            .ok_or("cached artifact memory overflows")?;
        drop(digest);
        report_memory.try_resize(retained)?;
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
