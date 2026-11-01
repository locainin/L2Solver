//! Secure bounded source admission for standalone files and artifact manifests

#[cfg(test)]
#[path = "../../tests/refine/input_memory.rs"]
mod tests;

use super::{
    invalid_input,
    read_budget::{SourceReadBudget, analysis_reservation},
};
use crate::safe_filename::is_safe_flat_file_name;
use l2_workbench::{
    job::{
        Counter, Job, MemoryBudget, MemoryClass, MemoryError, MemoryLease,
        cache::{SourceFingerprint, SourceIdentity},
    },
    sha256,
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::HashSet,
    error::Error,
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_ARTIFACTS: usize = 4_096;

#[cfg(target_os = "linux")]
struct DirectoryAnchor {
    descriptor: rustix::fd::OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
}

pub(super) struct InputSet {
    sources: Vec<InputSpec>,
    plans: Vec<SourcePlan>,
    budget: SourceReadBudget,
    extra_read_bytes: Cell<u64>,
    publication_recheck_held: Cell<bool>,
    manifest_read_bytes: u64,
    manifest_sha256: Option<String>,
    memory: MemoryBudget,
    #[cfg(target_os = "linux")]
    directory: Option<DirectoryAnchor>,
    #[cfg(not(target_os = "linux"))]
    directory: Option<PathBuf>,
    _metadata_memory: MemoryLease,
}

struct SourcePlan {
    length: usize,
    metadata: MetadataFingerprint,
    omission: Option<ReadOmission>,
}

impl InputSet {
    pub(super) const fn extra_read_bytes(&self) -> u64 {
        self.extra_read_bytes.get()
    }

    fn hold_extra_reads(&self, bytes: u64) -> bool {
        let Some(remaining) = self.extra_read_bytes.get().checked_sub(bytes) else {
            return false;
        };
        self.extra_read_bytes.set(remaining);
        true
    }

    pub(super) fn reserve_extra_reads(&self, bytes: u64) -> Result<bool, Box<dyn Error>> {
        if !self.hold_extra_reads(bytes) {
            return Ok(false);
        }
        self.budget.reserve(bytes)?;
        Ok(true)
    }

    fn publication_recheck_bytes(&self) -> Result<u64, Box<dyn Error>> {
        let samples = self
            .plans
            .iter()
            .filter(|plan| plan.omission.is_none())
            .try_fold(0_u64, |sum, plan| {
                sum.checked_add(SourceFingerprint::sample_read_bytes(
                    u64::try_from(plan.length).ok()?,
                ))
            })
            .ok_or_else(|| invalid_input("publication source recheck size overflows"))?;
        samples
            .checked_add(self.manifest_read_bytes)
            .ok_or_else(|| invalid_input("publication source recheck size overflows"))
    }

    fn reserve_source_output(&self, bytes: u64) -> Result<bool, Box<dyn Error>> {
        let recheck = if self.publication_recheck_held.get() {
            0
        } else {
            self.publication_recheck_bytes()?
        };
        let required = bytes
            .checked_add(recheck)
            .ok_or_else(|| invalid_input("source output read reservation overflows"))?;
        if required > self.extra_read_bytes() {
            return Ok(false);
        }
        if recheck > 0 {
            self.hold_extra_reads(recheck);
            self.publication_recheck_held.set(true);
        }
        self.reserve_extra_reads(bytes)
    }

    pub(super) fn write_file_artifact(
        &self,
        artifact: &super::file_artifact::FileArtifact,
        staging: &Path,
        job: &Job,
        buffer: &mut [u8],
    ) -> Result<(), Box<dyn Error>> {
        use super::file_artifact::FileBacking;
        if !is_safe_flat_file_name(&artifact.file_name) {
            return Err(invalid_input("artifact output name is unsafe"));
        }
        let spec = self
            .sources
            .get(artifact.source_index)
            .ok_or_else(|| invalid_input("artifact source index is missing"))?;
        let plan = self
            .plans
            .get(artifact.source_index)
            .ok_or_else(|| invalid_input("artifact source plan is missing"))?;
        let end = artifact
            .range
            .offset
            .checked_add(artifact.range.length)
            .ok_or_else(|| invalid_input("artifact range overflows"))?;
        if matches!(&artifact.backing, FileBacking::Source) && end > plan.length {
            return Err(invalid_input("artifact range exceeds its source"));
        }
        let source = open_identity_source(self, spec)?;
        if metadata_fingerprint(&source.metadata()?) != plan.metadata {
            return Err(invalid_input("input artifact changed before publication"));
        }
        let mut target = File::options()
            .write(true)
            .create_new(true)
            .open(staging.join(&artifact.file_name))?;
        match &artifact.backing {
            FileBacking::Source => {
                let mut source_copy = source.try_clone()?;
                source_copy.seek(SeekFrom::Start(u64::try_from(artifact.range.offset)?))?;
                let mut reader = CancellableReader::new(source_copy, job);
                copy_verified_range(&mut reader, &mut target, artifact, buffer)?;
            }
            FileBacking::Spool(spool) => {
                let mut spool = spool.file.try_clone()?;
                spool.seek(SeekFrom::Start(u64::try_from(artifact.range.offset)?))?;
                let mut reader = PrivateReader { inner: spool, job };
                copy_verified_range(&mut reader, &mut target, artifact, buffer)?;
            }
        }
        if metadata_fingerprint(&source.metadata()?) != plan.metadata {
            return Err(invalid_input(
                "input artifact changed while it was published",
            ));
        }
        let named = open_identity_source(self, spec)?;
        if metadata_fingerprint(&named.metadata()?) != plan.metadata {
            return Err(invalid_input(
                "input artifact changed while it was published",
            ));
        }
        #[cfg(target_os = "linux")]
        if let Some(directory) = &self.directory {
            directory.check_location()?;
        }
        target.sync_all()?;
        Ok(())
    }
}

fn copy_verified_range(
    source: &mut impl Read,
    target: &mut File,
    artifact: &super::file_artifact::FileArtifact,
    buffer: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let mut digest = Sha256::new();
    let mut remaining = artifact.range.length;
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        let part = buffer
            .get_mut(..count)
            .ok_or_else(|| invalid_input("source output buffer is invalid"))?;
        source.read_exact(part)?;
        target.write_all(part)?;
        digest.update(part);
        remaining -= count;
    }
    if format!("{:x}", digest.finalize()) != artifact.sha256 {
        return Err(invalid_input("artifact changed while it was published"));
    }
    Ok(())
}

struct PrivateReader<'a> {
    inner: File,
    job: &'a Job,
}

impl Read for PrivateReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        self.inner.read(buffer)
    }
}

#[derive(Clone, Copy)]
pub(super) struct ReadOmission {
    pub(super) length: usize,
    pub(super) required: u64,
    pub(super) remaining: u64,
    pub(super) maximum: u64,
}

struct InputSpec {
    label: String,
    path: InputPath,
    expected_length: Option<usize>,
    expected_sha256: Option<String>,
}

enum InputPath {
    Direct(PathBuf),
    ManifestMember(String),
}

pub(super) struct LoadedSource {
    pub(super) label: String,
    pub(super) data: SourceData,
}

pub(super) struct LoadedSources {
    values: Vec<LoadedSource>,
    _metadata_memory: MemoryLease,
}

impl std::ops::Deref for LoadedSources {
    type Target = [LoadedSource];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

pub(super) enum SourceData {
    Memory {
        bytes: Vec<u8>,
        sha256: String,
        _memory: Option<MemoryLease>,
    },
    File(RangeSource),
    Skipped(ReadOmission),
}

pub(super) struct RangeSource {
    length: usize,
    metadata: MetadataFingerprint,
}

pub(super) struct AdmittedPngBoundary {
    pub(super) boundary: l2_workbench::artifact::StreamPngBoundary,
    // The digest must be dropped before its charge is released
    pub(super) memory: MemoryLease,
}

pub(super) struct RangeAnalysis {
    pub(super) report: l2_workbench::artifact::ArtifactAnalysis,
    pub(super) archive: Option<l2_workbench::artifact::zip::ZipArtifactReport>,
    pub(super) retain_source: bool,
    pub(super) png: Option<AdmittedPngBoundary>,
    pub(super) observation: Option<super::range_transform::Observation>,
    pub(super) report_memory: MemoryLease,
    pub(super) omission_memory: MemoryLease,
    pub(super) source_digest_memory: MemoryLease,
}

impl LoadedSource {
    pub(super) fn with_range_reader<T>(
        &self,
        input_set: &InputSet,
        source_index: usize,
        job: &Job,
        action: impl FnOnce(&mut CancellableReader<'_, File>) -> T,
    ) -> Result<Option<T>, Box<dyn Error>> {
        let SourceData::File(source) = &self.data else {
            return Err(invalid_input("source is not range-backed"));
        };
        let read_bytes = u64::try_from(source.length)?
            .checked_add(1)
            .ok_or_else(|| invalid_input("source transform read length overflows"))?;
        if !input_set.reserve_extra_reads(read_bytes)? {
            return Ok(None);
        }
        let spec = input_set
            .sources
            .get(source_index)
            .ok_or_else(|| invalid_input("range source index is missing"))?;
        let file = open_identity_source(input_set, spec)?;
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed before streaming transformation",
            ));
        }
        let mut reader = CancellableReader::new(file, job);
        let result = action(&mut reader);
        let file = reader.into_inner();
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed during streaming transformation",
            ));
        }
        confirm_range_source_name(input_set, spec, source)?;
        Ok(Some(result))
    }

    pub(super) const fn length(&self) -> usize {
        match &self.data {
            SourceData::Memory { bytes, .. } => bytes.len(),
            SourceData::File(source) => source.length,
            SourceData::Skipped(omission) => omission.length,
        }
    }

    pub(super) fn bytes(&self) -> Option<&[u8]> {
        match &self.data {
            SourceData::Memory { bytes, .. } => Some(bytes),
            SourceData::File(_) | SourceData::Skipped(_) => None,
        }
    }

    pub(super) fn digest(&self) -> Option<&str> {
        match &self.data {
            SourceData::Memory { sha256, .. } => Some(sha256),
            SourceData::File(_) | SourceData::Skipped(_) => None,
        }
    }

    pub(super) fn analyze_ranges(
        &self,
        input_set: &InputSet,
        source_index: usize,
        mut options: l2_workbench::artifact::ArtifactAnalysisOptions,
        job: &Job,
        memory: &MemoryBudget,
        observe_transforms: bool,
    ) -> Result<RangeAnalysis, Box<dyn Error>> {
        let SourceData::File(source) = &self.data else {
            return Err(invalid_input("source is not range-backed"));
        };
        let spec = input_set
            .sources
            .get(source_index)
            .ok_or_else(|| invalid_input("range source index is missing"))?;
        let mut file = open_range_source(input_set, spec, source)?;
        let complete_work_limit = options.limits.max_total_work_bytes;
        let tail = probe_source_tail(
            &mut file,
            source.length,
            &mut options,
            input_set,
            job,
            memory,
        )?;
        file.seek(SeekFrom::Start(0))?;
        input_set.budget.reserve(
            u64::try_from(source.length)?
                .checked_add(1)
                .ok_or_else(|| invalid_input("source read length overflows"))?,
        )?;
        let mut reader = CancellableReader::new(file, job);
        let checkpoint = tail
            .candidate
            .as_ref()
            .and_then(|candidate| (candidate.length < source.length).then_some(candidate.length));
        let ScannedSource {
            mut report_memory,
            mut omission_memory,
            scanned,
            observation,
            mut png,
            source_digest_memory,
            probe,
        } = analyze_source_stream(
            &mut reader,
            source.length,
            options,
            checkpoint,
            memory,
            observe_transforms,
        )?;
        let mut report = scanned.analysis;
        record_tail_work(
            &mut report,
            &mut omission_memory,
            tail.work_bytes,
            tail.omission,
        )?;
        options.limits.max_total_work_bytes = complete_work_limit;
        let mut file = reader.into_inner();
        confirm_range_content(&file, source, spec, &report.source_sha256)?;
        let (archive, retain_source) = inspect_source_archive(
            &mut file,
            ObservedArchiveEnds {
                tail: tail.candidate,
                probe,
            },
            &mut report,
            options,
            input_set,
            job,
            (&mut report_memory, &mut omission_memory),
        )?;
        png = retain_png_range(png, &mut report, input_set, &mut omission_memory)?;
        confirm_range_source_after_analysis(&file, input_set, spec, source)?;
        Ok(RangeAnalysis {
            report,
            archive,
            retain_source,
            png,
            observation,
            report_memory,
            omission_memory,
            source_digest_memory,
        })
    }
}

fn open_range_source(
    input: &InputSet,
    spec: &InputSpec,
    source: &RangeSource,
) -> Result<File, Box<dyn Error>> {
    let file = open_identity_source(input, spec)?;
    if metadata_fingerprint(&file.metadata()?) != source.metadata {
        return Err(invalid_input(
            "input artifact changed before range analysis",
        ));
    }
    Ok(file)
}

fn confirm_range_content(
    file: &File,
    source: &RangeSource,
    spec: &InputSpec,
    sha256: &str,
) -> Result<(), Box<dyn Error>> {
    if metadata_fingerprint(&file.metadata()?) != source.metadata {
        return Err(invalid_input(
            "input artifact changed during range analysis",
        ));
    }
    if spec
        .expected_sha256
        .as_deref()
        .is_some_and(|expected| expected != sha256)
    {
        return Err(invalid_input("artifact hash does not match its manifest"));
    }
    Ok(())
}

fn confirm_range_source_after_analysis(
    file: &File,
    input: &InputSet,
    spec: &InputSpec,
    source: &RangeSource,
) -> Result<(), Box<dyn Error>> {
    if metadata_fingerprint(&file.metadata()?) != source.metadata {
        return Err(invalid_input(
            "input artifact changed during range analysis",
        ));
    }
    confirm_range_source_name(input, spec, source)
}

struct SourceTail {
    candidate: Option<super::range_zip::ZipCandidate>,
    work_bytes: usize,
    omission: Option<&'static str>,
}

fn probe_source_tail(
    file: &mut File,
    length: usize,
    options: &mut l2_workbench::artifact::ArtifactAnalysisOptions,
    input: &InputSet,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<SourceTail, Box<dyn Error>> {
    let result = super::range_zip::probe_tail(
        file,
        length,
        options.limits.max_input_bytes,
        input,
        job,
        memory,
        options.limits.max_total_work_bytes.saturating_sub(1),
    )?;
    let (candidate, work_bytes, omission) = match result {
        super::range_zip::TailProbe::Skipped => (None, 0, None),
        super::range_zip::TailProbe::ReadLimit => {
            (None, 0, Some("ZIP tail hint exceeds the source read limit"))
        }
        super::range_zip::TailProbe::WorkLimit => (
            None,
            0,
            Some("ZIP tail hint exceeds the remaining work limit"),
        ),
        super::range_zip::TailProbe::Scanned {
            candidate,
            work_bytes,
        } => {
            options.limits.max_total_work_bytes -= work_bytes;
            (candidate, work_bytes, None)
        }
    };
    Ok(SourceTail {
        candidate,
        work_bytes,
        omission,
    })
}

fn record_tail_work(
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    memory: &mut MemoryLease,
    work_bytes: usize,
    omission: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    report.work_bytes = report
        .work_bytes
        .checked_add(work_bytes)
        .ok_or("ZIP tail work overflows")?;
    if let Some(message) = omission {
        super::analysis_memory::reserve_omission(&mut report.omissions, memory)?;
        let reason = super::analysis_memory::copy_message(message, memory)?;
        report.omissions.push(
            l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit {
                format: l2_workbench::artifact::AnalysisFormat::Zip,
                reason,
            },
        );
    }
    Ok(())
}

fn retain_png_range(
    png: Option<AdmittedPngBoundary>,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    input: &InputSet,
    omission_memory: &mut MemoryLease,
) -> Result<Option<AdmittedPngBoundary>, Box<dyn Error>> {
    let Some(boundary) = png else { return Ok(None) };
    if report.artifacts.iter().any(|artifact| {
        artifact.sha256 == boundary.boundary.sha256
            && artifact.bytes.len() == boundary.boundary.range.length
    }) {
        return Ok(None);
    }
    let length = u64::try_from(boundary.boundary.range.length)?;
    if input.reserve_source_output(length)? {
        return Ok(Some(boundary));
    }
    super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
    report.omissions.push(
        l2_workbench::artifact::AnalysisOmission::SourceRangeOutputReadLimit {
            length,
            remaining: input.extra_read_bytes(),
            maximum: input.budget.maximum(),
        },
    );
    Ok(None)
}

struct ScannedSource {
    scanned: l2_workbench::artifact::StreamSourceAnalysis,
    png: Option<AdmittedPngBoundary>,
    probe: AdmittedArchiveProbe,
    observation: Option<super::range_transform::Observation>,
    report_memory: MemoryLease,
    omission_memory: MemoryLease,
    source_digest_memory: MemoryLease,
}

struct AdmittedArchiveProbe {
    prefix_sha256: Option<String>,
    stream: Option<l2_workbench::artifact::ZipEndObservation>,
    // Keep the source buffers alive until their accounting is released
    memory: MemoryLease,
}

fn analyze_source_stream(
    reader: &mut impl Read,
    length: usize,
    options: l2_workbench::artifact::ArtifactAnalysisOptions,
    checkpoint: Option<usize>,
    memory: &MemoryBudget,
    observe_transforms: bool,
) -> Result<ScannedSource, Box<dyn Error>> {
    let mut signature = [0_u8; l2_workbench::artifact::PNG_SIGNATURE.len()];
    let count = length.min(signature.len());
    let prefix = signature
        .get_mut(..count)
        .ok_or_else(|| invalid_input("source prefix length is invalid"))?;
    reader.read_exact(prefix)?;
    // Feed the already-read prefix to the analyzer without reopening the source
    let is_png = count == signature.len() && signature == l2_workbench::artifact::PNG_SIGNATURE;
    let (mut scratch, mut retained) =
        super::analysis_memory::reserve(memory, length, options, is_png)?;
    let mut omissions = memory.try_reserve(MemoryClass::Executor, 0)?;
    let prefix = signature
        .get(..count)
        .ok_or_else(|| invalid_input("source prefix length is invalid"))?;
    let complete = io::Cursor::new(prefix).chain(reader);
    let mut complete = super::range_transform::ObservingReader::new(complete, observe_transforms);
    let mut stream_options = options;
    // Leave work for canonical ZIP validation after observing source markers
    let total_work = options.limits.max_total_work_bytes;
    let zip_work = if total_work >= 1024 * 1024 {
        (total_work / 8).min(16 * 1024 * 1024)
    } else {
        0
    };
    stream_options.limits.max_total_work_bytes -= zip_work;
    let remaining = if is_png && length < stream_options.limits.max_total_work_bytes {
        stream_options.limits.max_total_work_bytes - length
    } else {
        stream_options.limits.max_total_work_bytes
    };
    let marker_work = if length <= remaining / 2 {
        length
    } else {
        remaining / 16
    };
    let limits = l2_workbench::artifact::ZipEndScanLimits {
        max_scan_bytes: length.min(marker_work),
        max_candidates: (options.limits.max_input_bytes / 256).min(64),
    };
    let mut png_metadata = memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut result = l2_workbench::artifact::analyze_artifacts_observing_zip_ends(
        &mut complete,
        length,
        stream_options,
        checkpoint,
        is_png,
        limits,
        Some(l2_workbench::artifact::StreamMemory {
            png_metadata: &mut png_metadata,
            report: &mut retained,
        }),
    )
    .map_err(stream_error)?;
    // Scanner scratch covers these records until their retained lease is charged
    super::analysis_memory::charge_existing_omissions(&result.analysis.omissions, &mut omissions)?;
    let source_bytes = u64::try_from(result.analysis.source_sha256.capacity())?;
    let png_bytes = u64::try_from(result.png.as_ref().map_or(0, |png| png.sha256.capacity()))?;
    let probe_bytes = u64::try_from(scanner_probe_bytes(&result)?)?;
    let total = source_bytes
        .checked_add(png_bytes)
        .and_then(|bytes| bytes.checked_add(probe_bytes))
        .ok_or("scanner output charge overflows")?;
    // Split the existing workspace charge while every returned buffer is still alive
    let Some(mut outputs) = scratch.split_off(total) else {
        return Err("scanner output charge is missing".into());
    };
    let Some(source_digest_memory) = outputs.split_off(source_bytes) else {
        drop(result);
        drop(outputs);
        return Err("scanner source digest charge is missing".into());
    };
    let Some(png_memory) = outputs.split_off(png_bytes) else {
        drop(result);
        drop(source_digest_memory);
        drop(outputs);
        return Err("scanner PNG digest charge is missing".into());
    };
    let png = match result.png.take() {
        Some(boundary) => Some(AdmittedPngBoundary {
            boundary,
            memory: png_memory,
        }),
        None => {
            drop(png_memory);
            None
        }
    };
    let probe = AdmittedArchiveProbe {
        prefix_sha256: result.prefix_sha256.take(),
        stream: result.zip_observation.take(),
        memory: outputs,
    };
    drop(scratch);
    Ok(ScannedSource {
        scanned: result,
        png,
        probe,
        observation: complete.finish(),
        report_memory: retained,
        omission_memory: omissions,
        source_digest_memory,
    })
}

fn scanner_probe_bytes(
    result: &l2_workbench::artifact::StreamSourceAnalysis,
) -> Result<usize, Box<dyn Error>> {
    let mut bytes = result.prefix_sha256.as_ref().map_or(0, String::capacity);
    if let Some(observation) = &result.zip_observation {
        let candidates = observation
            .candidates
            .capacity()
            .checked_mul(std::mem::size_of::<l2_workbench::artifact::StreamZipEnd>())
            .ok_or("ZIP observation size overflows")?;
        bytes = bytes
            .checked_add(candidates)
            .ok_or("ZIP observation size overflows")?;
        for candidate in &observation.candidates {
            bytes = bytes
                .checked_add(candidate.sha256.capacity())
                .ok_or("ZIP observation size overflows")?;
        }
    }
    Ok(bytes)
}

pub(super) fn stream_error(error: io::Error) -> Box<dyn Error> {
    if let Some(memory) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<MemoryError>())
    {
        Box::new(*memory)
    } else {
        Box::new(error)
    }
}

fn confirm_range_source_name(
    input: &InputSet,
    spec: &InputSpec,
    source: &RangeSource,
) -> Result<(), Box<dyn Error>> {
    // Confirm the name still resolves to the same opened object
    let named = open_identity_source(input, spec)?;
    if metadata_fingerprint(&named.metadata()?) != source.metadata {
        return Err(invalid_input(
            "input artifact changed during range analysis",
        ));
    }
    #[cfg(target_os = "linux")]
    if let Some(directory) = &input.directory {
        directory.check_location()?;
    }
    Ok(())
}

struct ObservedArchiveEnds {
    tail: Option<super::range_zip::ZipCandidate>,
    probe: AdmittedArchiveProbe,
}

fn inspect_source_archive(
    file: &mut File,
    mut ends: ObservedArchiveEnds,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    options: l2_workbench::artifact::ArtifactAnalysisOptions,
    input: &InputSet,
    job: &Job,
    memory: (&mut MemoryLease, &mut MemoryLease),
) -> Result<(Option<l2_workbench::artifact::zip::ZipArtifactReport>, bool), Box<dyn Error>> {
    let (memory, omission_memory) = memory;
    let candidates = source_zip_candidates(&mut ends, report, omission_memory)?;
    for candidate in candidates {
        let Some(archive) = super::range_zip::inspect(
            file,
            candidate.end,
            &candidate.sha256,
            report,
            options,
            input,
            job,
            memory,
            omission_memory,
        )?
        else {
            continue;
        };
        let length = u64::try_from(candidate.end)?;
        let retain = input.reserve_source_output(length)?;
        if !retain {
            super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
            report.omissions.push(
                l2_workbench::artifact::AnalysisOmission::SourceRangeOutputReadLimit {
                    length,
                    remaining: input.extra_read_bytes(),
                    maximum: input.budget.maximum(),
                },
            );
        }
        return Ok((Some(archive), retain));
    }
    Ok((None, false))
}

fn source_zip_candidates(
    ends: &mut ObservedArchiveEnds,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    omission_memory: &mut MemoryLease,
) -> Result<Vec<l2_workbench::artifact::StreamZipEnd>, Box<dyn Error>> {
    let mut candidates = if let Some(observation) = ends.probe.stream.take() {
        if observation.unscanned_bytes > 0 || observation.omitted_candidates > 0 {
            super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
            let reason = super::analysis_memory::format_message(
                format_args!(
                    "ZIP end observation left {} bytes unscanned and omitted {} candidates",
                    observation.unscanned_bytes, observation.omitted_candidates
                ),
                omission_memory,
            )?;
            report.omissions.push(
                l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit {
                    format: l2_workbench::artifact::AnalysisFormat::Zip,
                    reason,
                },
            );
        }
        observation.candidates
    } else {
        Vec::new()
    };
    let mut multiple = false;
    if let Some(tail) = ends.tail.take() {
        multiple = tail.multiple_boundaries;
        if !candidates
            .iter()
            .any(|candidate| candidate.end == tail.length)
        {
            let sha256 = if tail.length == report.source_length {
                super::analysis_memory::copy_message(&report.source_sha256, &mut ends.probe.memory)?
            } else {
                ends.probe
                    .prefix_sha256
                    .take()
                    .ok_or_else(|| invalid_input("ZIP boundary digest is missing"))?
            };
            super::analysis_memory::grow_vec_exact(&mut candidates, &mut ends.probe.memory, 1)?;
            candidates.push(l2_workbench::artifact::StreamZipEnd {
                end: tail.length,
                sha256,
            });
        }
    }
    if multiple || candidates.len() > 1 {
        super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
        let reason = super::analysis_memory::copy_message(
            "multiple ZIP end boundaries were found; candidates were checked until one validated",
            omission_memory,
        )?;
        report.omissions.push(
            l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit {
                format: l2_workbench::artifact::AnalysisFormat::Zip,
                reason,
            },
        );
    }
    candidates.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.end));
    Ok(candidates)
}

pub(super) struct CancellableReader<'a, R> {
    inner: R,
    job: &'a Job,
}

impl<'a, R> CancellableReader<'a, R> {
    pub(super) const fn new(inner: R, job: &'a Job) -> Self {
        Self { inner, job }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CancellableReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        const MAX_READ_BYTES: usize = 64 * 1024;
        self.job.check_cancelled().map_err(io::Error::other)?;
        let length = buffer.len().min(MAX_READ_BYTES);
        let part = buffer
            .get_mut(..length)
            .ok_or_else(|| io::Error::other("input read buffer is invalid"))?;
        let count = self.inner.read(part)?;
        record_source_read(self.job, count)?;
        Ok(count)
    }
}

impl<R: Seek> Seek for CancellableReader<'_, R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.job.check_cancelled().map_err(io::Error::other)?;
        self.inner.seek(position)
    }
}

fn record_source_read(job: &Job, count: usize) -> io::Result<()> {
    job.increment(
        Counter::SourceReadBytes,
        u64::try_from(count).map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)
}

impl<R: MetadataReader> MetadataReader for CancellableReader<'_, R> {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.inner.file_metadata()
    }
}

/// A bounded local hint; only the ordered full digest proves source content identity
pub(super) struct FingerprintedSources {
    pub(super) identity: SourceIdentity,
    pub(super) labels: Vec<String>,
    pub(super) total_bytes: u64,
    pub(super) sample_set_sha256: String,
    _memory: MemoryLease,
}

#[derive(Serialize)]
struct SampledSource<'a> {
    label: &'a str,
    expected_length: Option<usize>,
    expected_sha256: Option<&'a str>,
    fingerprint: Option<SourceFingerprint>,
    skipped_metadata: Option<MetadataFingerprint>,
}

#[derive(Deserialize)]
struct InputManifest {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_manifest_artifacts")]
    artifacts: Vec<InputManifestArtifact>,
}

#[derive(Deserialize)]
struct InputManifestArtifact {
    file: String,
    byte_length: usize,
    #[serde(default)]
    sha256: Option<String>,
}

fn deserialize_manifest_artifacts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<InputManifestArtifact>, D::Error> {
    struct ArtifactsVisitor;
    impl<'de> Visitor<'de> for ArtifactsVisitor {
        type Value = Vec<InputManifestArtifact>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded artifact list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut artifacts = Vec::new();
            while let Some(artifact) = sequence.next_element()? {
                if artifacts.len() >= MAX_MANIFEST_ARTIFACTS {
                    return Err(de::Error::custom(
                        "artifact manifest entry count exceeds the limit",
                    ));
                }
                artifacts.try_reserve(1).map_err(de::Error::custom)?;
                artifacts.push(artifact);
            }
            Ok(artifacts)
        }
    }
    deserializer.deserialize_seq(ArtifactsVisitor)
}

#[cfg(test)]
pub(super) fn prepare_input_set(path: &Path) -> Result<InputSet, Box<dyn Error>> {
    prepare_input_set_with_limit(
        path,
        u64::MAX,
        &Job::new("unlimited test input"),
        &MemoryBudget::new(u64::MAX),
    )
}

pub(super) fn prepare_input_set_with_limit(
    path: &Path,
    maximum: u64,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<InputSet, Box<dyn Error>> {
    let budget = SourceReadBudget::new(maximum);
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_input("input path must not be a symbolic link"));
    }
    if metadata.is_dir() {
        let mut input = prepare_export_directory(path, budget, job, memory)?;
        plan_sources(&mut input)?;
        return Ok(input);
    }
    if !metadata.is_file() {
        return Err(invalid_input(
            "input must be a regular file or artifact directory",
        ));
    }

    let metadata_bytes = path
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or_else(|| invalid_input("input metadata size overflows"))?;
    let metadata_memory = memory.try_reserve(MemoryClass::Base, u64::try_from(metadata_bytes)?)?;
    let label = path.file_name().map_or_else(
        || String::from("input.bin"),
        |name| name.to_string_lossy().into_owned(),
    );
    let mut input = InputSet {
        sources: vec![InputSpec {
            label,
            path: InputPath::Direct(path.to_owned()),
            expected_length: None,
            expected_sha256: None,
        }],
        manifest_sha256: None,
        memory: memory.clone(),
        _metadata_memory: metadata_memory,
        plans: Vec::new(),
        budget,
        extra_read_bytes: Cell::new(0),
        publication_recheck_held: Cell::new(false),
        manifest_read_bytes: 0,
        #[cfg(target_os = "linux")]
        directory: None,
        #[cfg(not(target_os = "linux"))]
        directory: None,
    };
    plan_sources(&mut input)?;
    Ok(input)
}

fn prepare_export_directory(
    path: &Path,
    budget: SourceReadBudget,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<InputSet, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    let directory = DirectoryAnchor::open(path)?;
    #[cfg(not(target_os = "linux"))]
    let directory = path.to_owned();

    let (manifest_bytes, manifest_sha256, metadata_memory) = read_directory_member(
        &directory,
        "manifest.json",
        MAX_MANIFEST_BYTES,
        &budget,
        job,
        memory,
    )?;
    let manifest_read_bytes = u64::try_from(manifest_bytes.len())?
        .checked_add(1)
        .ok_or_else(|| invalid_input("manifest read length overflows"))?;
    let manifest: InputManifest = serde_json::from_slice(&manifest_bytes)?;
    if !matches!(manifest.schema_version, 1 | 2) {
        return Err(invalid_input(
            "artifact manifest schema version is unsupported",
        ));
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
        return Err(invalid_input(
            "artifact manifest entry count is outside its supported range",
        ));
    }

    let mut seen_files = HashSet::new();
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(manifest.artifacts.len())
        .map_err(|_| io::Error::other("manifest source allocation failed"))?;
    for artifact in manifest.artifacts {
        if !is_safe_flat_file_name(&artifact.file) {
            return Err(invalid_input(
                "artifact manifest contains an unsafe file name",
            ));
        }
        if !seen_files.insert(artifact.file.clone()) {
            return Err(invalid_input("artifact manifest repeats a file name"));
        }
        sources.push(InputSpec {
            label: artifact.file.clone(),
            path: InputPath::ManifestMember(artifact.file),
            expected_length: Some(artifact.byte_length),
            expected_sha256: artifact.sha256,
        });
    }
    Ok(InputSet {
        sources,
        manifest_sha256: Some(manifest_sha256),
        memory: memory.clone(),
        _metadata_memory: metadata_memory,
        plans: Vec::new(),
        budget,
        extra_read_bytes: Cell::new(0),
        publication_recheck_held: Cell::new(false),
        manifest_read_bytes,
        #[cfg(target_os = "linux")]
        directory: Some(directory),
        #[cfg(not(target_os = "linux"))]
        directory: Some(directory),
    })
}

fn plan_sources(input_set: &mut InputSet) -> Result<(), Box<dyn Error>> {
    // Leave room for both manifest rechecks before admitting source reads
    let manifest_reserve = input_set
        .manifest_read_bytes
        .checked_mul(2)
        .ok_or_else(|| invalid_input("manifest read reservation overflows"))?;
    let mut available = input_set
        .budget
        .remaining()
        .checked_sub(manifest_reserve)
        .ok_or_else(|| invalid_input("source read limit cannot cover manifest rechecks"))?;
    let mut plans = Vec::new();
    plans.try_reserve_exact(input_set.sources.len())?;
    for spec in &input_set.sources {
        let file = open_identity_source(input_set, spec)?;
        let metadata = file.metadata()?;
        let length = checked_length(&metadata, spec.expected_length, usize::MAX)?;
        let length_u64 = u64::try_from(length)?;
        let required = analysis_reservation(length_u64);
        let omission = match required {
            Some(required) if required <= available => {
                available -= required;
                None
            }
            required => Some(ReadOmission {
                length,
                required: required.unwrap_or(u64::MAX),
                remaining: available,
                maximum: input_set.budget.maximum(),
            }),
        };
        plans.push(SourcePlan {
            length,
            metadata: metadata_fingerprint(&metadata),
            omission,
        });
    }
    input_set.plans = plans;
    input_set.extra_read_bytes.set(available);
    Ok(())
}

pub(super) fn ensure_manifest_unchanged(
    input_set: &InputSet,
    job: &Job,
) -> Result<(), Box<dyn Error>> {
    let Some(expected) = &input_set.manifest_sha256 else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    if let Some(directory) = &input_set.directory {
        directory.check_location()?;
    }
    let file = read_directory_file(input_set, "manifest.json")?;
    let metadata = file.file_metadata()?;
    let opened = metadata_fingerprint(&metadata);
    let manifest_length = usize::try_from(metadata.len())?;
    let manifest_read_bytes = metadata
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_input("manifest read length overflows"))?;
    input_set.budget.reserve(manifest_read_bytes)?;
    let (_, digest) = read_snapshot(
        CancellableReader::new(file, job),
        MAX_MANIFEST_BYTES,
        Some(manifest_length),
        None,
    )?;
    let named = read_directory_file(input_set, "manifest.json")?;
    if &digest != expected || opened != metadata_fingerprint(&named.file_metadata()?) {
        return Err(invalid_input(
            "input artifact manifest changed during refinement",
        ));
    }
    #[cfg(target_os = "linux")]
    if let Some(directory) = &input_set.directory {
        directory.check_location()?;
    }
    Ok(())
}

pub(super) fn read_sources(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<LoadedSources, Box<dyn Error>> {
    let count = input_set.sources.len();
    let labels = input_set
        .sources
        .iter()
        .try_fold(0_usize, |total, source| {
            total.checked_add(source.label.len())
        })
        .ok_or("source label size overflows")?;
    let requested = count
        .checked_mul(std::mem::size_of::<LoadedSource>())
        .and_then(|bytes| bytes.checked_add(labels))
        .ok_or("loaded source metadata overflows")?;
    let mut metadata_memory = memory.try_reserve(MemoryClass::Base, u64::try_from(requested)?)?;
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(count)
        .map_err(|_| io::Error::other("input source allocation failed"))?;
    super::analysis_memory::charge(
        &mut metadata_memory,
        (sources.capacity() - count)
            .checked_mul(std::mem::size_of::<LoadedSource>())
            .ok_or("loaded source metadata overflows")?,
    )?;
    let mut total_bytes = 0_usize;
    for (spec, plan) in input_set.sources.iter().zip(&input_set.plans) {
        job.check_cancelled()?;
        let mut label = String::new();
        label.try_reserve_exact(spec.label.len())?;
        super::analysis_memory::charge(&mut metadata_memory, label.capacity() - spec.label.len())?;
        label.push_str(&spec.label);
        if let Some(omission) = plan.omission {
            sources.push(LoadedSource {
                label,
                data: SourceData::Skipped(omission),
            });
            continue;
        }
        let file = open_identity_source(input_set, spec)?;
        let metadata = file.metadata()?;
        if metadata_fingerprint(&metadata) != plan.metadata {
            return Err(invalid_input("input artifact changed during admission"));
        }
        let length = plan.length;
        if length > per_file_limit {
            // Keep the identity, then hash content as the analyzer reads it
            let fingerprint = metadata_fingerprint(&metadata);
            if fingerprint != metadata_fingerprint(&file.metadata()?) {
                return Err(invalid_input("input artifact changed during admission"));
            }
            sources.push(LoadedSource {
                label,
                data: SourceData::File(RangeSource {
                    length,
                    metadata: fingerprint,
                }),
            });
        } else {
            let next_total = checked_total(total_bytes, length, total_limit)?;
            let data =
                read_memory_source(input_set, spec, file, length, per_file_limit, job, memory)?;
            total_bytes = next_total;
            sources.push(LoadedSource { label, data });
        }
    }
    Ok(LoadedSources {
        values: sources,
        _metadata_memory: metadata_memory,
    })
}

fn read_memory_source(
    input: &InputSet,
    spec: &InputSpec,
    file: File,
    length: usize,
    per_file_limit: usize,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<SourceData, Box<dyn Error>> {
    let requested = length.checked_add(128).ok_or("source memory overflows")?;
    let mut lease = memory.try_reserve(MemoryClass::Base, u64::try_from(requested)?)?;
    input.budget.reserve(
        u64::try_from(length)?
            .checked_add(1)
            .ok_or_else(|| invalid_input("source read length overflows"))?,
    )?;
    let (bytes, sha256) = read_snapshot(
        CancellableReader::new(file, job),
        per_file_limit,
        Some(length),
        spec.expected_sha256.as_deref(),
    )?;
    let retained = bytes
        .capacity()
        .checked_add(sha256.capacity())
        .ok_or("source memory overflows")?;
    lease.try_resize(u64::try_from(retained)?)?;
    Ok(SourceData::Memory {
        bytes,
        sha256,
        _memory: Some(lease),
    })
}

#[cfg(test)]
pub(super) fn read_sources_with_test_budget(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<LoadedSources, Box<dyn Error>> {
    read_sources(
        input_set,
        total_limit,
        per_file_limit,
        job,
        &MemoryBudget::new(u64::MAX),
    )
}

pub(super) fn fingerprint_sources(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<FingerprintedSources, Box<dyn Error>> {
    let count = input_set.sources.len();
    let labels_bytes = input_set
        .sources
        .iter()
        .try_fold(0_usize, |total, spec| total.checked_add(spec.label.len()))
        .ok_or("fingerprint label size overflows")?;
    let scratch_bytes = count
        .checked_mul(std::mem::size_of::<SampledSource<'_>>() + 128)
        .and_then(|bytes| bytes.checked_add(64 * 1024 + 512))
        .ok_or("fingerprint scratch size overflows")?;
    let retained_bytes = count
        .checked_mul(std::mem::size_of::<String>())
        .and_then(|bytes| bytes.checked_add(labels_bytes))
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or("fingerprint metadata size overflows")?;
    let mut scratch = input_set
        .memory
        .try_reserve(MemoryClass::Base, u64::try_from(scratch_bytes)?)?;
    let mut retained = input_set
        .memory
        .try_reserve(MemoryClass::Base, u64::try_from(retained_bytes)?)?;
    let mut sampled = Vec::new();
    let mut labels = Vec::new();
    sampled.try_reserve_exact(count)?;
    labels.try_reserve_exact(count)?;
    super::analysis_memory::charge(
        &mut scratch,
        (sampled.capacity() - count)
            .checked_mul(std::mem::size_of::<SampledSource<'_>>())
            .ok_or("fingerprint scratch size overflows")?,
    )?;
    super::analysis_memory::charge(
        &mut retained,
        (labels.capacity() - count)
            .checked_mul(std::mem::size_of::<String>())
            .ok_or("fingerprint metadata size overflows")?,
    )?;
    let mut total = 0_u64;
    let mut memory_bytes = 0_usize;
    for (spec, plan) in input_set.sources.iter().zip(&input_set.plans) {
        job.check_cancelled()?;
        let mut file = open_identity_source(input_set, spec)?;
        let metadata = metadata_fingerprint(&file.metadata()?);
        if metadata != plan.metadata {
            return Err(invalid_input("input artifact changed during refinement"));
        }
        let length = plan.length;
        if plan.omission.is_none() && length <= per_file_limit {
            memory_bytes = checked_total(memory_bytes, length, total_limit)?;
        }
        total = total
            .checked_add(u64::try_from(length)?)
            .ok_or_else(|| invalid_input("input source byte total overflows"))?;
        let fingerprint = if plan.omission.is_none() {
            input_set
                .budget
                .reserve(SourceFingerprint::sample_read_bytes(u64::try_from(length)?))?;
            let fingerprint = SourceFingerprint::fast_open_file_with_expected_length_and_observer(
                &mut file,
                u64::try_from(length)?,
                |count| record_source_read(job, count),
            )?;
            if fingerprint.size_bytes != u64::try_from(length)? {
                return Err(invalid_input(
                    "input artifact changed while it was fingerprinted",
                ));
            }
            super::analysis_memory::charge(
                &mut scratch,
                fingerprint.sample_sha256.capacity().saturating_sub(128),
            )?;
            Some(fingerprint)
        } else {
            None
        };
        sampled.push(SampledSource {
            label: &spec.label,
            expected_length: spec.expected_length,
            expected_sha256: spec.expected_sha256.as_deref(),
            fingerprint,
            skipped_metadata: plan.omission.map(|_| metadata),
        });
        let mut label = String::new();
        label.try_reserve_exact(spec.label.len())?;
        super::analysis_memory::charge(&mut retained, label.capacity() - spec.label.len())?;
        label.push_str(&spec.label);
        labels.push(label);
    }

    // The set hint binds ordering, labels, declarations, metadata, and bounded samples
    let sample_set_sha256 = super::hash::hash_json(&("l2solver-refine-sample-set-v1", &sampled))?;
    let identity = if sampled.iter().all(|entry| entry.fingerprint.is_some()) {
        let mut fingerprint = sampled
            .first()
            .and_then(|entry| entry.fingerprint.as_ref())
            .ok_or_else(|| invalid_input("input has no sources"))?
            .sample_hint();
        fingerprint.size_bytes = total;
        fingerprint.sample_sha256.clone_from(&sample_set_sha256);
        SourceIdentity::Fast(fingerprint)
    } else {
        SourceIdentity::Unavailable
    };
    let digest_bytes = sample_set_sha256
        .capacity()
        .checked_add(match &identity {
            SourceIdentity::Fast(fingerprint) => fingerprint.sample_sha256.capacity(),
            _ => 0,
        })
        .ok_or("fingerprint digest size overflows")?;
    super::analysis_memory::charge(&mut retained, digest_bytes.saturating_sub(256))?;
    drop(sampled);
    drop(scratch);
    Ok(FingerprintedSources {
        identity,
        labels,
        total_bytes: total,
        sample_set_sha256,
        _memory: retained,
    })
}

pub(super) fn strong_source_identity(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<SourceIdentity, Box<dyn Error>> {
    // One reusable read buffer and digest workspace cover each strong identity pass
    let _scratch = input_set
        .memory
        .try_reserve(MemoryClass::Base, 64 * 1024 + 512)?;
    let mut writer = super::output::SourceIdentityWriter::new()?;
    let mut total = 0_usize;
    for (spec, plan) in input_set.sources.iter().zip(&input_set.plans) {
        job.check_cancelled()?;
        if plan.omission.is_some() {
            return Err(invalid_input(
                "source read limit prevents full identity verification",
            ));
        }
        let mut file = open_identity_source(input_set, spec)?;
        if metadata_fingerprint(&file.metadata()?) != plan.metadata {
            return Err(invalid_input("input artifact changed during refinement"));
        }
        let length = plan.length;
        if length <= per_file_limit {
            total = checked_total(total, length, total_limit)?;
        }
        input_set.budget.reserve(
            u64::try_from(length)?
                .checked_add(1)
                .ok_or_else(|| invalid_input("source read length overflows"))?,
        )?;
        let SourceIdentity::Sha256(digest) =
            SourceIdentity::sha256_open_file_with_expected_length_and_check(
                &mut file,
                u64::try_from(length)?,
                || job.check_cancelled().map_err(io::Error::other),
                |count| record_source_read(job, count),
            )?
        else {
            return Err(invalid_input("source digest is unavailable"));
        };
        if spec
            .expected_sha256
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(invalid_input("artifact hash does not match its manifest"));
        }
        if checked_source_length(&file, spec, usize::MAX)? != length {
            return Err(invalid_input("input artifact changed while it was hashed"));
        }
        writer.push(u64::try_from(length)?, &digest)?;
    }
    let digest = writer.finish()?;
    Ok(SourceIdentity::from_sha256(digest)?)
}

fn checked_source_length(
    file: &File,
    spec: &InputSpec,
    maximum: usize,
) -> Result<usize, Box<dyn Error>> {
    checked_length(&file.metadata()?, spec.expected_length, maximum)
}

fn checked_length(
    metadata: &Metadata,
    expected_length: Option<usize>,
    maximum: usize,
) -> Result<usize, Box<dyn Error>> {
    if !metadata.is_file() {
        return Err(invalid_input("input artifact is not a regular file"));
    }
    let length = usize::try_from(metadata.len())?;
    if length > maximum {
        return Err(invalid_input(
            "input artifact exceeds the configured analysis file limit",
        ));
    }
    if expected_length.is_some_and(|expected| expected != length) {
        return Err(invalid_input("artifact length does not match its manifest"));
    }
    Ok(length)
}

fn checked_total(total: usize, length: usize, maximum: usize) -> Result<usize, Box<dyn Error>> {
    let total = total
        .checked_add(length)
        .ok_or_else(|| invalid_input("input source byte total overflows"))?;
    if total > maximum {
        return Err(invalid_input(
            "manifest input bytes exceed the configured recovery memory limit",
        ));
    }
    Ok(total)
}

fn open_identity_source(input_set: &InputSet, spec: &InputSpec) -> Result<File, Box<dyn Error>> {
    match &spec.path {
        InputPath::Direct(path) => Ok(crate::input::regular_no_follow(path)?.into_inner()),
        InputPath::ManifestMember(name) => {
            #[cfg(target_os = "linux")]
            {
                read_directory_file(input_set, name)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Ok(read_directory_file(input_set, name)?.into_inner())
            }
        }
    }
}

pub(super) fn read_snapshot(
    file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    read_snapshot_inner(file, maximum, expected_length, expected_sha256, None)
}

// The caller retains this charge with the returned buffers and rolls it back after errors
pub(super) fn read_snapshot_with_memory(
    file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
    memory: &mut MemoryLease,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    read_snapshot_inner(
        file,
        maximum,
        expected_length,
        expected_sha256,
        Some(memory),
    )
}

fn read_snapshot_inner(
    mut file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
    mut memory: Option<&mut MemoryLease>,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let before = file.file_metadata()?;
    let length = checked_length(&before, expected_length, maximum)?;

    if let Some(lease) = memory.as_deref_mut() {
        let requested = length
            .checked_add(128)
            .ok_or("snapshot memory size overflows")?;
        // The byte copy and digest formatting may coexist until both are returned
        super::analysis_memory::charge(lease, requested)?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("input artifact allocation failed"))?;
    if let Some(lease) = memory {
        super::analysis_memory::charge(lease, bytes.capacity() - length)?;
    }
    bytes.resize(length, 0);
    if let Err(error) = file.read_exact(&mut bytes) {
        if error.kind() != io::ErrorKind::UnexpectedEof {
            return Err(error.into());
        }
        return Err(invalid_input(
            "input artifact length changed while it was read",
        ));
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(invalid_input(
            "input artifact length changed while it was read",
        ));
    }
    let after = file.file_metadata()?;
    if metadata_fingerprint(&before) != metadata_fingerprint(&after) {
        return Err(invalid_input("input artifact changed while it was read"));
    }
    let digest = sha256(&bytes);
    if expected_sha256.is_some_and(|expected| expected != digest) {
        return Err(invalid_input("artifact hash does not match its manifest"));
    }
    Ok((bytes, digest))
}

pub(super) trait MetadataReader {
    fn file_metadata(&self) -> io::Result<Metadata>;
}

impl MetadataReader for crate::input::InputFile {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.metadata()
    }
}

impl MetadataReader for File {
    fn file_metadata(&self) -> io::Result<Metadata> {
        self.metadata()
    }
}

#[derive(PartialEq, Eq, Serialize)]
struct MetadataFingerprint {
    length: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

fn metadata_fingerprint(metadata: &Metadata) -> MetadataFingerprint {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    MetadataFingerprint {
        length: metadata.len(),
        #[cfg(not(unix))]
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        modified_seconds: metadata.mtime(),
        #[cfg(unix)]
        modified_nanoseconds: metadata.mtime_nsec(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
impl DirectoryAnchor {
    fn open(path: &Path) -> Result<Self, Box<dyn Error>> {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt;

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
        let opened = File::from(descriptor.try_clone()?).metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !named.is_dir() || opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(invalid_input("input directory changed while it was opened"));
        }
        Ok(Self {
            descriptor,
            path: path.to_owned(),
            device: opened.dev(),
            inode: opened.ino(),
        })
    }

    fn check_location(&self) -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;
        let named = fs::symlink_metadata(&self.path)?;
        if !named.is_dir() || named.dev() != self.device || named.ino() != self.inode {
            return Err(invalid_input("input directory changed during refinement"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn read_directory_member(
    directory: &DirectoryAnchor,
    name: &str,
    maximum: usize,
    budget: &SourceReadBudget,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<(Vec<u8>, String, MemoryLease), Box<dyn Error>> {
    let file = open_directory_member(directory, name)?;
    let length = checked_length(&file.metadata()?, None, maximum)?;
    read_manifest_snapshot(file, length, maximum, budget, job, memory)
}

#[cfg(not(target_os = "linux"))]
fn read_directory_member(
    directory: &PathBuf,
    name: &str,
    maximum: usize,
    budget: &SourceReadBudget,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<(Vec<u8>, String, MemoryLease), Box<dyn Error>> {
    let path = directory.join(name);
    let file = crate::input::regular_no_follow(&path)?;
    let length = checked_length(&file.metadata()?, None, maximum)?;
    read_manifest_snapshot(file, length, maximum, budget, job, memory)
}

fn read_manifest_snapshot(
    file: impl Read + MetadataReader,
    length: usize,
    maximum: usize,
    budget: &SourceReadBudget,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<(Vec<u8>, String, MemoryLease), Box<dyn Error>> {
    // Bound both the raw manifest and its parsed source records before reading
    let records = (length / 2 + 1).min(MAX_MANIFEST_ARTIFACTS);
    let record_size = std::mem::size_of::<InputSpec>()
        + std::mem::size_of::<InputManifestArtifact>()
        + std::mem::size_of::<SourcePlan>()
        + 128;
    let allowance = length
        .checked_mul(4)
        .and_then(|bytes| {
            records
                .checked_mul(record_size)
                .and_then(|extra| bytes.checked_add(extra))
        })
        .and_then(|bytes| bytes.checked_add(1024))
        .ok_or_else(|| invalid_input("manifest memory allowance overflows"))?;
    let lease = memory.try_reserve(MemoryClass::Base, u64::try_from(allowance)?)?;
    budget.reserve(
        u64::try_from(length)?
            .checked_add(1)
            .ok_or_else(|| invalid_input("manifest read length overflows"))?,
    )?;
    let (bytes, digest) = read_snapshot(
        CancellableReader::new(file, job),
        maximum,
        Some(length),
        None,
    )?;
    Ok((bytes, digest, lease))
}

#[cfg(target_os = "linux")]
fn read_directory_file(input_set: &InputSet, name: &str) -> Result<File, Box<dyn Error>> {
    let directory = input_set
        .directory
        .as_ref()
        .ok_or_else(|| invalid_input("manifest member has no anchored input directory"))?;
    open_directory_member(directory, name).map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn read_directory_file(
    input_set: &InputSet,
    name: &str,
) -> Result<crate::input::InputFile, Box<dyn Error>> {
    let directory = input_set
        .directory
        .as_ref()
        .ok_or_else(|| invalid_input("manifest member has no input directory"))?;
    let path = directory.join(name);
    Ok(crate::input::regular_no_follow(&path)?)
}

#[cfg(target_os = "linux")]
fn open_directory_member(directory: &DirectoryAnchor, name: &str) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::ffi::OsStr;

    let descriptor = openat(
        &directory.descriptor,
        OsStr::new(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    Ok(File::from(descriptor))
}
