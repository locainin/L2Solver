//! Secure bounded source admission for standalone files and artifact manifests

use super::{
    invalid_input,
    read_budget::{SourceReadBudget, analysis_reservation},
};
use crate::safe_filename::is_safe_flat_file_name;
use l2_workbench::{
    job::{
        Counter, Job, MemoryBudget, MemoryClass, MemoryLease,
        cache::{SourceFingerprint, SourceIdentity},
    },
    sha256,
};
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
    #[cfg(target_os = "linux")]
    directory: Option<DirectoryAnchor>,
    #[cfg(not(target_os = "linux"))]
    directory: Option<PathBuf>,
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
        if end > plan.length {
            return Err(invalid_input("artifact range exceeds its source"));
        }
        let mut source = open_identity_source(self, spec)?;
        if metadata_fingerprint(&source.metadata()?) != plan.metadata {
            return Err(invalid_input("input artifact changed before publication"));
        }
        source.seek(SeekFrom::Start(u64::try_from(artifact.range.offset)?))?;
        let mut source = CancellableReader::new(source, job);
        let mut target = File::options()
            .write(true)
            .create_new(true)
            .open(staging.join(&artifact.file_name))?;
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
            return Err(invalid_input(
                "input artifact changed while it was published",
            ));
        }
        let source = source.into_inner();
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

pub(super) struct RangeAnalysis {
    pub(super) report: l2_workbench::artifact::ArtifactAnalysis,
    pub(super) archive: Option<l2_workbench::artifact::zip::ZipArtifactReport>,
    pub(super) retain_source: bool,
    pub(super) png: Option<l2_workbench::artifact::StreamPngBoundary>,
}

impl LoadedSource {
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
        options: l2_workbench::artifact::ArtifactAnalysisOptions,
        job: &Job,
    ) -> Result<RangeAnalysis, Box<dyn Error>> {
        let SourceData::File(source) = &self.data else {
            return Err(invalid_input("source is not range-backed"));
        };
        let spec = input_set
            .sources
            .get(source_index)
            .ok_or_else(|| invalid_input("range source index is missing"))?;
        let mut file = open_identity_source(input_set, spec)?;
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed before range analysis",
            ));
        }
        let zip_candidate = super::range_zip::probe_tail(
            &mut file,
            source.length,
            options.limits.max_input_bytes,
            input_set,
            job,
        )?;
        file.seek(SeekFrom::Start(0))?;
        input_set.budget.reserve(
            u64::try_from(source.length)?
                .checked_add(1)
                .ok_or_else(|| invalid_input("source read length overflows"))?,
        )?;
        let mut reader = CancellableReader::new(file, job);
        let checkpoint = zip_candidate
            .as_ref()
            .and_then(|candidate| (candidate.length < source.length).then_some(candidate.length));
        let scanned = analyze_source_stream(&mut reader, source.length, options, checkpoint)?;
        let mut report = scanned.analysis;
        let mut png = scanned.png;
        let mut file = reader.into_inner();
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed during range analysis",
            ));
        }
        if spec
            .expected_sha256
            .as_ref()
            .is_some_and(|expected| expected != &report.source_sha256)
        {
            return Err(invalid_input("artifact hash does not match its manifest"));
        }
        let (archive, retain_source) = inspect_source_archive(
            &mut file,
            ObservedArchiveEnds {
                tail: zip_candidate,
                prefix_sha256: scanned.prefix_sha256,
                stream: scanned.zip_observation,
            },
            &mut report,
            options,
            input_set,
            job,
        )?;
        png = retain_png_range(png, &mut report, input_set)?;
        if metadata_fingerprint(&file.metadata()?) != source.metadata {
            return Err(invalid_input(
                "input artifact changed during range analysis",
            ));
        }
        confirm_range_source_name(input_set, spec, source)?;
        Ok(RangeAnalysis {
            report,
            archive,
            retain_source,
            png,
        })
    }
}

fn retain_png_range(
    png: Option<l2_workbench::artifact::StreamPngBoundary>,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    input: &InputSet,
) -> Result<Option<l2_workbench::artifact::StreamPngBoundary>, Box<dyn Error>> {
    let Some(boundary) = png else { return Ok(None) };
    if report.artifacts.iter().any(|artifact| {
        artifact.sha256 == boundary.sha256 && artifact.bytes.len() == boundary.range.length
    }) {
        return Ok(None);
    }
    let length = u64::try_from(boundary.range.length)?;
    if input.reserve_source_output(length)? {
        return Ok(Some(boundary));
    }
    report.omissions.push(
        l2_workbench::artifact::AnalysisOmission::SourceRangeOutputReadLimit {
            length,
            remaining: input.extra_read_bytes(),
            maximum: input.budget.maximum(),
        },
    );
    Ok(None)
}

fn analyze_source_stream(
    reader: &mut impl Read,
    length: usize,
    options: l2_workbench::artifact::ArtifactAnalysisOptions,
    checkpoint: Option<usize>,
) -> Result<l2_workbench::artifact::StreamSourceAnalysis, Box<dyn Error>> {
    let mut signature = [0_u8; l2_workbench::artifact::PNG_SIGNATURE.len()];
    let count = length.min(signature.len());
    let prefix = signature
        .get_mut(..count)
        .ok_or_else(|| invalid_input("source prefix length is invalid"))?;
    reader.read_exact(prefix)?;
    // Feed the already-read prefix to the analyzer without reopening the source
    let is_png = count == signature.len() && signature == l2_workbench::artifact::PNG_SIGNATURE;
    let prefix = signature
        .get(..count)
        .ok_or_else(|| invalid_input("source prefix length is invalid"))?;
    let mut complete = io::Cursor::new(prefix).chain(reader);
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
    Ok(
        l2_workbench::artifact::analyze_artifacts_observing_zip_ends(
            &mut complete,
            length,
            stream_options,
            checkpoint,
            is_png,
            limits,
        )?,
    )
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
    prefix_sha256: Option<String>,
    stream: Option<l2_workbench::artifact::ZipEndObservation>,
}

fn inspect_source_archive(
    file: &mut File,
    ends: ObservedArchiveEnds,
    report: &mut l2_workbench::artifact::ArtifactAnalysis,
    options: l2_workbench::artifact::ArtifactAnalysisOptions,
    input: &InputSet,
    job: &Job,
) -> Result<(Option<l2_workbench::artifact::zip::ZipArtifactReport>, bool), Box<dyn Error>> {
    let mut candidates = if let Some(observation) = ends.stream {
        if observation.unscanned_bytes > 0 || observation.omitted_candidates > 0 {
            report.omissions.push(
                l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit {
                    format: l2_workbench::artifact::AnalysisFormat::Zip,
                    reason: format!(
                        "ZIP end observation left {} bytes unscanned and omitted {} candidates",
                        observation.unscanned_bytes, observation.omitted_candidates
                    ),
                },
            );
        }
        observation.candidates
    } else {
        Vec::new()
    };
    let mut multiple = false;
    if let Some(tail) = ends.tail {
        multiple = tail.multiple_boundaries;
        if !candidates
            .iter()
            .any(|candidate| candidate.end == tail.length)
        {
            let sha256 = if tail.length == report.source_length {
                report.source_sha256.clone()
            } else {
                ends.prefix_sha256
                    .ok_or_else(|| invalid_input("ZIP boundary digest is missing"))?
            };
            candidates.try_reserve(1)?;
            candidates.push(l2_workbench::artifact::StreamZipEnd {
                end: tail.length,
                sha256,
            });
        }
    }
    if multiple || candidates.len() > 1 {
        report.omissions.push(
            l2_workbench::artifact::AnalysisOmission::SourceRangeValidationLimit {
                format: l2_workbench::artifact::AnalysisFormat::Zip,
                reason: String::from(
                    "multiple ZIP end boundaries were found; candidates were checked until one validated",
                ),
            },
        );
    }
    candidates.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.end));
    for candidate in candidates {
        let Some(archive) = super::range_zip::inspect(
            file,
            candidate.end,
            &candidate.sha256,
            report,
            options,
            input,
            job,
        )?
        else {
            continue;
        };
        let length = u64::try_from(candidate.end)?;
        let retain = input.reserve_source_output(length)?;
        if !retain {
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
    artifacts: Vec<InputManifestArtifact>,
}

#[derive(Deserialize)]
struct InputManifestArtifact {
    file: String,
    byte_length: usize,
    #[serde(default)]
    sha256: Option<String>,
}

#[cfg(test)]
pub(super) fn prepare_input_set(path: &Path) -> Result<InputSet, Box<dyn Error>> {
    prepare_input_set_with_limit(path, u64::MAX, &Job::new("unlimited test input"))
}

pub(super) fn prepare_input_set_with_limit(
    path: &Path,
    maximum: u64,
    job: &Job,
) -> Result<InputSet, Box<dyn Error>> {
    let budget = SourceReadBudget::new(maximum);
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_input("input path must not be a symbolic link"));
    }
    if metadata.is_dir() {
        let mut input = prepare_export_directory(path, budget, job)?;
        plan_sources(&mut input)?;
        return Ok(input);
    }
    if !metadata.is_file() {
        return Err(invalid_input(
            "input must be a regular file or artifact directory",
        ));
    }

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
) -> Result<InputSet, Box<dyn Error>> {
    #[cfg(target_os = "linux")]
    let directory = DirectoryAnchor::open(path)?;
    #[cfg(not(target_os = "linux"))]
    let directory = path.to_owned();

    let (manifest_bytes, manifest_sha256) = read_directory_member(
        &directory,
        "manifest.json",
        MAX_MANIFEST_BYTES,
        &budget,
        job,
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
) -> Result<Vec<LoadedSource>, Box<dyn Error>> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(input_set.sources.len())
        .map_err(|_| io::Error::other("input source allocation failed"))?;
    let mut total_bytes = 0_usize;
    for (spec, plan) in input_set.sources.iter().zip(&input_set.plans) {
        job.check_cancelled()?;
        if let Some(omission) = plan.omission {
            sources.push(LoadedSource {
                label: spec.label.clone(),
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
                label: spec.label.clone(),
                data: SourceData::File(RangeSource {
                    length,
                    metadata: fingerprint,
                }),
            });
        } else {
            let next_total = checked_total(total_bytes, length, total_limit)?;
            let loaded =
                read_memory_source(input_set, spec, file, length, per_file_limit, job, memory)?;
            if loaded.bytes().is_some() {
                total_bytes = next_total;
            }
            sources.push(loaded);
        }
    }
    Ok(sources)
}

fn read_memory_source(
    input: &InputSet,
    spec: &InputSpec,
    file: File,
    length: usize,
    per_file_limit: usize,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<LoadedSource, Box<dyn Error>> {
    let mut lease = memory.try_reserve(MemoryClass::Base, u64::try_from(length)?)?;
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
    lease.try_resize(u64::try_from(bytes.capacity())?)?;
    Ok(LoadedSource {
        label: spec.label.clone(),
        data: SourceData::Memory {
            bytes,
            sha256,
            _memory: Some(lease),
        },
    })
}

#[cfg(test)]
pub(super) fn read_sources_with_test_budget(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<Vec<LoadedSource>, Box<dyn Error>> {
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
    let mut sampled = Vec::new();
    let mut labels = Vec::new();
    sampled.try_reserve_exact(input_set.sources.len())?;
    labels.try_reserve_exact(input_set.sources.len())?;
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
        labels.push(spec.label.clone());
    }

    // The set hint binds ordering, labels, declarations, metadata, and bounded samples
    let sample_set_sha256 = sha256(&serde_json::to_vec(&(
        "l2solver-refine-sample-set-v1",
        &sampled,
    ))?);
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
    Ok(FingerprintedSources {
        identity,
        labels,
        total_bytes: total,
        sample_set_sha256,
    })
}

pub(super) fn strong_source_identity(
    input_set: &InputSet,
    total_limit: usize,
    per_file_limit: usize,
    job: &Job,
) -> Result<SourceIdentity, Box<dyn Error>> {
    let mut digests = Vec::new();
    digests.try_reserve_exact(input_set.sources.len())?;
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
        digests.push((u64::try_from(length)?, digest));
    }
    let digest = super::output::refine_source_identity_sha256(
        digests
            .iter()
            .map(|(length, digest)| (*length, digest.as_str())),
    )?;
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
    mut file: impl Read + MetadataReader,
    maximum: usize,
    expected_length: Option<usize>,
    expected_sha256: Option<&str>,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let before = file.file_metadata()?;
    let length = checked_length(&before, expected_length, maximum)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("input artifact allocation failed"))?;
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
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let file = open_directory_member(directory, name)?;
    let length = checked_length(&file.metadata()?, None, maximum)?;
    budget.reserve(
        u64::try_from(length)?
            .checked_add(1)
            .ok_or_else(|| invalid_input("manifest read length overflows"))?,
    )?;
    read_snapshot(
        CancellableReader::new(file, job),
        maximum,
        Some(length),
        None,
    )
}

#[cfg(not(target_os = "linux"))]
fn read_directory_member(
    directory: &PathBuf,
    name: &str,
    maximum: usize,
    budget: &SourceReadBudget,
    job: &Job,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    let path = directory.join(name);
    let file = crate::input::regular_no_follow(&path)?;
    let length = checked_length(&file.metadata()?, None, maximum)?;
    budget.reserve(
        u64::try_from(length)?
            .checked_add(1)
            .ok_or_else(|| invalid_input("manifest read length overflows"))?,
    )?;
    read_snapshot(
        CancellableReader::new(file, job),
        maximum,
        Some(length),
        None,
    )
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
