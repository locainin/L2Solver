//! Stream bounded source windows through the existing embedded-object validators

use super::{
    AnalysisBoundary, AnalysisFormat, AnalysisOmission, AnalysisStatus, AnalyzedArtifact,
    ArtifactAnalysis, ArtifactAnalysisOptions, ArtifactOrigin, ArtifactValidationState,
    EmbeddedDiscoveryLimits, EmbeddedFormat, EmbeddedValidationEvidence, FileRange, PngLimits,
    ValidationSummary, ZipEndObservation, ZipEndScanLimits, discover_embedded_objects_with_work,
    scan_file_signatures, source_hash::SourceHasher, zip::ZipArtifactLimits,
};
use crate::job::MemoryLease;
use std::io::{self, Read};

// Two windows fit within the caller's in-memory input budget
const MAX_WINDOW_STEP_BYTES: usize = 4 * 1024 * 1024;
const HASH_TAIL_BYTES: usize = 64 * 1024;

/// A validated PNG boundary and digest collected during the source pass
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamPngBoundary {
    /// Exact PNG range ending immediately after IEND
    pub range: FileRange,
    /// SHA-256 of that range, excluding any following bytes
    pub sha256: String,
    /// Number of CRC-checked chunks
    pub chunk_count: usize,
}

/// Source analysis, an optional PNG boundary, and an optional prefix digest
pub struct StreamSourceAnalysis {
    /// Bounded rolling source analysis and the digest of the complete source
    pub analysis: ArtifactAnalysis,
    /// PNG structure when the source starts with a valid, affordable PNG
    pub png: Option<StreamPngBoundary>,
    /// SHA-256 at a requested prefix boundary, captured during the source pass
    pub prefix_sha256: Option<String>,
    /// Optional bounded observation of unvalidated ZIP end records
    pub zip_observation: Option<ZipEndObservation>,
}

/// Analyze bounded PNG and ZIP ranges while hashing the complete source stream
///
/// Only objects no larger than half the in-memory input limit, capped at 4 MiB, are
/// guaranteed to fit across a window boundary. Whole-source transformations and recursive
/// archive expansion are not performed, so the result is always partial. The reader must
/// begin at the first source byte and remain stable throughout the call.
///
/// # Errors
/// Returns an I/O error when the source length changes, reading fails, policy limits are
/// invalid, or bounded analysis storage cannot be allocated
pub fn analyze_artifacts_from_reader(
    reader: &mut impl Read,
    source_length: usize,
    options: ArtifactAnalysisOptions,
) -> io::Result<ArtifactAnalysis> {
    let mut reader = ScannedReader::new(reader, source_length, options, None, None)?;
    reader.drain_source()?;
    Ok(reader.finish()?.0)
}

/// Observe possible ZIP ends while performing the same source pass and optional PNG scan
///
/// Observed markers are candidates only. The caller must validate every selected range
/// with the canonical ZIP parser. Observation work is charged to the shared work limit.
///
/// # Errors
/// Returns an I/O or policy error if the work allowance or reader is invalid
pub fn analyze_artifacts_observing_zip_ends(
    reader: &mut impl Read,
    source_length: usize,
    options: ArtifactAnalysisOptions,
    checkpoint: Option<usize>,
    scan_png: bool,
    limits: ZipEndScanLimits,
    memory: Option<&mut MemoryLease>,
) -> io::Result<StreamSourceAnalysis> {
    let scan_work = source_length.min(limits.max_scan_bytes);
    let mut scan_options = options;
    scan_options.limits.max_total_work_bytes = options
        .limits
        .max_total_work_bytes
        .checked_sub(scan_work)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ZIP observation exceeds the byte-work limit",
            )
        })?;
    let mut result = if scan_png {
        analyze_png_inner(
            reader,
            source_length,
            scan_options,
            checkpoint,
            Some(limits),
            memory,
        )?
    } else {
        let mut reader = ScannedReader::new(
            reader,
            source_length,
            scan_options,
            checkpoint,
            Some(limits),
        )?;
        reader.drain_source()?;
        let (analysis, prefix_sha256, zip_observation) = reader.finish()?;
        StreamSourceAnalysis {
            analysis,
            png: None,
            prefix_sha256,
            zip_observation,
        }
    };
    result.analysis.work_bytes = result
        .analysis
        .work_bytes
        .checked_add(scan_work)
        .ok_or_else(|| io::Error::other("ZIP observation work overflows"))?;
    Ok(result)
}

fn analyze_png_inner(
    reader: &mut impl Read,
    source_length: usize,
    options: ArtifactAnalysisOptions,
    checkpoint: Option<usize>,
    zip_limits: Option<ZipEndScanLimits>,
    mut memory: Option<&mut MemoryLease>,
) -> io::Result<StreamSourceAnalysis> {
    if source_length >= options.limits.max_total_work_bytes {
        return png_work_omitted(reader, source_length, options, checkpoint, zip_limits);
    }
    let mut scan_options = options;
    // Reserve the worst-case PNG scan before the rolling scanner spends work
    scan_options.limits.max_total_work_bytes -= source_length;
    let mut reader =
        ScannedReader::new(reader, source_length, scan_options, checkpoint, zip_limits)?;
    // Keep chunk metadata within the caller's bounded input allowance
    let metadata_bytes = std::mem::size_of::<super::PngRangeChunk>().max(1);
    let limits = PngLimits {
        max_input_bytes: source_length,
        max_chunks: PngLimits::default()
            .max_chunks
            .min((options.limits.max_input_bytes / metadata_bytes).max(1)),
    };
    let before = memory.as_ref().map(|lease| lease.bytes());
    let result = if let Some(lease) = memory.as_deref_mut() {
        super::parse_png_from_reader_with_memory(&mut reader, source_length, limits, lease)
    } else {
        super::parse_png_from_reader(&mut reader, source_length, limits)
    };
    let consumed = reader.scanned.read_bytes;
    // Unused PNG work remains available to later rolling windows
    reader.scanned.state.refund_work(source_length - consumed)?;
    let (png, omission) = match result {
        Ok(report) => {
            let length = report.bytes_after_iend_range.offset;
            if length != consumed {
                return Err(io::Error::other(
                    "PNG boundary differs from the consumed stream",
                ));
            }
            // Snapshot at IEND before the reader continues into trailing bytes
            (
                Some(StreamPngBoundary {
                    range: FileRange { offset: 0, length },
                    sha256: reader.scanned.hasher.current_digest(),
                    chunk_count: report.chunks.len(),
                }),
                None,
            )
        }
        Err(super::PngReadError::Io(error)) => return Err(error),
        Err(super::PngReadError::Memory(error)) => return Err(io::Error::other(error)),
        Err(super::PngReadError::Format(
            error @ (super::PngError::TooManyChunks { .. } | super::PngError::AllocationFailure),
        )) => (None, Some(error.to_string())),
        Err(super::PngReadError::Format(_)) => (None, None),
    };
    if let (Some(lease), Some(before)) = (memory, before) {
        lease.try_resize(before).map_err(io::Error::other)?;
    }
    reader.drain_source()?;
    let (mut analysis, prefix_sha256, zip_observation) = reader.finish()?;
    analysis.work_bytes = analysis
        .work_bytes
        .checked_add(consumed)
        .ok_or_else(|| io::Error::other("PNG validation work overflows"))?;
    if let Some(reason) = omission {
        analysis
            .omissions
            .push(AnalysisOmission::SourceRangeValidationLimit {
                format: AnalysisFormat::Png,
                reason,
            });
    }
    Ok(StreamSourceAnalysis {
        analysis,
        png,
        prefix_sha256,
        zip_observation,
    })
}

fn png_work_omitted(
    reader: &mut impl Read,
    source_length: usize,
    options: ArtifactAnalysisOptions,
    checkpoint: Option<usize>,
    zip_limits: Option<ZipEndScanLimits>,
) -> io::Result<StreamSourceAnalysis> {
    let mut reader = ScannedReader::new(reader, source_length, options, checkpoint, zip_limits)?;
    reader.drain_source()?;
    let (mut analysis, prefix_sha256, zip_observation) = reader.finish()?;
    analysis
        .omissions
        .push(AnalysisOmission::SourceRangeValidationLimit {
            format: AnalysisFormat::Png,
            reason: String::from("PNG validation exceeds the remaining byte-work limit"),
        });
    Ok(StreamSourceAnalysis {
        analysis,
        png: None,
        prefix_sha256,
        zip_observation,
    })
}

struct ScannedReader<'a, R> {
    inner: &'a mut R,
    scanned: RangeCollector,
}

impl<'a, R: Read> ScannedReader<'a, R> {
    fn new(
        reader: &'a mut R,
        source_length: usize,
        options: ArtifactAnalysisOptions,
        checkpoint: Option<usize>,
        zip_limits: Option<ZipEndScanLimits>,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: reader,
            scanned: RangeCollector::new(source_length, options, checkpoint, zip_limits)?,
        })
    }

    fn drain_source(&mut self) -> io::Result<()> {
        let capacity = (self.scanned.source_length - self.scanned.read_bytes).min(HASH_TAIL_BYTES);
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(io::Error::other)?;
        buffer.resize(capacity, 0);
        while self.scanned.read_bytes < self.scanned.source_length {
            let length = (self.scanned.source_length - self.scanned.read_bytes).min(buffer.len());
            let part = buffer
                .get_mut(..length)
                .ok_or_else(|| io::Error::other("source buffer length is invalid"))?;
            self.read_exact(part)?;
        }
        let mut extra = [0_u8; 1];
        if self.read(&mut extra)? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source length changed while it was read",
            ));
        }
        Ok(())
    }

    fn finish(self) -> io::Result<(ArtifactAnalysis, Option<String>, Option<ZipEndObservation>)> {
        self.scanned.finish()
    }
}

impl<R: Read> Read for ScannedReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.scanned.read_bytes == self.scanned.source_length {
            return self.inner.read(buffer);
        }
        let mut limit = (self.scanned.source_length - self.scanned.read_bytes).min(buffer.len());
        if !self.scanned.stopped {
            limit = limit.min(self.scanned.window_capacity - self.scanned.window.len());
        }
        let part = buffer
            .get_mut(..limit)
            .ok_or_else(|| io::Error::other("source buffer length is invalid"))?;
        let count = self.inner.read(part)?;
        self.scanned.accept(
            part.get(..count)
                .ok_or_else(|| io::Error::other("source read length is invalid"))?,
        )?;
        Ok(count)
    }
}

struct RangeCollector {
    state: RangeState,
    source_length: usize,
    read_bytes: usize,
    offset: usize,
    step: usize,
    window_capacity: usize,
    window: Vec<u8>,
    hasher: SourceHasher,
    stopped: bool,
}

impl RangeCollector {
    fn new(
        source_length: usize,
        options: ArtifactAnalysisOptions,
        checkpoint: Option<usize>,
        zip_limits: Option<ZipEndScanLimits>,
    ) -> io::Result<Self> {
        // A full Case may leave no output space while the source still needs hashing
        let mut validation_limits = options.limits;
        validation_limits.max_total_output_bytes = validation_limits.max_total_output_bytes.max(1);
        super::analyzer::validate_limits(validation_limits)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if options.limits.max_input_bytes < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "range analysis needs at least two input bytes",
            ));
        }
        let step = (options.limits.max_input_bytes / 2).clamp(1, MAX_WINDOW_STEP_BYTES);
        let window_capacity = step
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("range window length overflow"))?;
        let mut window = Vec::new();
        window
            .try_reserve_exact(window_capacity.min(source_length))
            .map_err(io::Error::other)?;
        Ok(Self {
            state: RangeState::new(options, source_length),
            source_length,
            read_bytes: 0,
            offset: 0,
            step,
            window_capacity,
            window,
            hasher: SourceHasher::new(source_length, checkpoint, zip_limits)?,
            stopped: false,
        })
    }

    fn accept(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.hasher.accept(bytes)?;
        self.read_bytes += bytes.len();
        if self.stopped || bytes.is_empty() {
            return Ok(());
        }
        self.window.extend_from_slice(bytes);
        if self.window.len() == self.window_capacity {
            self.inspect_window()?;
        }
        Ok(())
    }

    fn inspect_window(&mut self) -> io::Result<()> {
        if !self.state.can_inspect(self.window.len()) {
            self.stopped = true;
            self.window.clear();
            return Ok(());
        }
        self.state
            .inspect_window(&self.window, self.offset, self.step)?;
        // The overlap gives boundary-spanning objects another complete window
        let consumed = self.step.min(self.window.len());
        self.window.copy_within(consumed.., 0);
        self.window.truncate(self.window.len() - consumed);
        self.offset += consumed;
        Ok(())
    }

    fn finish(
        mut self,
    ) -> io::Result<(ArtifactAnalysis, Option<String>, Option<ZipEndObservation>)> {
        while !self.stopped && !self.window.is_empty() {
            self.inspect_window()?;
        }
        let hashes = self.hasher.finish()?;
        Ok((
            self.state.finish(hashes.source_sha256, self.step),
            hashes.prefix_sha256,
            hashes.zip_observation,
        ))
    }
}

struct RangeState {
    options: ArtifactAnalysisOptions,
    source_length: usize,
    artifacts: Vec<AnalyzedArtifact>,
    output_bytes: usize,
    work_remaining: usize,
    signature_remaining: usize,
    attempts_remaining: usize,
    candidates_remaining: usize,
    scanned_end: usize,
    omitted_candidates: usize,
    zip_entry_count_limited: usize,
    signature_scans_omitted: usize,
}

impl RangeState {
    fn refund_work(&mut self, bytes: usize) -> io::Result<()> {
        self.work_remaining = self
            .work_remaining
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("range work allowance overflows"))?;
        self.options.limits.max_total_work_bytes = self
            .options
            .limits
            .max_total_work_bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("range work limit overflows"))?;
        Ok(())
    }

    const fn new(options: ArtifactAnalysisOptions, source_length: usize) -> Self {
        let limits = options.limits;
        Self {
            options,
            source_length,
            artifacts: Vec::new(),
            output_bytes: 0,
            work_remaining: limits.max_total_work_bytes,
            signature_remaining: limits.max_signature_scan_bytes,
            attempts_remaining: limits.max_artifacts.saturating_mul(2),
            candidates_remaining: limits.max_artifacts.saturating_mul(2),
            scanned_end: 0,
            omitted_candidates: 0,
            zip_entry_count_limited: 0,
            signature_scans_omitted: 0,
        }
    }

    const fn can_inspect(&self, length: usize) -> bool {
        length <= self.work_remaining
            && self.candidates_remaining > 0
            && self.attempts_remaining > 0
    }

    fn inspect_window(&mut self, window: &[u8], offset: usize, step: usize) -> io::Result<()> {
        self.work_remaining -= window.len();
        let mut png_limits = PngLimits::default();
        png_limits.max_input_bytes = png_limits.max_input_bytes.min(step);
        let mut zip_limits = ZipArtifactLimits::default();
        zip_limits.max_archive_bytes = zip_limits.max_archive_bytes.min(step);
        let limits = EmbeddedDiscoveryLimits {
            max_scan_bytes: window.len(),
            max_validation_attempts: self.attempts_remaining,
            max_candidates: self.candidates_remaining,
            png_limits,
            zip_limits,
            // Source-range analysis validates archive boundaries without expanding members
            max_zip_operation_expanded_bytes: 0,
        };
        let discovery = discover_embedded_objects_with_work(window, limits, self.work_remaining)
            .map_err(io::Error::other)?;
        let validation_work = discovery
            .validation_input_bytes
            .checked_add(discovery.zip_work_bytes)
            .ok_or_else(|| io::Error::other("range validation work overflow"))?;
        self.work_remaining = self
            .work_remaining
            .checked_sub(validation_work)
            .ok_or_else(|| io::Error::other("range validation exceeded its work budget"))?;
        self.attempts_remaining = self
            .attempts_remaining
            .checked_sub(discovery.validation_attempt_count)
            .ok_or_else(|| io::Error::other("range validation exceeded its attempt budget"))?;
        self.candidates_remaining = self
            .candidates_remaining
            .checked_sub(discovery.candidates.len())
            .ok_or_else(|| io::Error::other("range validation exceeded its candidate budget"))?;
        self.omitted_candidates = self
            .omitted_candidates
            .saturating_add(discovery.omissions.output_candidate_count)
            .saturating_add(discovery.omissions.unvalidated_candidate_count);
        self.zip_entry_count_limited = self
            .zip_entry_count_limited
            .saturating_add(discovery.omissions.zip_entry_count_limited);
        self.scanned_end = offset + step.min(window.len());

        for candidate in discovery.candidates {
            let Ok(evidence) = candidate.validation else {
                continue;
            };
            let end = candidate
                .range
                .offset
                .checked_add(candidate.range.length)
                .ok_or_else(|| io::Error::other("candidate range overflow"))?;
            let bytes = window
                .get(candidate.range.offset..end)
                .ok_or_else(|| io::Error::other("candidate range is outside its window"))?;
            let absolute = offset
                .checked_add(candidate.range.offset)
                .ok_or_else(|| io::Error::other("source range overflow"))?;
            self.retain(
                bytes,
                FileRange {
                    offset: absolute,
                    length: bytes.len(),
                },
                candidate.format,
                &evidence,
            )?;
        }
        Ok(())
    }

    fn retain(
        &mut self,
        bytes: &[u8],
        range: FileRange,
        format: EmbeddedFormat,
        evidence: &EmbeddedValidationEvidence,
    ) -> io::Result<()> {
        let origin = ArtifactOrigin::SourceRange { range, format };
        // Overlapping windows keep the same immutable bytes for an already observed range
        if self
            .artifacts
            .iter()
            .any(|artifact| artifact.origins.contains(&origin))
        {
            return Ok(());
        }
        let digest = match evidence {
            EmbeddedValidationEvidence::Zip { archive_sha256, .. } => archive_sha256.clone(),
            EmbeddedValidationEvidence::Png { .. } => crate::sha256(bytes),
        };
        // Equal bytes keep every distinct source range as separate evidence
        if let Some(existing) = self
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.sha256 == digest && artifact.bytes == bytes)
        {
            if !existing.origins.contains(&origin) {
                if existing.origins.len() >= self.options.limits.max_artifacts {
                    self.omitted_candidates = self.omitted_candidates.saturating_add(1);
                } else {
                    existing.origins.try_reserve(1).map_err(io::Error::other)?;
                    existing.origins.push(origin);
                }
            }
            return Ok(());
        }
        if self.artifacts.len() >= self.options.limits.max_artifacts
            || bytes.len()
                > self
                    .options
                    .limits
                    .max_total_output_bytes
                    .saturating_sub(self.output_bytes)
        {
            self.omitted_candidates = self.omitted_candidates.saturating_add(1);
            return Ok(());
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(io::Error::other)?;
        retained.extend_from_slice(bytes);
        self.artifacts.try_reserve(1).map_err(io::Error::other)?;
        let signatures_scanned =
            bytes.len() <= self.work_remaining && bytes.len() <= self.signature_remaining;
        let signature_match_count = if signatures_scanned {
            self.work_remaining -= bytes.len();
            self.signature_remaining -= bytes.len();
            scan_file_signatures(bytes).matches.len()
        } else {
            self.signature_scans_omitted += 1;
            0
        };
        self.output_bytes += bytes.len();
        self.artifacts.push(AnalyzedArtifact {
            index: self.artifacts.len(),
            origins: vec![origin],
            sha256: digest,
            signature_match_count,
            signatures_scanned,
            validation: validation_summary(bytes.len(), evidence),
            bytes: retained,
        });
        Ok(())
    }

    fn finish(self, source_sha256: String, step: usize) -> ArtifactAnalysis {
        // A stopped scan cannot claim complete coverage for the remaining source
        let uncovered_range = (self.scanned_end < self.source_length).then(|| FileRange {
            offset: self.scanned_end,
            length: self.source_length - self.scanned_end,
        });
        ArtifactAnalysis {
            source_sha256,
            source_length: self.source_length,
            artifacts: self.artifacts,
            status: AnalysisStatus::Partial,
            omissions: vec![AnalysisOmission::SourceRangeCoverage {
                max_object_bytes: step,
                omitted_candidates: self.omitted_candidates,
                zip_entry_count_limited: self.zip_entry_count_limited,
                signature_scans_omitted: self.signature_scans_omitted,
                uncovered_range,
            }],
            region_transform_reports: Vec::new(),
            work_bytes: self.options.limits.max_total_work_bytes - self.work_remaining,
            zip_expanded_work_bytes: 0,
        }
    }
}

const fn validation_summary(
    length: usize,
    evidence: &EmbeddedValidationEvidence,
) -> ValidationSummary {
    let (format, boundary, structure_count) = match evidence {
        EmbeddedValidationEvidence::Png { chunk_count, .. } => {
            (AnalysisFormat::Png, AnalysisBoundary::PngIend, *chunk_count)
        }
        EmbeddedValidationEvidence::Zip { entry_count, .. } => (
            AnalysisFormat::Zip,
            AnalysisBoundary::ZipEndRecord,
            *entry_count,
        ),
    };
    ValidationSummary {
        state: ArtifactValidationState::Validated,
        format: Some(format),
        boundary: Some(boundary),
        range: Some(FileRange { offset: 0, length }),
        structure_count,
    }
}
