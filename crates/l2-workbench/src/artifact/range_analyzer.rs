//! Stream bounded source windows through the existing embedded-object validators

use super::{
    AnalysisBoundary, AnalysisFormat, AnalysisOmission, AnalysisStatus, AnalyzedArtifact,
    ArtifactAnalysis, ArtifactAnalysisOptions, ArtifactOrigin, ArtifactValidationState,
    EmbeddedDiscoveryLimits, EmbeddedFormat, EmbeddedValidationEvidence, FileRange, PngLimits,
    ValidationSummary, discover_embedded_objects_with_work, scan_file_signatures,
    zip::ZipArtifactLimits,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

// Two windows fit within the caller's in-memory input budget
const MAX_WINDOW_STEP_BYTES: usize = 4 * 1024 * 1024;
const HASH_TAIL_BYTES: usize = 64 * 1024;

/// Analyze bounded PNG and ZIP ranges while hashing the complete source stream
///
/// Only objects no larger than half the in-memory input limit, capped at 4 MiB, are
/// guaranteed to fit across a window boundary. Whole-source validation, recursive archive
/// expansion, and transformations are not performed, so the result is always partial.
/// The reader must begin at the first source byte and remain stable throughout the call.
///
/// # Errors
/// Returns an I/O error when the source length changes, reading fails, policy limits are
/// invalid, or bounded analysis storage cannot be allocated
pub fn analyze_artifacts_from_reader(
    reader: &mut impl Read,
    source_length: usize,
    options: ArtifactAnalysisOptions,
) -> io::Result<ArtifactAnalysis> {
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
    let mut state = RangeState::new(options, source_length);
    let mut source_hasher = Sha256::new();
    let mut read_bytes = 0_usize;
    let mut offset = 0_usize;

    // Hash each block once while keeping its bytes for the next overlapping window
    while read_bytes < source_length || !window.is_empty() {
        let additional = (source_length - read_bytes).min(window_capacity - window.len());
        if additional > 0 {
            let previous_length = window.len();
            window.resize(previous_length + additional, 0);
            let new_bytes = window
                .get_mut(previous_length..)
                .ok_or_else(|| io::Error::other("range window length is inconsistent"))?;
            reader.read_exact(new_bytes)?;
            source_hasher.update(new_bytes);
            read_bytes += additional;
        }
        if !state.can_inspect(window.len()) {
            // Once coverage stops, hash the remaining source in fixed-size blocks
            let mut tail = Vec::new();
            let tail_capacity = (source_length - read_bytes).min(HASH_TAIL_BYTES);
            tail.try_reserve_exact(tail_capacity)
                .map_err(io::Error::other)?;
            tail.resize(tail_capacity, 0);
            while read_bytes < source_length {
                let count = (source_length - read_bytes).min(tail.len());
                let part = tail
                    .get_mut(..count)
                    .ok_or_else(|| io::Error::other("hash buffer length is inconsistent"))?;
                reader.read_exact(part)?;
                source_hasher.update(part);
                read_bytes += count;
            }
            break;
        }
        state.inspect_window(&window, offset, step)?;
        // The overlap gives boundary-spanning objects another complete window
        let consumed = step.min(window.len());
        window.copy_within(consumed.., 0);
        window.truncate(window.len() - consumed);
        offset += consumed;
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source length changed while it was read",
        ));
    }
    Ok(state.finish(format!("{:x}", source_hasher.finalize()), step))
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
