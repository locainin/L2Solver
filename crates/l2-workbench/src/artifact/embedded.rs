use core::fmt;

use serde::{Deserialize, Serialize};

use super::zip::{
    ZipArtifactError, ZipArtifactLimits, ZipArtifactOmissionReason,
    inspect_zip_at_depth_with_operation_budget,
};
use super::{FileRange, PngError, PngLimits, PngReport, parse_png};

const ZIP_LOCAL_FILE_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
const ZIP_END_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP_END_FIXED_SIZE: usize = 22;

/// Resource policy for one embedded-object discovery pass
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedDiscoveryLimits {
    /// Maximum source positions scanned for markers and ZIP end boundaries
    ///
    /// PNG validation reads up to `png_limits.max_input_bytes` from each marker
    pub max_scan_bytes: usize,
    /// Maximum structural parser calls, including failed ZIP boundary attempts
    pub max_validation_attempts: usize,
    /// Maximum candidate results retained
    pub max_candidates: usize,
    /// Structural limits passed to the PNG parser
    pub png_limits: PngLimits,
    /// Archive limits passed to the ZIP parser
    pub zip_limits: ZipArtifactLimits,
    /// Shared ZIP expanded-byte budget across all candidate validation attempts
    pub max_zip_operation_expanded_bytes: usize,
}

/// Format selected by an embedded marker
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EmbeddedFormat {
    /// Portable Network Graphics
    Png,
    /// ZIP archive
    Zip,
}

/// Structural facts returned by the existing format validators
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmbeddedValidationEvidence {
    /// Checked PNG chunk layout and exact end marker
    Png {
        /// Number of chunks accepted by the structural parser
        chunk_count: usize,
        /// Exact source range of the IEND chunk
        iend_range: FileRange,
        /// Bytes after IEND in the original input
        trailing_range: Option<FileRange>,
    },
    /// Checked ZIP directory and member-work summary
    Zip {
        /// SHA-256 of the exact candidate archive bytes
        archive_sha256: String,
        /// Number of central-directory entries
        entry_count: usize,
        /// Successfully extracted expanded bytes
        expanded_byte_count: usize,
        /// Declared expanded bytes charged during validation
        expanded_work_byte_count: usize,
        /// Number of entries omitted by format or resource limits
        omitted_entry_count: usize,
    },
}

/// Why a marker candidate did not receive successful structural validation
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmbeddedValidationFailure {
    /// Existing PNG parser rejected the candidate
    Png(PngError),
    /// Existing ZIP parser rejected the candidate
    Zip(ZipArtifactError),
    /// The configured validation-attempt budget was exhausted
    ValidationAttemptsExhausted,
    /// The shared parser-work budget was exhausted before validation completed
    ValidationWorkExhausted,
    /// The configured scan budget ended before a usable ZIP boundary was found
    ScanBudgetExhausted,
    /// ZIP entry count exceeded the limit before the directory could be parsed
    ZipEntryCountLimit {
        /// Entry count declared by the archive
        count: usize,
        /// Maximum entry count permitted for structural parsing
        maximum: usize,
    },
}

/// Marker candidate with the range considered and its structural result
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedCandidate {
    /// Candidate format selected by its marker bytes
    pub format: EmbeddedFormat,
    /// Start offset of the marker in the supplied input
    pub offset: usize,
    /// Exact object range when validation succeeds; otherwise the range considered
    pub range: FileRange,
    /// Structural evidence or the reason validation did not succeed
    pub validation: Result<EmbeddedValidationEvidence, EmbeddedValidationFailure>,
}

/// Candidates omitted because a configured discovery budget was reached
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EmbeddedDiscoveryOmissions {
    /// Marker candidates not retained after reaching the output limit
    pub output_candidate_count: usize,
    /// Retained marker candidates without a complete validation attempt
    pub unvalidated_candidate_count: usize,
    /// ZIP candidates stopped before directory parsing by the entry-count limit
    pub zip_entry_count_limited: usize,
    /// Input bytes beyond the scan limit
    pub unscanned_range: Option<FileRange>,
}

/// Embedded candidates and explicit work/output omissions
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedDiscoveryReport {
    /// Marker candidates in source order
    pub candidates: Vec<EmbeddedCandidate>,
    /// Input range searched for marker bytes
    pub scanned_range: FileRange,
    /// Number of structural validator calls made
    pub validation_attempt_count: usize,
    /// Candidate input bytes reserved for structural parser work
    pub validation_input_bytes: usize,
    /// ZIP expanded bytes consumed across successful and failed validation attempts
    pub zip_work_bytes: usize,
    /// Candidates and input omitted by configured budgets
    pub omissions: EmbeddedDiscoveryOmissions,
}

/// Failure while allocating bounded discovery metadata
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedDiscoveryError {
    /// A bounded metadata allocation could not be reserved
    AllocationFailure,
}

impl fmt::Display for EmbeddedDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailure => formatter.write_str("embedded discovery allocation failed"),
        }
    }
}

impl std::error::Error for EmbeddedDiscoveryError {}

#[derive(Clone, Copy)]
struct MarkerCandidate {
    format: EmbeddedFormat,
    offset: usize,
}

#[derive(Clone, Copy)]
struct ZipBoundary {
    offset: usize,
    end: usize,
}

struct MarkerScan {
    markers: Vec<MarkerCandidate>,
    boundaries: Vec<ZipBoundary>,
    last_omitted_boundary_offset: Option<usize>,
    scan_length: usize,
    omissions: EmbeddedDiscoveryOmissions,
}

struct ZipValidationContext<'a> {
    boundaries: &'a [ZipBoundary],
    last_omitted_boundary_offset: Option<usize>,
    scan_incomplete: bool,
    scan_end: usize,
    limits: ZipArtifactLimits,
    maximum_attempts: usize,
    attempt_count: &'a mut usize,
    work_remaining: &'a mut usize,
    validation_input_bytes: &'a mut usize,
    expanded_remaining: &'a mut usize,
}

enum ZipBoundaryResult {
    Validated(EmbeddedValidationEvidence),
    Rejected(ZipArtifactError),
    Omitted(EmbeddedValidationFailure),
    MissingBytes,
}

/// Find bounded PNG and ZIP candidates in an arbitrary byte slice
///
/// Every marker candidate is checked by the existing format parser before it
/// receives success evidence. DER is not scanned because it has no universal prefix
/// ZIP end records provide candidate boundaries, while the ZIP parser validates
/// their directory, members, and exact end position
///
/// # Errors
/// Returns an error if bounded discovery metadata cannot be allocated
pub fn discover_embedded_objects(
    bytes: &[u8],
    limits: EmbeddedDiscoveryLimits,
) -> Result<EmbeddedDiscoveryReport, EmbeddedDiscoveryError> {
    discover_embedded_objects_with_work(bytes, limits, usize::MAX)
}

/// Find bounded embedded candidates while reserving parser input and ZIP output work
///
/// # Errors
/// Returns an error if bounded discovery metadata cannot be allocated
pub fn discover_embedded_objects_with_work(
    bytes: &[u8],
    limits: EmbeddedDiscoveryLimits,
    max_work_bytes: usize,
) -> Result<EmbeddedDiscoveryReport, EmbeddedDiscoveryError> {
    discover_embedded_objects_with_work_and_skip_start(bytes, limits, max_work_bytes, None)
}

pub(super) fn discover_embedded_objects_with_work_and_skip_start(
    bytes: &[u8],
    limits: EmbeddedDiscoveryLimits,
    max_work_bytes: usize,
    skip_start_format: Option<EmbeddedFormat>,
) -> Result<EmbeddedDiscoveryReport, EmbeddedDiscoveryError> {
    let scan = scan_markers(bytes, limits, skip_start_format)?;
    validate_markers(bytes, limits, scan, max_work_bytes)
}

fn validate_markers(
    bytes: &[u8],
    limits: EmbeddedDiscoveryLimits,
    scan: MarkerScan,
    max_work_bytes: usize,
) -> Result<EmbeddedDiscoveryReport, EmbeddedDiscoveryError> {
    let MarkerScan {
        markers,
        boundaries,
        last_omitted_boundary_offset,
        scan_length,
        mut omissions,
    } = scan;
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(markers.len())
        .map_err(|_| EmbeddedDiscoveryError::AllocationFailure)?;
    let mut validation_attempt_count = 0_usize;
    let mut work_remaining = max_work_bytes;
    let mut validation_input_bytes = 0_usize;
    let initial_zip_budget = limits.max_zip_operation_expanded_bytes.min(max_work_bytes);
    let mut zip_expanded_remaining = initial_zip_budget;

    // The validators receive only the caller-selected per-format and shared budgets
    for marker in markers {
        let candidate = match marker.format {
            EmbeddedFormat::Png => validate_png_candidate(
                bytes,
                marker.offset,
                limits.png_limits,
                limits.max_validation_attempts,
                &mut validation_attempt_count,
                &mut work_remaining,
                &mut validation_input_bytes,
            ),
            EmbeddedFormat::Zip => validate_zip_candidate(
                bytes,
                marker.offset,
                &mut ZipValidationContext {
                    boundaries: &boundaries,
                    last_omitted_boundary_offset,
                    scan_incomplete: omissions.unscanned_range.is_some(),
                    scan_end: scan_length,
                    limits: limits.zip_limits,
                    maximum_attempts: limits.max_validation_attempts,
                    attempt_count: &mut validation_attempt_count,
                    work_remaining: &mut work_remaining,
                    validation_input_bytes: &mut validation_input_bytes,
                    expanded_remaining: &mut zip_expanded_remaining,
                },
            ),
        };
        if matches!(
            candidate.validation,
            Err(EmbeddedValidationFailure::ValidationAttemptsExhausted
                | EmbeddedValidationFailure::ValidationWorkExhausted
                | EmbeddedValidationFailure::ScanBudgetExhausted
                | EmbeddedValidationFailure::ZipEntryCountLimit { .. })
        ) {
            omissions.unvalidated_candidate_count += 1;
        }
        if matches!(
            candidate.validation,
            Err(EmbeddedValidationFailure::ZipEntryCountLimit { .. })
        ) {
            omissions.zip_entry_count_limited += 1;
        }
        candidates.push(candidate);
    }

    Ok(EmbeddedDiscoveryReport {
        candidates,
        scanned_range: FileRange {
            offset: 0,
            length: scan_length,
        },
        validation_attempt_count,
        validation_input_bytes,
        zip_work_bytes: initial_zip_budget - zip_expanded_remaining,
        omissions,
    })
}

fn scan_markers(
    bytes: &[u8],
    limits: EmbeddedDiscoveryLimits,
    skip_start_format: Option<EmbeddedFormat>,
) -> Result<MarkerScan, EmbeddedDiscoveryError> {
    let scan_length = bytes.len().min(limits.max_scan_bytes);
    let mut markers = Vec::new();
    let marker_capacity = limits.max_candidates.min(scan_length);
    markers
        .try_reserve_exact(marker_capacity)
        .map_err(|_| EmbeddedDiscoveryError::AllocationFailure)?;

    let mut boundaries = Vec::new();
    let boundary_capacity = limits
        .max_validation_attempts
        .min(scan_length / ZIP_END_SIGNATURE.len());
    boundaries
        .try_reserve_exact(boundary_capacity)
        .map_err(|_| EmbeddedDiscoveryError::AllocationFailure)?;

    let mut omissions = EmbeddedDiscoveryOmissions {
        unscanned_range: (scan_length < bytes.len()).then_some(FileRange {
            offset: scan_length,
            length: bytes.len() - scan_length,
        }),
        ..EmbeddedDiscoveryOmissions::default()
    };
    let mut last_omitted_boundary_offset = None;

    // Each position is checked once for the supported format prefixes
    for offset in 0..scan_length {
        if !(offset == 0 && skip_start_format == Some(EmbeddedFormat::Png))
            && marker_matches(bytes, offset, &super::PNG_SIGNATURE, scan_length)
        {
            retain_marker(
                &mut markers,
                &mut omissions,
                limits.max_candidates,
                MarkerCandidate {
                    format: EmbeddedFormat::Png,
                    offset,
                },
            );
        }

        if !(offset == 0 && skip_start_format == Some(EmbeddedFormat::Zip))
            && marker_matches(bytes, offset, ZIP_LOCAL_FILE_SIGNATURE, scan_length)
        {
            retain_marker(
                &mut markers,
                &mut omissions,
                limits.max_candidates,
                MarkerCandidate {
                    format: EmbeddedFormat::Zip,
                    offset,
                },
            );
        }

        if marker_matches(bytes, offset, ZIP_END_SIGNATURE, scan_length)
            && let Some(end) = zip_end_boundary(bytes, offset, scan_length)
        {
            if !(offset == 0 && skip_start_format == Some(EmbeddedFormat::Zip))
                && empty_zip_fields(bytes, offset, scan_length)
            {
                retain_marker(
                    &mut markers,
                    &mut omissions,
                    limits.max_candidates,
                    MarkerCandidate {
                        format: EmbeddedFormat::Zip,
                        offset,
                    },
                );
            }
            if boundaries.len() < boundary_capacity {
                boundaries.push(ZipBoundary { offset, end });
            } else {
                last_omitted_boundary_offset = Some(offset);
            }
        }
    }

    Ok(MarkerScan {
        markers,
        boundaries,
        last_omitted_boundary_offset,
        scan_length,
        omissions,
    })
}

fn marker_matches(bytes: &[u8], offset: usize, marker: &[u8], scan_length: usize) -> bool {
    offset
        .checked_add(marker.len())
        .filter(|end| *end <= scan_length)
        .and_then(|end| bytes.get(offset..end))
        .is_some_and(|candidate| candidate == marker)
}

fn retain_marker(
    markers: &mut Vec<MarkerCandidate>,
    omissions: &mut EmbeddedDiscoveryOmissions,
    maximum: usize,
    candidate: MarkerCandidate,
) {
    if markers.len() >= maximum {
        omissions.output_candidate_count += 1;
        return;
    }
    // One recognized marker can occur at each scanned source position
    markers.push(candidate);
}

fn zip_end_boundary(bytes: &[u8], offset: usize, scan_length: usize) -> Option<usize> {
    let comment_length_offset = offset.checked_add(20)?;
    let comment_length_end = comment_length_offset.checked_add(2)?;
    if comment_length_end > scan_length {
        return None;
    }
    let comment_length_bytes = bytes.get(comment_length_offset..comment_length_end)?;
    let comment_length = usize::from(u16::from_le_bytes([
        *comment_length_bytes.first()?,
        *comment_length_bytes.get(1)?,
    ]));
    let end = offset
        .checked_add(ZIP_END_FIXED_SIZE)?
        .checked_add(comment_length)?;
    (end <= scan_length).then_some(end)
}

fn empty_zip_fields(bytes: &[u8], offset: usize, scan_length: usize) -> bool {
    let Some(fields_start) = offset.checked_add(4) else {
        return false;
    };
    let Some(fields_end) = offset.checked_add(20) else {
        return false;
    };
    fields_end <= scan_length
        && bytes
            .get(fields_start..fields_end)
            .is_some_and(|fields| fields.iter().all(|byte| *byte == 0))
}

fn validate_png_candidate(
    bytes: &[u8],
    offset: usize,
    limits: PngLimits,
    maximum_attempts: usize,
    attempt_count: &mut usize,
    work_remaining: &mut usize,
    validation_input_bytes: &mut usize,
) -> EmbeddedCandidate {
    let available_length = bytes.len() - offset;
    let probe_length = available_length.min(limits.max_input_bytes);
    let probe_end = offset + probe_length;
    let probe_range = FileRange {
        offset,
        length: probe_length,
    };
    if *attempt_count >= maximum_attempts {
        return EmbeddedCandidate {
            format: EmbeddedFormat::Png,
            offset,
            range: probe_range,
            validation: Err(EmbeddedValidationFailure::ValidationAttemptsExhausted),
        };
    }
    if probe_length > *work_remaining {
        return EmbeddedCandidate {
            format: EmbeddedFormat::Png,
            offset,
            range: probe_range,
            validation: Err(EmbeddedValidationFailure::ValidationWorkExhausted),
        };
    }
    *attempt_count += 1;
    *work_remaining -= probe_length;
    *validation_input_bytes += probe_length;

    let Some(candidate_bytes) = bytes.get(offset..probe_end) else {
        return EmbeddedCandidate {
            format: EmbeddedFormat::Png,
            offset,
            range: probe_range,
            validation: Err(EmbeddedValidationFailure::Png(PngError::TruncatedChunk)),
        };
    };
    match parse_png(candidate_bytes, limits) {
        Ok(report) => png_candidate(offset, bytes.len(), probe_range, &report),
        Err(error) => EmbeddedCandidate {
            format: EmbeddedFormat::Png,
            offset,
            range: probe_range,
            validation: Err(EmbeddedValidationFailure::Png(error)),
        },
    }
}

fn png_candidate(
    offset: usize,
    input_length: usize,
    probe_range: FileRange,
    report: &PngReport<'_>,
) -> EmbeddedCandidate {
    let Some(iend_chunk) = report.chunks.last() else {
        return EmbeddedCandidate {
            format: EmbeddedFormat::Png,
            offset,
            range: probe_range,
            validation: Err(EmbeddedValidationFailure::Png(PngError::MissingIend)),
        };
    };
    let Some(iend_offset) = offset.checked_add(iend_chunk.chunk_range.offset) else {
        return png_range_failure(offset, probe_range);
    };
    let Some(object_end) = iend_offset.checked_add(iend_chunk.chunk_range.length) else {
        return png_range_failure(offset, probe_range);
    };
    let Some(trailing_length) = input_length.checked_sub(object_end) else {
        return png_range_failure(offset, probe_range);
    };
    let iend_range = FileRange {
        offset: iend_offset,
        length: iend_chunk.chunk_range.length,
    };
    EmbeddedCandidate {
        format: EmbeddedFormat::Png,
        offset,
        range: FileRange {
            offset,
            length: object_end - offset,
        },
        validation: Ok(EmbeddedValidationEvidence::Png {
            chunk_count: report.chunks.len(),
            iend_range,
            trailing_range: (trailing_length > 0).then_some(FileRange {
                offset: object_end,
                length: trailing_length,
            }),
        }),
    }
}

const fn png_range_failure(offset: usize, probe_range: FileRange) -> EmbeddedCandidate {
    EmbeddedCandidate {
        format: EmbeddedFormat::Png,
        offset,
        range: probe_range,
        validation: Err(EmbeddedValidationFailure::Png(PngError::TruncatedChunk)),
    }
}

fn validate_zip_candidate(
    bytes: &[u8],
    offset: usize,
    context: &mut ZipValidationContext<'_>,
) -> EmbeddedCandidate {
    let mut last_candidate_range = FileRange { offset, length: 0 };
    let mut last_error = None;

    // Earlier end records are tried first to preserve exact adjacent archive ranges
    let first_boundary = context
        .boundaries
        .partition_point(|boundary| boundary.offset < offset);
    let future_boundaries = context.boundaries.get(first_boundary..).unwrap_or(&[]);

    // Only candidate ends after this marker need structural checks
    for boundary in future_boundaries {
        last_candidate_range = FileRange {
            offset,
            length: boundary.end - offset,
        };
        match inspect_zip_boundary(bytes, offset, boundary.end, context) {
            ZipBoundaryResult::Validated(evidence) => {
                return EmbeddedCandidate {
                    format: EmbeddedFormat::Zip,
                    offset,
                    range: last_candidate_range,
                    validation: Ok(evidence),
                };
            }
            ZipBoundaryResult::Rejected(error) => last_error = Some(error),
            ZipBoundaryResult::Omitted(reason) => {
                return zip_failure(offset, last_candidate_range, reason);
            }
            ZipBoundaryResult::MissingBytes => {
                last_error = Some(ZipArtifactError::InvalidArchive);
            }
        }
    }

    if context
        .last_omitted_boundary_offset
        .is_some_and(|boundary_offset| boundary_offset >= offset)
    {
        return zip_failure(
            offset,
            range_through_scan(offset, context.scan_end),
            EmbeddedValidationFailure::ValidationAttemptsExhausted,
        );
    }
    if context.scan_incomplete {
        return zip_failure(
            offset,
            range_through_scan(offset, context.scan_end),
            EmbeddedValidationFailure::ScanBudgetExhausted,
        );
    }
    if let Some(error) = last_error {
        return zip_failure(
            offset,
            last_candidate_range,
            EmbeddedValidationFailure::Zip(error),
        );
    }

    zip_failure(
        offset,
        range_through_scan(offset, context.scan_end),
        EmbeddedValidationFailure::Zip(ZipArtifactError::InvalidArchive),
    )
}

fn inspect_zip_boundary(
    bytes: &[u8],
    offset: usize,
    end: usize,
    context: &mut ZipValidationContext<'_>,
) -> ZipBoundaryResult {
    if *context.attempt_count >= context.maximum_attempts {
        return ZipBoundaryResult::Omitted(EmbeddedValidationFailure::ValidationAttemptsExhausted);
    }
    let Some(candidate_bytes) = bytes.get(offset..end) else {
        return ZipBoundaryResult::MissingBytes;
    };
    if candidate_bytes.len() > *context.work_remaining {
        return ZipBoundaryResult::Omitted(EmbeddedValidationFailure::ValidationWorkExhausted);
    }
    *context.work_remaining -= candidate_bytes.len();
    *context.validation_input_bytes += candidate_bytes.len();
    *context.attempt_count += 1;
    let operation_budget = (*context.expanded_remaining).min(*context.work_remaining);
    let mut operation_remaining = operation_budget;
    let result = inspect_zip_at_depth_with_operation_budget(
        candidate_bytes,
        context.limits,
        0,
        &mut operation_remaining,
    );
    let consumed = operation_budget - operation_remaining;
    *context.expanded_remaining -= consumed;
    *context.work_remaining -= consumed;

    match result {
        Ok(report)
            if report.omissions.iter().any(|omission| {
                matches!(omission.reason, ZipArtifactOmissionReason::EntryCountLimit)
            }) =>
        {
            ZipBoundaryResult::Omitted(EmbeddedValidationFailure::ZipEntryCountLimit {
                count: report.entry_count,
                maximum: context.limits.max_entries,
            })
        }
        Ok(report) => ZipBoundaryResult::Validated(EmbeddedValidationEvidence::Zip {
            archive_sha256: report.archive_sha256,
            entry_count: report.entry_count,
            expanded_byte_count: report.expanded_byte_count,
            expanded_work_byte_count: report.expanded_work_byte_count,
            omitted_entry_count: report.omitted_entry_count,
        }),
        Err(error) => ZipBoundaryResult::Rejected(error),
    }
}

const fn range_through_scan(offset: usize, scan_end: usize) -> FileRange {
    FileRange {
        offset,
        length: scan_end - offset,
    }
}

const fn zip_failure(
    offset: usize,
    range: FileRange,
    failure: EmbeddedValidationFailure,
) -> EmbeddedCandidate {
    EmbeddedCandidate {
        format: EmbeddedFormat::Zip,
        offset,
        range,
        validation: Err(failure),
    }
}
