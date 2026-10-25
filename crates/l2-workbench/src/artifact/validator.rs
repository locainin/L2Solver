use core::fmt;

use super::{
    ArtifactError, ArtifactFormat, ArtifactReport, DerError, DerLimits, DerReport, FileRange,
    MAX_DER_DEPTH, PNG_SIGNATURE, PngError, PngLimits, PngReport, candidate_executable_format,
    parse_der, parse_png,
};
use super::{
    scan_file_signatures,
    zip::{
        ZipArtifactError, ZipArtifactLimits, ZipArtifactOmissionReason, ZipArtifactReport,
        inspect_zip_with_limits,
    },
};

/// Format selected for structural artifact validation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactValidationFormat {
    /// Canonical DER value
    Der,
    /// Executable and linkable format
    Elf,
    /// Portable Network Executable image
    PortableExecutable,
    /// Portable Network Graphics image
    Png,
    /// ZIP archive
    Zip,
}

/// Boundary evidence supplied by the selected existing parser
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactBoundaryEvidence {
    /// PNG parser reached IEND; image completeness and decoding are outside its checks
    PngIend,
    /// DER parser accepted its supported subset and the encoded length consumed the range
    DerEncodedLength,
    /// ZIP parser checked the archive end record and directory at the selected range end
    ZipEndRecord,
}

/// Parsed facts retained from the existing format-specific parser
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactStructure<'a> {
    /// DER tags and values tied to the supplied bytes
    Der(DerReport),
    /// PE or ELF header, table, and mapping facts
    Executable(ArtifactReport),
    /// PNG chunks and their exact source ranges
    Png(PngReport<'a>),
    /// ZIP directory, member metadata, and any member-level omissions
    Zip(ZipArtifactReport),
}

/// Typed structural rejection returned by an existing parser
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactValidationFailure {
    /// DER parser rejection
    Der(DerError),
    /// PNG parser rejection
    Png(PngError),
    /// ZIP parser rejection
    Zip(ZipArtifactError),
    /// PE or ELF parser rejection
    Executable(ArtifactError),
}

/// Why validation work or report data was omitted by a resource limit
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactResourceOmissionReason {
    /// The selected byte slice exceeded an input ceiling
    InputTooLarge { length: usize, maximum: usize },
    /// The PNG parser reached its chunk-count ceiling
    PngChunkLimit { maximum: usize },
    /// A DER parser limit stopped structural validation
    DerObjectLimit { length: usize, maximum: usize },
    /// A DER nesting limit stopped structural validation
    DerDepthLimit { maximum: usize },
    /// A DER node limit stopped structural validation
    DerNodeLimit { maximum: usize },
    /// A ZIP archive exceeded its parser input ceiling
    ZipArchiveLimit { length: usize, maximum: usize },
    /// ZIP directory validation was skipped after its entry-count ceiling
    ZipEntryLimit { count: usize, maximum: usize },
    /// A parser could not reserve bounded report storage
    AllocationFailure,
    /// The ZIP entry count cannot fit the current platform's report field
    ZipEntryCountOutOfRange { count: u64 },
    /// The executable parser reached its image-size ceiling
    ExecutableSizeLimit { length: usize, maximum: usize },
    /// The executable parser reached a table-count ceiling
    ExecutableTableLimit { field: &'static str, maximum: usize },
    /// A parser rejected the configured limits before examining the bytes
    InvalidParserPolicy { format: ArtifactValidationFormat },
}

/// One deterministic result from an artifact validation attempt
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactValidationOutcome<'a> {
    /// Existing parser checks passed and established their exact selected range
    /// This is structural evidence, not a claim of complete format conformance or safety
    Validated {
        /// Format accepted by the structural parser
        format: ArtifactValidationFormat,
        /// Exact source range accepted by the parser, relative to this input
        range: FileRange,
        /// Parser evidence that established the range boundary
        boundary: ArtifactBoundaryEvidence,
        /// Format-specific structural report
        structure: ArtifactStructure<'a>,
    },
    /// PE or ELF structures parsed, but no format-defined whole-file end was proven
    BoundaryUnproven {
        /// Format reported by the existing executable parser
        format: ArtifactValidationFormat,
        /// Caller-supplied byte range inspected by the parser
        input_range: FileRange,
        /// Format-specific static inspection report
        structure: ArtifactStructure<'a>,
    },
    /// A selected candidate failed the existing structural parser
    Rejected {
        /// Format candidate supplied or selected for parsing
        format: ArtifactValidationFormat,
        /// Complete input range considered by the parser
        input_range: FileRange,
        /// Typed parser rejection
        reason: ArtifactValidationFailure,
    },
    /// No enabled validator had an applicable format candidate
    Unsupported {
        /// Complete input range considered by automatic detection
        input_range: FileRange,
    },
    /// A resource or output budget prevented a conclusive validation result
    Omitted {
        /// Candidate format, when detection or explicit selection identified one
        format: Option<ArtifactValidationFormat>,
        /// Complete input range considered
        input_range: FileRange,
        /// Budget or allocation reason
        reason: ArtifactResourceOmissionReason,
    },
}

/// Caller-controlled budgets for artifact validation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactValidationPolicy {
    /// Largest source slice dispatched to any parser
    pub max_input_bytes: usize,
    /// Structural limits passed to the existing PNG parser
    pub png_limits: PngLimits,
    /// Object, depth, inventory, and preview limits passed to the DER parser
    pub der_limits: DerLimits,
    /// Archive and expanded-member limits passed to the ZIP parser
    pub zip_limits: ZipArtifactLimits,
}

impl Default for ArtifactValidationPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: super::zip::MAX_ZIP_ARCHIVE_BYTES,
            png_limits: PngLimits::default(),
            der_limits: DerLimits::default(),
            zip_limits: ZipArtifactLimits::default(),
        }
    }
}

/// Invalid resource policy that cannot be passed to the existing parsers
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactValidationPolicyError {
    /// The named policy field must be positive or within its supported range
    InvalidLimit { field: &'static str },
}

impl fmt::Display for ArtifactValidationPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "artifact validation limit {field} is invalid")
            }
        }
    }
}

impl std::error::Error for ArtifactValidationPolicyError {}

/// Reusable bounded dispatcher over the existing artifact parsers
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArtifactValidator {
    policy: ArtifactValidationPolicy,
}

impl ArtifactValidator {
    /// Build a validator with an explicit, checked resource policy
    ///
    /// # Errors
    /// Returns an error when a configured parser limit is invalid
    pub fn new(policy: ArtifactValidationPolicy) -> Result<Self, ArtifactValidationPolicyError> {
        validate_policy(policy)?;
        Ok(Self { policy })
    }

    /// Select a validator from supported leading signatures and validate the input
    ///
    /// Detection uses exact signatures only to select parsers. A match does not
    /// itself count as validation. DER requires [`Self::validate_as`] because it
    /// has no reliable file signature. Candidate order is PNG, executable, ZIP.
    /// The first exact-boundary validation wins; when none succeeds, resource
    /// omission takes precedence over boundary-unproven executable inspection,
    /// which takes precedence over parser rejection
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use l2_workbench::artifact::ArtifactValidator;
    ///
    /// let validator = ArtifactValidator::default();
    /// let result = validator.validate(b"arbitrary source bytes");
    /// # let _ = result;
    /// ```
    #[must_use]
    pub fn validate<'a>(&self, bytes: &'a [u8]) -> ArtifactValidationOutcome<'a> {
        let input_range = complete_range(bytes);
        if bytes.len() > self.policy.max_input_bytes {
            return omitted_input(None, input_range, bytes.len(), self.policy.max_input_bytes);
        }

        let executable = candidate_executable_format(bytes).map(validation_format);
        let zip_candidate = has_zip_signature(bytes) || super::zip::has_zip_end_record(bytes);
        let candidates = [
            bytes
                .starts_with(&PNG_SIGNATURE)
                .then_some(ArtifactValidationFormat::Png),
            executable,
            zip_candidate.then_some(ArtifactValidationFormat::Zip),
        ];
        let mut first_unproven = None;
        let mut first_omission = None;
        let mut first_rejection = None;

        for format in candidates.into_iter().flatten() {
            match self.validate_as(format, bytes) {
                outcome @ ArtifactValidationOutcome::Validated { .. } => return outcome,
                outcome @ ArtifactValidationOutcome::BoundaryUnproven { .. } => {
                    if first_unproven.is_none() {
                        first_unproven = Some(outcome);
                    }
                }
                outcome @ ArtifactValidationOutcome::Omitted { .. } => {
                    if first_omission.is_none() {
                        first_omission = Some(outcome);
                    }
                }
                outcome @ ArtifactValidationOutcome::Rejected { .. } => {
                    if first_rejection.is_none() {
                        first_rejection = Some(outcome);
                    }
                }
                ArtifactValidationOutcome::Unsupported { .. } => {}
            }
        }

        first_omission
            .or(first_unproven)
            .or(first_rejection)
            .unwrap_or(ArtifactValidationOutcome::Unsupported { input_range })
    }

    /// Validate the complete input as one explicitly selected format
    ///
    /// This is required for DER and is also available when an upstream format
    /// decision needs an exact parser result without using automatic detection.
    /// PE and ELF success remains boundary-unproven
    #[must_use]
    pub fn validate_as<'a>(
        &self,
        format: ArtifactValidationFormat,
        bytes: &'a [u8],
    ) -> ArtifactValidationOutcome<'a> {
        let input_range = complete_range(bytes);
        if bytes.len() > self.policy.max_input_bytes {
            return omitted_input(
                Some(format),
                input_range,
                bytes.len(),
                self.policy.max_input_bytes,
            );
        }

        match format {
            ArtifactValidationFormat::Der => {
                match parse_der(bytes, input_range, self.policy.der_limits) {
                    Ok(report) => ArtifactValidationOutcome::Validated {
                        format,
                        range: report.boundary_range,
                        boundary: ArtifactBoundaryEvidence::DerEncodedLength,
                        structure: ArtifactStructure::Der(report),
                    },
                    Err(error) => classify_der_error(format, input_range, error),
                }
            }
            ArtifactValidationFormat::Png => match parse_png(bytes, self.policy.png_limits) {
                Ok(report) => png_result(report),
                Err(error) => classify_png_error(format, input_range, error),
            },
            ArtifactValidationFormat::Zip => {
                match inspect_zip_with_limits(bytes, self.policy.zip_limits) {
                    Ok(report) => zip_result(format, input_range, self.policy.zip_limits, report),
                    Err(error) => classify_zip_error(format, input_range, error),
                }
            }
            ArtifactValidationFormat::Elf => {
                validate_executable(format, ArtifactFormat::Elf, bytes, input_range)
            }
            ArtifactValidationFormat::PortableExecutable => validate_executable(
                format,
                ArtifactFormat::PortableExecutable,
                bytes,
                input_range,
            ),
        }
    }
}

fn validate_policy(policy: ArtifactValidationPolicy) -> Result<(), ArtifactValidationPolicyError> {
    for (field, valid) in [
        ("input bytes", policy.max_input_bytes > 0),
        ("PNG input bytes", policy.png_limits.max_input_bytes > 0),
        ("PNG chunks", policy.png_limits.max_chunks > 0),
        ("DER object bytes", policy.der_limits.max_object_bytes > 0),
        ("DER depth", policy.der_limits.max_depth <= MAX_DER_DEPTH),
        ("DER nodes", policy.der_limits.max_nodes > 0),
        ("ZIP archive bytes", policy.zip_limits.max_archive_bytes > 0),
        ("ZIP entries", policy.zip_limits.max_entries > 0),
        (
            "ZIP entry expanded bytes",
            policy.zip_limits.max_entry_expanded_bytes > 0,
        ),
    ] {
        if !valid {
            return Err(ArtifactValidationPolicyError::InvalidLimit { field });
        }
    }
    Ok(())
}

const fn validation_format(format: ArtifactFormat) -> ArtifactValidationFormat {
    match format {
        ArtifactFormat::Elf => ArtifactValidationFormat::Elf,
        ArtifactFormat::PortableExecutable => ArtifactValidationFormat::PortableExecutable,
    }
}

fn has_zip_signature(bytes: &[u8]) -> bool {
    // The catalogue scan is kept to the prefix because auto-detection is a file-start check
    let prefix_length = bytes.len().min(8);
    let Some(prefix) = bytes.get(..prefix_length) else {
        return false;
    };
    scan_file_signatures(prefix)
        .matches
        .iter()
        .any(|signature| signature.possible_formats.contains(&"zip_container"))
}

const fn complete_range(bytes: &[u8]) -> FileRange {
    FileRange {
        offset: 0,
        length: bytes.len(),
    }
}

const fn omitted_input<'a>(
    format: Option<ArtifactValidationFormat>,
    input_range: FileRange,
    length: usize,
    maximum: usize,
) -> ArtifactValidationOutcome<'a> {
    ArtifactValidationOutcome::Omitted {
        format,
        input_range,
        reason: ArtifactResourceOmissionReason::InputTooLarge { length, maximum },
    }
}

const fn classify_der_error<'a>(
    format: ArtifactValidationFormat,
    input_range: FileRange,
    error: DerError,
) -> ArtifactValidationOutcome<'a> {
    match error {
        DerError::ObjectTooLarge { length, maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::DerObjectLimit { length, maximum },
        },
        DerError::DepthLimitExceeded { maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::DerDepthLimit { maximum },
        },
        DerError::NodeLimitExceeded { maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::DerNodeLimit { maximum },
        },
        DerError::InvalidLimits => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::InvalidParserPolicy { format },
        },
        error @ (DerError::InvalidBoundary { .. } | DerError::InvalidDer) => {
            ArtifactValidationOutcome::Rejected {
                format,
                input_range,
                reason: ArtifactValidationFailure::Der(error),
            }
        }
    }
}

const fn classify_png_error<'a>(
    format: ArtifactValidationFormat,
    input_range: FileRange,
    error: PngError,
) -> ArtifactValidationOutcome<'a> {
    match error {
        PngError::InputTooLarge { length, maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::InputTooLarge { length, maximum },
        },
        PngError::TooManyChunks { maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::PngChunkLimit { maximum },
        },
        PngError::InvalidLimits => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::InvalidParserPolicy { format },
        },
        error @ (PngError::InvalidSignature
        | PngError::TruncatedChunk
        | PngError::InvalidChunkType { .. }
        | PngError::InvalidChecksum { .. }
        | PngError::IhdrNotFirst
        | PngError::RepeatedIhdr
        | PngError::InvalidIhdrLength
        | PngError::InvalidIendLength
        | PngError::MissingIend) => ArtifactValidationOutcome::Rejected {
            format,
            input_range,
            reason: ArtifactValidationFailure::Png(error),
        },
    }
}

const fn classify_zip_error<'a>(
    format: ArtifactValidationFormat,
    input_range: FileRange,
    error: ZipArtifactError,
) -> ArtifactValidationOutcome<'a> {
    match error {
        ZipArtifactError::ArchiveTooLarge { length, maximum } => {
            ArtifactValidationOutcome::Omitted {
                format: Some(format),
                input_range,
                reason: ArtifactResourceOmissionReason::ZipArchiveLimit { length, maximum },
            }
        }
        ZipArtifactError::EntryCountOutOfRange { count } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::ZipEntryCountOutOfRange { count },
        },
        ZipArtifactError::AllocationFailure => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::AllocationFailure,
        },
        ZipArtifactError::InvalidLimits { .. } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::InvalidParserPolicy { format },
        },
        error @ (ZipArtifactError::InvalidArchive | ZipArtifactError::AmbiguousEndRecords) => {
            ArtifactValidationOutcome::Rejected {
                format,
                input_range,
                reason: ArtifactValidationFailure::Zip(error),
            }
        }
    }
}

const fn classify_executable_error<'a>(
    format: ArtifactValidationFormat,
    input_range: FileRange,
    error: ArtifactError,
) -> ArtifactValidationOutcome<'a> {
    match error {
        ArtifactError::ArtifactTooLarge { length, maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::ExecutableSizeLimit { length, maximum },
        },
        ArtifactError::LimitExceeded { field, maximum } => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::ExecutableTableLimit { field, maximum },
        },
        ArtifactError::UnsupportedFormat => ArtifactValidationOutcome::Unsupported { input_range },
        error @ (ArtifactError::InvalidRange { .. }
        | ArtifactError::InvalidHeader { .. }
        | ArtifactError::InvalidName { .. }
        | ArtifactError::UnmappedAddress { .. }
        | ArtifactError::AmbiguousAddress { .. }
        | ArtifactError::SourceHashMismatch
        | ArtifactError::R2JsonTooLarge { .. }
        | ArtifactError::InvalidR2Json { .. }) => ArtifactValidationOutcome::Rejected {
            format,
            input_range,
            reason: ArtifactValidationFailure::Executable(error),
        },
    }
}

fn validate_executable(
    format: ArtifactValidationFormat,
    expected: ArtifactFormat,
    bytes: &[u8],
    input_range: FileRange,
) -> ArtifactValidationOutcome<'_> {
    if candidate_executable_format(bytes) != Some(expected) {
        return ArtifactValidationOutcome::Unsupported { input_range };
    }
    match super::inspect(bytes) {
        Ok(report) => ArtifactValidationOutcome::BoundaryUnproven {
            format,
            input_range,
            structure: ArtifactStructure::Executable(report),
        },
        Err(error) => classify_executable_error(format, input_range, error),
    }
}

const fn png_result(report: PngReport<'_>) -> ArtifactValidationOutcome<'_> {
    ArtifactValidationOutcome::Validated {
        format: ArtifactValidationFormat::Png,
        range: FileRange {
            offset: 0,
            length: report.bytes_after_iend_range.offset,
        },
        boundary: ArtifactBoundaryEvidence::PngIend,
        structure: ArtifactStructure::Png(report),
    }
}

fn zip_result<'a>(
    format: ArtifactValidationFormat,
    input_range: FileRange,
    limits: ZipArtifactLimits,
    report: ZipArtifactReport,
) -> ArtifactValidationOutcome<'a> {
    if report
        .omissions
        .iter()
        .any(|omission| matches!(omission.reason, ZipArtifactOmissionReason::EntryCountLimit))
    {
        return ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::ZipEntryLimit {
                count: report.entry_count,
                maximum: limits.max_entries,
            },
        };
    }
    ArtifactValidationOutcome::Validated {
        format,
        range: input_range,
        boundary: ArtifactBoundaryEvidence::ZipEndRecord,
        structure: ArtifactStructure::Zip(report),
    }
}
