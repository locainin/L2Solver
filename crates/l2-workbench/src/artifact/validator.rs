use core::fmt;

#[cfg(test)]
#[path = "../../tests/artifact/validator_memory_internal.rs"]
mod memory_tests;

use super::{
    ArtifactError, ArtifactFormat, ArtifactReport, DerError, DerLimits, DerReport, FileRange,
    MAX_DER_DEPTH, PNG_SIGNATURE, PngError, PngLimits, PngReport, candidate_executable_format,
    parse_der,
};
use super::{
    der::{DerMemoryError, parse_der_with_memory},
    png::parse_png_optional_memory,
    signatures::matches_zip_signature,
    zip::{
        ZipArtifactError, ZipArtifactLimits, ZipArtifactOmissionReason, ZipArtifactReport,
        ZipMemoryError, inspect_zip_at_depth_with_memory,
        inspect_zip_at_depth_with_operation_budget, inspect_zip_with_limits,
    },
};
use crate::job::{MemoryError, MemoryLease};

/// Format selected for structural artifact validation
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationFormat {
    /// Canonical DER value
    Der,
    /// Executable and linkable format
    Elf,
    /// Portable Network Executable image
    #[serde(rename = "pe")]
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
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
    ExecutableTableLimit {
        field: std::borrow::Cow<'static, str>,
        maximum: usize,
    },
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
        unmetered_outcome(self.validate_internal(bytes, None, None), bytes, None)
    }

    /// Select a validator and consume a caller-shared ZIP expansion budget
    ///
    /// The ZIP parser deducts each member's declared expanded size before extraction.
    /// A zero budget therefore validates the archive directory without expanding members
    #[must_use]
    pub fn validate_with_zip_budget<'a>(
        &self,
        bytes: &'a [u8],
        zip_budget_remaining: &mut usize,
    ) -> ArtifactValidationOutcome<'a> {
        unmetered_outcome(
            self.validate_internal(bytes, Some(zip_budget_remaining), None),
            bytes,
            None,
        )
    }

    /// The caller keeps the lease until every returned report and moved member is dropped
    pub(crate) fn validate_with_zip_budget_and_memory<'a>(
        &self,
        bytes: &'a [u8],
        zip_budget_remaining: &mut usize,
        memory: &mut MemoryLease,
    ) -> Result<ArtifactValidationOutcome<'a>, MemoryError> {
        self.validate_internal(bytes, Some(zip_budget_remaining), Some(memory))
    }

    fn validate_internal<'a>(
        &self,
        bytes: &'a [u8],
        mut zip_budget_remaining: Option<&mut usize>,
        mut memory: Option<&mut MemoryLease>,
    ) -> Result<ArtifactValidationOutcome<'a>, MemoryError> {
        let input_range = complete_range(bytes);
        if bytes.len() > self.policy.max_input_bytes {
            return Ok(omitted_input(
                None,
                input_range,
                bytes.len(),
                self.policy.max_input_bytes,
            ));
        }

        let executable = candidate_executable_format(bytes).map(validation_format);
        let candidates = [
            bytes
                .starts_with(&PNG_SIGNATURE)
                .then_some(ArtifactValidationFormat::Png),
            executable,
            Some(ArtifactValidationFormat::Zip),
        ];
        // Keep the report before its lease so the report drops first on every exit
        let mut first_unproven: Option<(ArtifactValidationOutcome<'a>, Option<MemoryLease>)> = None;
        let mut first_omission = None;
        let mut first_rejection = None;

        for format in candidates.into_iter().flatten() {
            if format == ArtifactValidationFormat::Zip && !matches_zip_signature(bytes) {
                // A successful earlier candidate wins before ZIP detection needs its tail buffer
                let has_end = if let Some(lease) = memory.as_deref() {
                    super::zip::has_zip_end_record_with_memory(bytes, lease)?
                } else {
                    super::zip::has_zip_end_record(bytes)
                };
                if !has_end {
                    continue;
                }
            }
            let mut candidate_memory = memory
                .as_deref()
                .map(|lease| lease.try_sibling(0))
                .transpose()?;
            let outcome = self.validate_as_with_operation_budget(
                format,
                bytes,
                zip_budget_remaining.as_deref_mut(),
                candidate_memory.as_mut(),
            )?;
            match outcome {
                outcome @ ArtifactValidationOutcome::Validated { .. } => {
                    // The selected report owns its vectors beyond this parser call
                    if let (Some(lease), Some(candidate)) =
                        (memory.as_deref_mut(), candidate_memory.take())
                    {
                        lease.absorb(candidate);
                    }
                    return Ok(outcome);
                }
                outcome @ ArtifactValidationOutcome::BoundaryUnproven { .. } => {
                    if first_unproven.is_none() {
                        first_unproven = Some((outcome, candidate_memory.take()));
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

        if let Some(outcome) = first_omission {
            return Ok(outcome);
        }
        if let Some((outcome, candidate)) = first_unproven {
            if let (Some(lease), Some(candidate)) = (memory, candidate) {
                lease.absorb(candidate);
            }
            return Ok(outcome);
        }
        Ok(first_rejection.unwrap_or(ArtifactValidationOutcome::Unsupported { input_range }))
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
        unmetered_outcome(
            self.validate_as_with_operation_budget(format, bytes, None, None),
            bytes,
            Some(format),
        )
    }

    /// Validate one format using a shared lease for supported parser buffers
    ///
    /// The caller keeps the lease until the returned report and moved data are dropped
    ///
    /// # Errors
    /// Returns a shared-memory admission failure from a metered parser
    pub fn validate_as_with_memory<'a>(
        &self,
        format: ArtifactValidationFormat,
        bytes: &'a [u8],
        memory: &mut MemoryLease,
    ) -> Result<ArtifactValidationOutcome<'a>, MemoryError> {
        self.validate_as_with_operation_budget(format, bytes, None, Some(memory))
    }

    /// Validate one explicit format while consuming a shared ZIP expansion budget
    ///
    /// The remaining budget is reduced before each member extraction, including failed
    /// checksum and decompression attempts. Non-ZIP formats leave it unchanged
    #[must_use]
    pub fn validate_as_with_zip_budget<'a>(
        &self,
        format: ArtifactValidationFormat,
        bytes: &'a [u8],
        zip_budget_remaining: &mut usize,
    ) -> ArtifactValidationOutcome<'a> {
        unmetered_outcome(
            self.validate_as_with_operation_budget(format, bytes, Some(zip_budget_remaining), None),
            bytes,
            Some(format),
        )
    }

    fn validate_as_with_operation_budget<'a>(
        &self,
        format: ArtifactValidationFormat,
        bytes: &'a [u8],
        zip_budget_remaining: Option<&mut usize>,
        memory: Option<&mut MemoryLease>,
    ) -> Result<ArtifactValidationOutcome<'a>, MemoryError> {
        let input_range = complete_range(bytes);
        if bytes.len() > self.policy.max_input_bytes {
            return Ok(omitted_input(
                Some(format),
                input_range,
                bytes.len(),
                self.policy.max_input_bytes,
            ));
        }

        Ok(match format {
            ArtifactValidationFormat::Der => {
                let parsed = if let Some(lease) = memory {
                    match parse_der_with_memory(bytes, input_range, self.policy.der_limits, lease) {
                        Ok(report) => Ok(report),
                        Err(DerMemoryError::Format(error)) => Err(error),
                        Err(DerMemoryError::Memory(error)) => return Err(error),
                    }
                } else {
                    parse_der(bytes, input_range, self.policy.der_limits)
                };
                match parsed {
                    Ok(report) => ArtifactValidationOutcome::Validated {
                        format,
                        range: report.boundary_range,
                        boundary: ArtifactBoundaryEvidence::DerEncodedLength,
                        structure: ArtifactStructure::Der(report),
                    },
                    Err(error) => classify_der_error(format, input_range, error),
                }
            }
            ArtifactValidationFormat::Png => {
                match parse_png_optional_memory(bytes, self.policy.png_limits, memory) {
                    Ok(report) => png_result(report),
                    Err(super::PngReadError::Format(error)) => {
                        classify_png_error(format, input_range, error)
                    }
                    Err(super::PngReadError::Io(_)) => {
                        classify_png_error(format, input_range, PngError::TruncatedChunk)
                    }
                    Err(super::PngReadError::Memory(error)) => return Err(error),
                }
            }
            ArtifactValidationFormat::Zip => {
                let result = if let Some(lease) = memory {
                    let mut unlimited = usize::MAX;
                    inspect_zip_at_depth_with_memory(
                        bytes,
                        self.policy.zip_limits,
                        0,
                        zip_budget_remaining.unwrap_or(&mut unlimited),
                        lease,
                    )
                } else {
                    zip_budget_remaining
                        .map_or_else(
                            || inspect_zip_with_limits(bytes, self.policy.zip_limits),
                            |remaining| {
                                inspect_zip_at_depth_with_operation_budget(
                                    bytes,
                                    self.policy.zip_limits,
                                    0,
                                    remaining,
                                )
                            },
                        )
                        .map_err(ZipMemoryError::Archive)
                };
                match result {
                    Ok(report) => zip_result(format, input_range, self.policy.zip_limits, report),
                    Err(ZipMemoryError::Archive(error)) => {
                        classify_zip_error(format, input_range, error)
                    }
                    Err(ZipMemoryError::Memory(error)) => return Err(error),
                }
            }
            ArtifactValidationFormat::Elf => {
                validate_executable(format, ArtifactFormat::Elf, bytes, input_range, memory)?
            }
            ArtifactValidationFormat::PortableExecutable => validate_executable(
                format,
                ArtifactFormat::PortableExecutable,
                bytes,
                input_range,
                memory,
            )?,
        })
    }
}

fn unmetered_outcome<'a>(
    result: Result<ArtifactValidationOutcome<'a>, MemoryError>,
    bytes: &'a [u8],
    format: Option<ArtifactValidationFormat>,
) -> ArtifactValidationOutcome<'a> {
    result.unwrap_or_else(|_| ArtifactValidationOutcome::Omitted {
        format,
        input_range: complete_range(bytes),
        reason: ArtifactResourceOmissionReason::AllocationFailure,
    })
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
        DerError::AllocationFailure => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::AllocationFailure,
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
        PngError::AllocationFailure => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::AllocationFailure,
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
            reason: ArtifactResourceOmissionReason::ExecutableTableLimit {
                field: std::borrow::Cow::Borrowed(field),
                maximum,
            },
        },
        ArtifactError::AllocationFailure => ArtifactValidationOutcome::Omitted {
            format: Some(format),
            input_range,
            reason: ArtifactResourceOmissionReason::AllocationFailure,
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

fn validate_executable<'src>(
    format: ArtifactValidationFormat,
    expected: ArtifactFormat,
    bytes: &'src [u8],
    input_range: FileRange,
    memory: Option<&mut MemoryLease>,
) -> Result<ArtifactValidationOutcome<'src>, MemoryError> {
    if candidate_executable_format(bytes) != Some(expected) {
        return Ok(ArtifactValidationOutcome::Unsupported { input_range });
    }
    let report = if let Some(lease) = memory {
        match super::inspect::inspect_with_memory(bytes, lease) {
            Ok(report) => Ok(report),
            Err(super::inspect::InspectMemoryError::Format(error)) => Err(error),
            Err(super::inspect::InspectMemoryError::Memory(error)) => return Err(error),
            Err(super::inspect::InspectMemoryError::Allocation) => {
                Err(ArtifactError::AllocationFailure)
            }
        }
    } else {
        super::inspect(bytes)
    };
    Ok(match report {
        Ok(report) => ArtifactValidationOutcome::BoundaryUnproven {
            format,
            input_range,
            structure: ArtifactStructure::Executable(report),
        },
        Err(error) => classify_executable_error(format, input_range, error),
    })
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
