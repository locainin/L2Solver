//! Analyze one byte object through the existing bounded artifact and derivation engines

mod memory;

use super::{
    ArtifactBoundaryEvidence, ArtifactStructure, ArtifactValidationFormat,
    ArtifactValidationOutcome, ArtifactValidationPolicy, ArtifactValidator, DerLimits,
    EmbeddedDiscoveryLimits, EmbeddedFormat, FileRange, PngLimits,
    zip::{ZipArtifactLimits, ZipArtifactOmissionReason},
};
use crate::job::{MemoryError, MemoryLease};
use crate::{
    derivation::{self, DerivationLimits, DerivationStatus, Operation},
    recovery::proposals::{
        ProposalMemoryError, TransformEvidence, TransformProposal, TransformProposalBudget,
        propose_transforms, propose_transforms_with_memory, transform_proposal_scan_work_bound,
    },
    recovery::regions::{
        RegionCueOrigin, RegionMemoryError, TransformRegionLimits, TransformRegionReport,
        propose_region_transforms, propose_region_transforms_with_memory,
        transform_region_scan_work_bound,
    },
    sha256,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// Hard limits for one standalone artifact analysis
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzerLimits {
    /// Largest complete source object accepted for in-memory analysis
    pub max_input_bytes: usize,
    /// Maximum number of unique byte objects retained, including the source
    pub max_artifacts: usize,
    /// Maximum cumulative byte length of retained objects
    pub max_total_output_bytes: usize,
    /// Maximum accounted parser, scan, and transform work
    pub max_total_work_bytes: usize,
    /// Maximum total bytes passed to the signature catalogue
    pub max_signature_scan_bytes: usize,
    /// Largest input considered by the canonical transform proposer
    pub max_transform_input_bytes: usize,
    /// Largest output retained from any canonical transform
    pub max_transform_output_bytes: usize,
    /// Maximum expanded bytes charged across archive inspections
    pub max_zip_expanded_bytes: usize,
    /// Maximum number of parent-child derivation levels below the source
    pub max_depth: usize,
}

impl Default for AnalyzerLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: ZipArtifactLimits::default().max_archive_bytes,
            max_artifacts: 256,
            max_total_output_bytes: 128 * 1024 * 1024,
            max_total_work_bytes: 256 * 1024 * 1024,
            max_signature_scan_bytes: 128 * 1024 * 1024,
            max_transform_input_bytes: derivation::MAX_INPUT_BYTES,
            max_transform_output_bytes: derivation::MAX_OUTPUT_BYTES,
            max_zip_expanded_bytes: ZipArtifactLimits::default().max_total_expanded_bytes,
            max_depth: ZipArtifactLimits::default().max_depth,
        }
    }
}

/// Whether the analyzer may attempt independently supported partial recovery
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryMode {
    /// Keep only complete, parser-validated objects and canonical derivations
    Conservative,
    /// Request partial recovery where a supported independent method exists
    Salvage,
}

/// Caller-selected policy for one complete in-memory artifact analysis
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAnalysisOptions {
    /// Resource limits shared across all objects discovered from the source
    pub limits: AnalyzerLimits,
    /// Recovery behavior requested for the source
    pub recovery: RecoveryMode,
}

impl Default for ArtifactAnalysisOptions {
    fn default() -> Self {
        Self {
            limits: AnalyzerLimits::default(),
            recovery: RecoveryMode::Conservative,
        }
    }
}

/// The structural validation state retained for one artifact
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationState {
    /// An existing format parser accepted the selected range
    Validated,
    /// An executable parser accepted structures without proving a whole-file boundary
    BoundaryUnproven,
    /// A selected existing parser rejected the candidate
    Rejected,
    /// No enabled parser recognized a supported format candidate
    Unsupported,
    /// A resource policy prevented a conclusive validation result
    Omitted,
}

/// Stable structural format label retained in an analysis receipt
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisFormat {
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

/// Stable parser boundary label retained in an analysis receipt
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisBoundary {
    /// PNG parser reached IEND
    PngIend,
    /// DER parser consumed the encoded object length
    DerEncodedLength,
    /// ZIP parser checked the archive end record
    ZipEndRecord,
}

/// Parser or scan stage whose work was stopped by the shared byte-work budget
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisStage {
    /// Hashing exact artifact bytes to establish their identity
    ArtifactIdentity,
    /// File-signature catalogue scan
    SignatureScan,
    /// Structural format validation
    ArtifactValidation,
    /// Embedded-object discovery
    EmbeddedDiscovery,
    /// Canonical transform execution
    TransformExecution,
    /// Canonical transform proposal scan
    TransformProposal,
}

/// Compact structural facts retained from an existing parser result
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationSummary {
    /// Result state from the canonical validator
    pub state: ArtifactValidationState,
    /// Format selected or identified by the validator
    pub format: Option<AnalysisFormat>,
    /// Boundary evidence supplied by the parser when validation completed
    pub boundary: Option<AnalysisBoundary>,
    /// Exact range accepted by the parser when a complete boundary was proven
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<FileRange>,
    /// Number of top-level chunks, nodes, sections, or archive entries parsed
    pub structure_count: usize,
}

/// Provenance for one retained source, carved object, archive member, or transform
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactOrigin {
    /// The exact input object supplied to the analyzer
    Source,
    /// A parser-validated range of the source stream, without a retained source blob
    SourceRange {
        /// Exact range in the source identified by the containing analysis receipt
        range: FileRange,
        /// Format selected by the existing embedded-object validator
        format: EmbeddedFormat,
    },
    /// A complete PNG or ZIP carved from the parent object's byte range
    EmbeddedObject {
        /// Parent artifact index whose bytes contain the carved range
        parent_index: usize,
        /// Exact object range relative to the parent bytes
        range: FileRange,
        /// Format selected by the existing embedded-object validator
        format: EmbeddedFormat,
    },
    /// Expanded member bytes validated by the existing ZIP parser
    ArchiveMember {
        /// Parent archive artifact index
        parent_index: usize,
        /// Archive range relative to the parent bytes
        archive_range: FileRange,
        /// Zero-based central-directory entry index
        entry_index: usize,
        /// SHA-256 of the raw archive member name
        raw_name_sha256: String,
        /// Bounded hexadecimal preview of the raw member name
        raw_name_hex_preview: String,
        /// Compressed size declared by the validated central directory
        compressed_size: u64,
        /// Expanded size checked by the ZIP parser
        expanded_size: u64,
    },
    /// Expanded member bytes validated against a ZIP range in the source
    SourceArchiveMember {
        /// Exact archive range in the source identified by the containing analysis
        archive_range: FileRange,
        /// SHA-256 of the complete validated archive range
        archive_sha256: String,
        /// Zero-based central-directory entry index
        entry_index: usize,
        /// SHA-256 of the raw archive member name
        raw_name_sha256: String,
        /// Bounded hexadecimal preview of the raw member name
        raw_name_hex_preview: String,
        /// ZIP compression method recorded by the validated directory
        compression_method: u16,
        /// Compressed size declared by the validated directory
        compressed_size: u64,
        /// Expanded size checked by the ZIP parser
        expanded_size: u64,
        /// CRC-32 checked against the expanded member bytes
        crc32: u32,
        /// Member local-header offset within the archive range
        local_header_offset: u64,
    },
    /// Bytes produced by one syntax-gated canonical operation
    Transformation {
        /// Parent artifact index containing the complete transform input
        parent_index: usize,
        /// Exact input range relative to the parent bytes
        input_range: FileRange,
        /// Canonical operation selected by the proposal engine
        operation: Operation,
        /// Syntax or header evidence supporting the proposal
        evidence: TransformEvidence,
        /// Exact observations that selected a subrange, empty for a whole-input proposal
        #[serde(default)]
        cue_origins: Vec<RegionCueOrigin>,
    },
}

/// Region-specific transform results retained for one analyzed artifact
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRegionTransformReport {
    /// Index of the original artifact whose bytes were scanned
    pub artifact_index: usize,
    /// Exact region proposals and their independent negative scopes
    pub report: TransformRegionReport,
}

/// One unique byte object and every independent origin that produced it
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzedArtifact {
    /// Stable zero-based index in the containing report
    pub index: usize,
    /// All known source and parent relationships for these exact bytes
    pub origins: Vec<ArtifactOrigin>,
    /// SHA-256 of the exact retained artifact bytes
    pub sha256: String,
    /// File-signature catalogue matches observed in the artifact
    pub signature_match_count: usize,
    /// Whether the catalogue scan completed within its input budget
    pub signatures_scanned: bool,
    /// Structural result from the existing artifact validator
    pub validation: ValidationSummary,
    /// Exact retained bytes, stored separately in the persistent analysis cache
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// Analysis completeness for one source object
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    /// Supported analysis and all requested work finished within limits
    Complete,
    /// The source was analyzed, but no supported complete object or derivation was found
    Unsupported,
    /// One or more requested inputs or analysis stages were limited or unavailable
    Partial,
}

/// Why one requested analysis step or output was not retained
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnalysisOmission {
    /// The operation-wide source read limit prevented opening this source for analysis
    SourceReadLimit {
        /// Source bytes that were not read
        length: u64,
        /// Reserved bytes required to analyze and recheck the source
        required: u64,
        /// Bytes still available for source admission
        remaining: u64,
        /// Operation-wide source read limit
        maximum: u64,
    },
    /// A validated file range could not be reread for publication within the source limit
    SourceRangeOutputReadLimit {
        /// Exact range length requiring publication
        length: u64,
        /// Source read bytes available after required checks
        remaining: u64,
        /// Operation-wide source read limit
        maximum: u64,
    },
    /// File-backed structural validation could not complete within its limits
    SourceRangeValidationLimit {
        /// Format selected for structural inspection
        format: AnalysisFormat,
        /// Reader or metadata limit that stopped validation
        reason: String,
    },
    /// Expanded ZIP members were not retained because their source archive was omitted
    SourceArchiveMembersOmitted {
        /// Exact archive range in the immutable source
        range: FileRange,
        /// Number of expanded members omitted with their parent
        count: usize,
    },
    /// An archive member was already omitted by the ZIP parser
    SourceArchiveMemberOmission {
        /// Exact archive range in the immutable source
        range: FileRange,
        /// Zero-based central-directory entry index
        entry_index: usize,
        /// Parser reason the entry could not be expanded
        reason: ZipArtifactOmissionReason,
    },
    /// An expanded source archive member exceeded the remaining output budget
    SourceArchiveMemberOutputLimit {
        /// Exact archive range in the immutable source
        range: FileRange,
        /// Zero-based central-directory entry index
        entry_index: usize,
        /// Expanded member length
        length: usize,
        /// Output bytes available before this member
        remaining: usize,
    },
    /// Work required to retain a source archive member exceeded the remaining budget
    SourceArchiveMemberWorkLimit {
        /// Exact archive range in the immutable source
        range: FileRange,
        /// Zero-based central-directory entry index
        entry_index: usize,
        /// Work stage stopped by the limit
        stage: AnalysisStage,
        /// Work bytes required by the stage
        requested: usize,
        /// Work bytes available before this stage
        remaining: usize,
    },
    /// A whole-source streaming transformation was incomplete or rejected
    SourceStreamTransform {
        /// Operation attempted when one was selected
        operation: Option<Operation>,
        /// Resource, depth, or transform failure
        reason: String,
    },
    /// The shared evidence Case has no remaining space for another source object
    CaseBlobLimit {
        /// Maximum aggregate bytes retained by the Case
        maximum: usize,
    },
    /// Range discovery has bounded windows and may omit whole-source work or larger objects
    SourceRangeCoverage {
        /// Largest object guaranteed to fit within overlapping source windows
        max_object_bytes: usize,
        /// Candidate observations omitted by configured budgets
        omitted_candidates: usize,
        /// ZIP candidates stopped before directory parsing by the entry-count limit
        zip_entry_count_limited: usize,
        /// Retained objects whose signature catalogue scan did not fit its budget
        signature_scans_omitted: usize,
        /// Source positions without a complete bounded-object discovery window
        uncovered_range: Option<FileRange>,
    },
    /// Coverage of bounded object discovery within one transformed stream
    DerivedStreamRangeCoverage {
        /// SHA-256 of the complete transformed stream
        output_sha256: String,
        /// Largest object guaranteed to fit within overlapping stream windows
        max_object_bytes: usize,
        /// Candidate observations omitted by configured budgets
        omitted_candidates: usize,
        /// ZIP candidates stopped before directory parsing by the entry-count limit
        zip_entry_count_limited: usize,
        /// Retained objects whose signature scan did not fit its budget
        signature_scans_omitted: usize,
        /// Stream positions without a complete bounded-object discovery window
        uncovered_range: Option<FileRange>,
    },
    /// Source bytes exceeded the selected in-memory analysis ceiling
    InputLimit { length: usize, maximum: usize },
    /// The source could not fit in the retained output byte budget
    SourceOutputLimit { length: usize, maximum: usize },
    /// A discovered object could not fit in the total output byte budget
    OutputLimit {
        parent_index: usize,
        length: usize,
        remaining: usize,
    },
    /// The unique-object count reached its configured ceiling
    ArtifactLimit { maximum: usize },
    /// Recursive inspection reached the configured depth ceiling
    DepthLimit {
        artifact_index: usize,
        maximum: usize,
    },
    /// A named scan or parser stage could not fit in the remaining work allowance
    WorkLimit {
        artifact_index: usize,
        stage: AnalysisStage,
        requested: usize,
        remaining: usize,
    },
    /// The signature catalogue was skipped because its separate scan allowance was exhausted
    SignatureScanLimit {
        artifact_index: usize,
        requested: usize,
        remaining: usize,
    },
    /// The selected format validator reported a concrete resource or allocation limit
    ValidationLimit {
        artifact_index: usize,
        format: Option<AnalysisFormat>,
        reason: String,
    },
    /// A transform candidate exceeded the canonical derivation input ceiling
    TransformInputLimit {
        artifact_index: usize,
        length: usize,
        maximum: usize,
    },
    /// A canonical proposal failed while applying its existing operation
    TransformFailed {
        artifact_index: usize,
        operation: Operation,
        message: String,
    },
    /// A validated ZIP entry had no expanded member bytes
    ZipMember {
        artifact_index: usize,
        entry_index: usize,
        reason: ZipArtifactOmissionReason,
    },
    /// Embedded discovery did not inspect all requested positions or candidates
    EmbeddedDiscovery {
        artifact_index: usize,
        output_candidates: usize,
        unvalidated_candidates: usize,
        #[serde(default)]
        zip_entry_count_limited: usize,
        unscanned_range: Option<FileRange>,
    },
    /// The requested salvage mode has no supported partial-repair operation for this input
    SalvageUnsupported,
}

impl AnalysisOmission {
    /// Report whether this omission means the source exceeded the selected input ceiling
    #[must_use]
    pub const fn is_input_limit(&self) -> bool {
        matches!(self, Self::InputLimit { .. })
    }

    /// Report whether salvage was requested without a supported partial-repair operation
    #[must_use]
    pub const fn is_salvage_unsupported(&self) -> bool {
        matches!(self, Self::SalvageUnsupported)
    }
}

/// Bounded findings and exact bytes retained from one source object
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAnalysis {
    /// SHA-256 of the exact input bytes, even when an input limit blocks inspection
    pub source_sha256: String,
    /// Number of bytes in the exact source object
    pub source_length: usize,
    /// Unique retained byte objects in deterministic discovery order
    pub artifacts: Vec<AnalyzedArtifact>,
    /// Overall completion state for the requested analysis
    pub status: AnalysisStatus,
    /// Work and output limits that left analysis incomplete
    pub omissions: Vec<AnalysisOmission>,
    /// Syntax assessments scoped to each selected byte region
    #[serde(default)]
    pub region_transform_reports: Vec<ArtifactRegionTransformReport>,
    /// Accounted byte work charged, including conservative failed-attempt reservations
    pub work_bytes: usize,
    /// Declared ZIP member bytes charged, including failed extraction attempts
    #[serde(default)]
    pub zip_expanded_work_bytes: usize,
}

impl ArtifactAnalysis {
    /// Return true only when the requested analysis completed with supported evidence
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.status, AnalysisStatus::Complete)
    }
}

/// Invalid analysis policy or bounded metadata allocation failure
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalyzerError {
    /// The named analysis limit must be positive
    InvalidLimit { field: &'static str },
    /// The trusted source digest is not lowercase SHA-256 hexadecimal
    InvalidSourceHash,
    /// A bounded analysis metadata allocation could not be reserved
    AllocationFailure,
    /// The shared live-memory budget could not admit an analysis allocation
    Memory(MemoryError),
    /// A proposed operation has no shared-memory admission model
    UnsupportedMemoryOperation,
}

impl fmt::Display for AnalyzerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "artifact analysis limit {field} is invalid")
            }
            Self::InvalidSourceHash => {
                formatter.write_str("artifact analysis source SHA-256 is invalid")
            }
            Self::AllocationFailure => formatter.write_str("artifact analysis allocation failed"),
            Self::Memory(error) => write!(
                formatter,
                "artifact analysis memory admission failed: {error}"
            ),
            Self::UnsupportedMemoryOperation => {
                formatter.write_str("artifact analysis operation lacks memory admission")
            }
        }
    }
}

impl Error for AnalyzerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

impl From<MemoryError> for AnalyzerError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

struct PendingArtifact {
    bytes: Vec<u8>,
    origin: ArtifactOrigin,
    depth: usize,
    memory: memory::Charge,
}

struct PendingArtifacts {
    values: Vec<PendingArtifact>,
    memory: memory::Charge,
}

impl PendingArtifacts {
    fn new(template: &memory::Charge) -> Result<Self, AnalyzerError> {
        Ok(Self {
            values: Vec::new(),
            memory: memory::sibling(template, 0)?,
        })
    }

    fn push(&mut self, candidate: PendingArtifact) -> Result<(), AnalyzerError> {
        memory::reserve_one(&mut self.values, &mut self.memory)?;
        self.values.push(candidate);
        Ok(())
    }
}

struct WorkBudget {
    remaining: usize,
    used: usize,
}

impl WorkBudget {
    const fn new(maximum: usize) -> Self {
        Self {
            remaining: maximum,
            used: 0,
        }
    }

    const fn charge(&mut self, amount: usize) -> bool {
        let Some(remaining) = self.remaining.checked_sub(amount) else {
            return false;
        };
        self.remaining = remaining;
        self.used += amount;
        true
    }
}

struct AnalysisBudget {
    work: WorkBudget,
    signature_scan_remaining: usize,
    zip_remaining: usize,
}

impl AnalysisBudget {
    const fn new(limits: AnalyzerLimits) -> Self {
        Self {
            work: WorkBudget::new(limits.max_total_work_bytes),
            signature_scan_remaining: limits.max_signature_scan_bytes,
            zip_remaining: limits.max_zip_expanded_bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct ArtifactInspection {
    signature_match_count: usize,
    signatures_scanned: bool,
    validation: ValidationSummary,
}

struct ArtifactContext<'a> {
    index: usize,
    depth: usize,
    input_bytes: &'a [u8],
    limits: AnalyzerLimits,
}

#[derive(Clone, Copy)]
struct TransformExecutionCandidate<'a> {
    proposal: &'a TransformProposal,
    input_range: FileRange,
    cue_origins: &'a [RegionCueOrigin],
}

// The derivation report drops before the charge that covers its buffers
struct AdmittedDerivation {
    report: derivation::DerivationReport,
    memory: memory::Charge,
}

fn inspect_artifact(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<ArtifactInspection, AnalyzerError> {
    let (signature_match_count, signatures_scanned) =
        scan_signatures(context, budget, report, memory)?;
    let validation = validate_and_expand_zip(context, budget, report, found, memory)?;
    discover_embedded_objects(context, validation, budget, report, found, memory)?;
    derive_candidates(context, budget, report, found, memory)?;
    Ok(ArtifactInspection {
        signature_match_count,
        signatures_scanned,
        validation,
    })
}

fn scan_signatures(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    memory: &mut memory::Charge,
) -> Result<(usize, bool), AnalyzerError> {
    let scan_charge = context.input_bytes.len();
    if scan_charge <= budget.signature_scan_remaining && budget.work.charge(scan_charge) {
        let matches = super::signatures::count_file_signature_matches(context.input_bytes);
        budget.signature_scan_remaining -= scan_charge;
        Ok((matches, true))
    } else if scan_charge > budget.signature_scan_remaining {
        push_omission(
            report,
            memory,
            AnalysisOmission::SignatureScanLimit {
                artifact_index: context.index,
                requested: scan_charge,
                remaining: budget.signature_scan_remaining,
            },
        )?;
        Ok((0, false))
    } else {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::SignatureScan,
                requested: scan_charge,
                remaining: budget.work.remaining,
            },
        )?;
        Ok((0, false))
    }
}

fn validate_and_expand_zip(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<ValidationSummary, AnalyzerError> {
    let validation_charge = context.input_bytes.len();
    if !budget.work.charge(validation_charge) {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::ArtifactValidation,
                requested: validation_charge,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(unsupported_validation());
    }

    let validator = validator_for(context.limits)?;
    let mut parser_zip_remaining = budget.zip_remaining.min(budget.work.remaining);
    let parser_zip_start = parser_zip_remaining;
    let mut validation_memory = memory::sibling(memory, 0)?;
    let validation = if let Some(lease) = &mut validation_memory {
        validator.validate_with_zip_budget_and_memory(
            context.input_bytes,
            &mut parser_zip_remaining,
            lease,
        )
    } else {
        Ok(validator.validate_with_zip_budget(context.input_bytes, &mut parser_zip_remaining))
    };
    let zip_work = parser_zip_start - parser_zip_remaining;
    budget.zip_remaining -= zip_work;
    let charged_zip_work = budget.work.charge(zip_work);
    debug_assert!(charged_zip_work);
    let validation = validation?;

    let summary = summarize_validation(&validation);
    match validation {
        ArtifactValidationOutcome::Validated {
            format: ArtifactValidationFormat::Zip,
            structure: ArtifactStructure::Zip(mut zip_report),
            ..
        } => {
            append_zip_omissions(context.index, &zip_report, report, memory)?;
            for entry in std::mem::take(&mut zip_report.entries) {
                if let Some(member_bytes) = entry.content {
                    found.push(zip_member_candidate(
                        context,
                        member_bytes,
                        &entry.metadata,
                        &mut validation_memory,
                    )?)?;
                }
            }
        }
        ArtifactValidationOutcome::Omitted { format, reason, .. } => {
            let reason = memory::format_message(format_args!("{reason:?}"), memory)?;
            push_omission(
                report,
                memory,
                AnalysisOmission::ValidationLimit {
                    artifact_index: context.index,
                    format: format.map(format_label),
                    reason,
                },
            )?;
        }
        _ => {}
    }
    Ok(summary)
}

fn append_zip_omissions(
    artifact_index: usize,
    zip_report: &super::zip::ZipArtifactReport,
    report: &mut ArtifactAnalysis,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    if zip_report.omitted_entry_count == 0 {
        return Ok(());
    }
    for entry in &zip_report.entries {
        if let Some(reason) = entry.omission {
            push_omission(
                report,
                memory,
                AnalysisOmission::ZipMember {
                    artifact_index,
                    entry_index: entry.metadata.index,
                    reason,
                },
            )?;
        }
    }
    Ok(())
}

fn zip_member_candidate(
    context: &ArtifactContext<'_>,
    bytes: Vec<u8>,
    metadata: &super::zip::ZipArtifactEntryMetadata,
    parser_memory: &mut memory::Charge,
) -> Result<PendingArtifact, AnalyzerError> {
    let mut owned = memory::Bytes {
        memory: memory::split(parser_memory, bytes.capacity())?,
        bytes,
    };
    let preview = metadata.raw_name.len().min(32) * 2;
    // Digest formatting and the bounded name preview can coexist during construction
    memory::grow(&mut owned.memory, 128 + preview)?;
    let origin = archive_member_origin(context.index, context.input_bytes.len(), metadata);
    let retained = owned
        .bytes
        .capacity()
        .checked_add(origin_owned_bytes(&origin)?)
        .ok_or(AnalyzerError::AllocationFailure)?;
    memory::resize(&mut owned.memory, retained)?;
    Ok(PendingArtifact {
        bytes: owned.bytes,
        origin,
        depth: context.depth.saturating_add(1),
        memory: owned.memory,
    })
}

fn discover_embedded_objects(
    context: &ArtifactContext<'_>,
    validation: ValidationSummary,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let discovery_charge = context.input_bytes.len();
    if !budget.work.charge(discovery_charge) {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::EmbeddedDiscovery,
                requested: discovery_charge,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(());
    }

    let mut discovery_limits = embedded_limits(context.limits);
    // ZIP members were expanded by validation; discovery only finds exact ranges
    discovery_limits.max_zip_operation_expanded_bytes = 0;
    let skip_start_format =
        embedded_format_for_validated_full_range(validation, context.input_bytes.len());
    let mut discovery_memory = memory::sibling(memory, 0)?;
    let discovery = if let Some(lease) = &mut discovery_memory {
        super::embedded::discover_embedded_objects_with_work_and_skip_start_with_memory(
            context.input_bytes,
            discovery_limits,
            budget.work.remaining,
            skip_start_format,
            lease,
        )
        .map_err(|error| match error {
            super::embedded::EmbeddedDiscoveryMemoryError::Discovery(_) => {
                AnalyzerError::AllocationFailure
            }
            super::embedded::EmbeddedDiscoveryMemoryError::Memory(error) => {
                AnalyzerError::Memory(error)
            }
        })?
    } else {
        super::embedded::discover_embedded_objects_with_work_and_skip_start(
            context.input_bytes,
            discovery_limits,
            budget.work.remaining,
            skip_start_format,
        )
        .map_err(|_| AnalyzerError::AllocationFailure)?
    };
    let charged_discovery_work = budget.work.charge(discovery.validation_input_bytes);
    debug_assert!(charged_discovery_work);
    if discovery.omissions.output_candidate_count > 0
        || discovery.omissions.unvalidated_candidate_count > 0
        || discovery.omissions.unscanned_range.is_some()
    {
        push_omission(
            report,
            memory,
            AnalysisOmission::EmbeddedDiscovery {
                artifact_index: context.index,
                output_candidates: discovery.omissions.output_candidate_count,
                unvalidated_candidates: discovery.omissions.unvalidated_candidate_count,
                zip_entry_count_limited: discovery.omissions.zip_entry_count_limited,
                unscanned_range: discovery.omissions.unscanned_range,
            },
        )?;
    }
    retain_embedded_objects(context, discovery.candidates, found, memory)
}

fn retain_embedded_objects(
    context: &ArtifactContext<'_>,
    candidates: Vec<super::embedded::EmbeddedCandidate>,
    found: &mut PendingArtifacts,
    memory: &memory::Charge,
) -> Result<(), AnalyzerError> {
    for candidate in candidates {
        if candidate.validation.is_err() {
            continue;
        }
        // A full-range candidate is the current object again, so it adds no provenance
        if candidate.range.offset == 0 && candidate.range.length == context.input_bytes.len() {
            continue;
        }
        let Some(end) = candidate.range.offset.checked_add(candidate.range.length) else {
            continue;
        };
        let Some(candidate_bytes) = context.input_bytes.get(candidate.range.offset..end) else {
            continue;
        };
        let memory::Bytes {
            memory: candidate_memory,
            bytes,
        } = memory::copy_bytes(candidate_bytes, memory)?;
        found.push(PendingArtifact {
            bytes,
            origin: ArtifactOrigin::EmbeddedObject {
                parent_index: context.index,
                range: candidate.range,
                format: candidate.format,
            },
            depth: context.depth.saturating_add(1),
            memory: candidate_memory,
        })?;
    }
    Ok(())
}

const fn embedded_format_for_validated_full_range(
    validation: ValidationSummary,
    input_length: usize,
) -> Option<EmbeddedFormat> {
    match (
        validation.state,
        validation.format,
        validation.boundary,
        validation.range,
    ) {
        (
            ArtifactValidationState::Validated,
            Some(AnalysisFormat::Png),
            Some(AnalysisBoundary::PngIend),
            Some(range),
        ) if range.offset == 0 && range.length == input_length => Some(EmbeddedFormat::Png),
        (
            ArtifactValidationState::Validated,
            Some(AnalysisFormat::Zip),
            Some(AnalysisBoundary::ZipEndRecord),
            Some(range),
        ) if range.offset == 0 && range.length == input_length => Some(EmbeddedFormat::Zip),
        _ => None,
    }
}

fn derive_candidates(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    if context.input_bytes.len() > context.limits.max_transform_input_bytes {
        push_omission(
            report,
            memory,
            AnalysisOmission::TransformInputLimit {
                artifact_index: context.index,
                length: context.input_bytes.len(),
                maximum: context.limits.max_transform_input_bytes,
            },
        )?;
        return Ok(());
    }
    let Some(proposal_charge) = transform_proposal_scan_work_bound(context.input_bytes.len())
    else {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::TransformProposal,
                requested: usize::MAX,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(());
    };
    if !budget.work.charge(proposal_charge) {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::TransformProposal,
                requested: proposal_charge,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(());
    }

    let proposal_budget = TransformProposalBudget {
        max_candidates: 7,
        max_reports: 7,
    };
    let mut proposal_memory = memory::sibling(memory, 0)?;
    let proposals = if let Some(lease) = &mut proposal_memory {
        propose_transforms_with_memory(context.input_bytes, proposal_budget, lease)
            .map_err(proposal_memory_error)?
    } else {
        propose_transforms(context.input_bytes, proposal_budget)
    };
    let candidates = proposals
        .proposals
        .iter()
        .map(|proposal| TransformExecutionCandidate {
            proposal,
            input_range: complete_range(context.input_bytes.len()),
            cue_origins: &[],
        });
    execute_transform_candidates(context, budget, report, found, candidates, memory)?;
    drop(proposals);
    drop(proposal_memory);
    derive_region_candidates(context, budget, report, found, memory)
}

fn derive_region_candidates(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let input_length = context.input_bytes.len();
    let region_limits = TransformRegionLimits::for_input(input_length);
    let Some(proposal_charge) = transform_region_scan_work_bound(region_limits) else {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::TransformProposal,
                requested: usize::MAX,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(());
    };
    if !budget.work.charge(proposal_charge) {
        push_omission(
            report,
            memory,
            AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::TransformProposal,
                requested: proposal_charge,
                remaining: budget.work.remaining,
            },
        )?;
        return Ok(());
    }

    let proposal_budget = TransformProposalBudget {
        max_candidates: 7,
        max_reports: 7,
    };
    let mut region_memory = memory::sibling(memory, 0)?;
    let region_report = if let Some(lease) = &mut region_memory {
        propose_region_transforms_with_memory(
            context.input_bytes,
            &[],
            region_limits,
            proposal_budget,
            lease,
        )
        .map_err(region_memory_error)?
    } else {
        propose_region_transforms(context.input_bytes, &[], region_limits, proposal_budget)
    };
    let candidates = region_report.regions.iter().flat_map(|region| {
        region
            .proposal_report
            .proposals
            .iter()
            .map(move |proposal| TransformExecutionCandidate {
                proposal,
                input_range: FileRange {
                    offset: region.range.start,
                    length: region.range.end - region.range.start,
                },
                cue_origins: &region.cue_origins,
            })
    });
    execute_transform_candidates(context, budget, report, found, candidates, memory)?;
    memory::reserve_one(&mut report.region_transform_reports, memory)?;
    report
        .region_transform_reports
        .push(ArtifactRegionTransformReport {
            artifact_index: context.index,
            report: region_report,
        });
    memory::absorb(memory, region_memory);
    Ok(())
}

const fn proposal_memory_error(error: ProposalMemoryError) -> AnalyzerError {
    match error {
        ProposalMemoryError::Memory(error) => AnalyzerError::Memory(error),
        ProposalMemoryError::Allocation => AnalyzerError::AllocationFailure,
    }
}

const fn region_memory_error(error: RegionMemoryError) -> AnalyzerError {
    match error {
        RegionMemoryError::Memory(error) => AnalyzerError::Memory(error),
        RegionMemoryError::Allocation => AnalyzerError::AllocationFailure,
    }
}

fn execute_transform_candidates<'a>(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    proposals: impl IntoIterator<Item = TransformExecutionCandidate<'a>>,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    for proposal in proposals {
        let operation = proposal
            .proposal
            .recipe
            .steps
            .last()
            .ok_or(AnalyzerError::AllocationFailure)?;
        if budget.work.remaining == 0 {
            push_omission(
                report,
                memory,
                AnalysisOmission::WorkLimit {
                    artifact_index: context.index,
                    stage: AnalysisStage::TransformExecution,
                    requested: 1,
                    remaining: 0,
                },
            )?;
            break;
        }
        let derivation_limits = derivation_limits(context.limits, budget.work.remaining);
        let mut result_memory = memory::sibling(memory, 0)?;
        let result = run_candidate_derivation(
            context.input_bytes,
            &proposal.proposal.recipe,
            derivation_limits,
            &mut result_memory,
        )?;
        match result {
            Ok(derivation) => {
                if !budget.work.charge(derivation.work_bytes) {
                    push_omission(
                        report,
                        memory,
                        AnalysisOmission::WorkLimit {
                            artifact_index: context.index,
                            stage: AnalysisStage::TransformExecution,
                            requested: derivation.work_bytes,
                            remaining: budget.work.remaining,
                        },
                    )?;
                    continue;
                }
                record_transform_result(
                    context,
                    proposal,
                    AdmittedDerivation {
                        report: derivation,
                        memory: result_memory,
                    },
                    report,
                    found,
                    memory,
                )?;
            }
            Err(error) => {
                let message = memory::format_message(format_args!("{error}"), memory)?;
                push_omission(
                    report,
                    memory,
                    AnalysisOmission::TransformFailed {
                        artifact_index: context.index,
                        operation: operation.clone(),
                        message,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn run_candidate_derivation(
    input: &[u8],
    recipe: &derivation::Recipe,
    limits: derivation::DerivationLimits,
    memory: &mut memory::Charge,
) -> Result<Result<derivation::DerivationReport, derivation::DerivationError>, AnalyzerError> {
    memory.as_mut().map_or_else(
        || Ok(derivation::run_with_limits(input, recipe, limits)),
        |lease| match derivation::run_with_memory(input, recipe, limits, lease) {
            Ok(result) => Ok(Ok(result)),
            Err(derivation::AdmittedDerivationError::Derivation(error)) => Ok(Err(error)),
            Err(derivation::AdmittedDerivationError::Memory(error)) => Err(error.into()),
            Err(derivation::AdmittedDerivationError::UnsupportedOperation) => {
                Err(AnalyzerError::UnsupportedMemoryOperation)
            }
        },
    )
}

fn record_transform_result(
    context: &ArtifactContext<'_>,
    proposal: TransformExecutionCandidate<'_>,
    mut result: AdmittedDerivation,
    report: &mut ArtifactAnalysis,
    found: &mut PendingArtifacts,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let operation = proposal
        .proposal
        .recipe
        .steps
        .last()
        .ok_or(AnalyzerError::AllocationFailure)?;
    if result.report.status != DerivationStatus::Completed {
        let message = memory::format_message(
            format_args!(
                "canonical operation stopped at step {:?}",
                result.report.status
            ),
            memory,
        )?;
        push_omission(
            report,
            memory,
            AnalysisOmission::TransformFailed {
                artifact_index: context.index,
                operation: operation.clone(),
                message,
            },
        )?;
    } else if !result.report.output.is_empty() && result.report.output != context.input_bytes {
        // Move the output charge with its bytes before releasing derivation metadata
        let mut candidate_memory =
            memory::split(&mut result.memory, result.report.output.capacity())?;
        let output = std::mem::take(&mut result.report.output);
        let (cue_origins, cue_memory) = memory::copy_cues(proposal.cue_origins, memory)?;
        memory::absorb(&mut candidate_memory, cue_memory);
        drop(result);
        found.push(PendingArtifact {
            bytes: output,
            origin: ArtifactOrigin::Transformation {
                parent_index: context.index,
                input_range: proposal.input_range,
                operation: operation.clone(),
                evidence: proposal.proposal.evidence.clone(),
                cue_origins,
            },
            depth: context.depth.saturating_add(1),
            memory: candidate_memory,
        })?;
    }
    Ok(())
}

/// Analyze one complete byte object without replacing or repairing its source bytes
///
/// Complete PNG and ZIP objects are validated by the existing parsers. Embedded objects,
/// validated ZIP members, and syntax-gated hexadecimal, Base64, gzip, or zlib outputs are
/// retained as immutable child artifacts with explicit parent relationships. A resource
/// ceiling produces a partial report with the source hash and length preserved.
///
/// # Errors
/// Returns an error when required policy limits are invalid or bounded report storage fails
pub fn analyze_artifacts(
    bytes: &[u8],
    options: ArtifactAnalysisOptions,
) -> Result<ArtifactAnalysis, AnalyzerError> {
    let source_sha256 = sha256(bytes);
    analyze_artifacts_with_source_sha256(bytes, &source_sha256, options)
}

/// Analyze bytes when a stable snapshot already has a verified SHA-256 digest
///
/// The supplied digest must have been computed from these exact bytes. This entry point lets
/// file-backed callers reuse the digest used for cache identity and manifest verification
/// without hashing the same potentially large object again
///
/// # Errors
/// Returns an error when the digest format or analysis policy is invalid, or bounded report
/// storage fails
pub fn analyze_artifacts_with_source_sha256(
    bytes: &[u8],
    source_sha256: &str,
    options: ArtifactAnalysisOptions,
) -> Result<ArtifactAnalysis, AnalyzerError> {
    analyze_artifacts_inner(bytes, source_sha256, options, &mut None)
}

/// Analyze bytes while admitting owned allocations against one shared live-memory lease
///
/// A supplied digest must identify the exact source bytes; otherwise it is computed once
/// The caller must retain the
/// lease until the report and every artifact moved from it have been dropped. On failure,
/// temporary allocations are dropped and the caller's original charge is preserved.
/// Charges cover managed buffers and documented workspace allowances, not process RSS
///
/// # Errors
/// Returns an error when limits, the digest, allocation, or shared-memory admission fail
pub fn analyze_artifacts_with_memory(
    bytes: &[u8],
    source_sha256: Option<&str>,
    options: ArtifactAnalysisOptions,
    memory: &mut MemoryLease,
) -> Result<ArtifactAnalysis, AnalyzerError> {
    let mut retained = Some(memory.try_sibling(0)?);
    let mut digest_memory = memory::sibling(&retained, 0)?;
    let computed = if source_sha256.is_none() {
        Some(memory::digest(bytes, &mut digest_memory)?)
    } else {
        None
    };
    let digest = source_sha256
        .or(computed.as_deref())
        .ok_or(AnalyzerError::InvalidSourceHash)?;
    let report = analyze_artifacts_inner(bytes, digest, options, &mut retained)?;
    drop(computed);
    drop(digest_memory);
    if let Some(retained) = retained {
        memory.absorb(retained);
    }
    Ok(report)
}

fn analyze_artifacts_inner(
    bytes: &[u8],
    source_sha256: &str,
    options: ArtifactAnalysisOptions,
    memory: &mut memory::Charge,
) -> Result<ArtifactAnalysis, AnalyzerError> {
    validate_limits(options.limits)?;
    if !crate::hashing::is_sha256_digest(source_sha256) {
        return Err(AnalyzerError::InvalidSourceHash);
    }
    let mut report = empty_analysis_report(bytes.len(), source_sha256, memory)?;
    if let Some(omission) = source_input_omission(bytes.len(), options.limits) {
        memory::reserve_one(&mut report.omissions, memory)?;
        report.omissions.push(omission);
        report.status = AnalysisStatus::Partial;
        return Ok(report);
    }
    let (work_bytes, zip_expanded_work_bytes) = analyze_queue(bytes, options, &mut report, memory)?;
    report.work_bytes = work_bytes;
    report.zip_expanded_work_bytes = zip_expanded_work_bytes;
    let has_validated_object = report
        .artifacts
        .iter()
        .any(|artifact| artifact.validation.state == ArtifactValidationState::Validated);
    if options.recovery == RecoveryMode::Salvage && !has_validated_object {
        // No current partial-repair parser can safely rebuild unsupported bytes
        memory::reserve_one(&mut report.omissions, memory)?;
        report.omissions.push(AnalysisOmission::SalvageUnsupported);
    }
    report.status = analysis_status(&report);
    Ok(report)
}

fn empty_analysis_report(
    source_length: usize,
    source_sha256: &str,
    memory: &mut memory::Charge,
) -> Result<ArtifactAnalysis, AnalyzerError> {
    Ok(ArtifactAnalysis {
        source_sha256: memory::copy_string(source_sha256, memory)?,
        source_length,
        artifacts: Vec::new(),
        status: AnalysisStatus::Unsupported,
        omissions: Vec::new(),
        region_transform_reports: Vec::new(),
        work_bytes: 0,
        zip_expanded_work_bytes: 0,
    })
}

const fn source_input_omission(length: usize, limits: AnalyzerLimits) -> Option<AnalysisOmission> {
    if length > limits.max_input_bytes {
        Some(AnalysisOmission::InputLimit {
            length,
            maximum: limits.max_input_bytes,
        })
    } else if length > limits.max_total_output_bytes {
        Some(AnalysisOmission::SourceOutputLimit {
            length,
            maximum: limits.max_total_output_bytes,
        })
    } else {
        None
    }
}

fn analyze_queue(
    source_bytes: &[u8],
    options: ArtifactAnalysisOptions,
    report: &mut ArtifactAnalysis,
    memory: &mut memory::Charge,
) -> Result<(usize, usize), AnalyzerError> {
    add_source_artifact(source_bytes, report, memory)?;
    let mut budget = AnalysisBudget::new(options.limits);
    let mut depth_memory = memory::sibling(memory, 0)?;
    let mut depth_by_index = Vec::new();
    memory::reserve_one(&mut depth_by_index, &mut depth_memory)?;
    depth_by_index.push(0_usize);
    let mut queue = QueueState {
        depth_by_index,
        total_output_bytes: source_bytes.len(),
        depth_memory,
    };

    // Each new artifact receives the next index, so a cursor is the same FIFO order
    let mut index = 0;
    while index < report.artifacts.len() {
        process_queue_item(index, options, report, &mut budget, &mut queue, memory)?;
        index += 1;
    }
    Ok((
        budget.work.used,
        options.limits.max_zip_expanded_bytes - budget.zip_remaining,
    ))
}

struct QueueState {
    depth_by_index: Vec<usize>,
    total_output_bytes: usize,
    depth_memory: memory::Charge,
}

fn add_source_artifact(
    source_bytes: &[u8],
    report: &mut ArtifactAnalysis,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let memory::Bytes {
        memory: bytes_memory,
        bytes,
    } = memory::copy_bytes(source_bytes, memory)?;
    let mut origins = Vec::new();
    memory::reserve_one(&mut origins, memory)?;
    origins.push(ArtifactOrigin::Source);
    let sha256 = memory::copy_string(&report.source_sha256, memory)?;
    memory::reserve_one(&mut report.artifacts, memory)?;
    report.artifacts.push(AnalyzedArtifact {
        index: 0,
        origins,
        sha256,
        signature_match_count: 0,
        signatures_scanned: false,
        validation: unsupported_validation(),
        bytes,
    });
    memory::absorb(memory, bytes_memory);
    Ok(())
}

fn process_queue_item(
    index: usize,
    options: ArtifactAnalysisOptions,
    report: &mut ArtifactAnalysis,
    budget: &mut AnalysisBudget,
    queue: &mut QueueState,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let depth = *queue
        .depth_by_index
        .get(index)
        .ok_or(AnalyzerError::AllocationFailure)?;
    if depth > options.limits.max_depth {
        memory::reserve_one(&mut report.omissions, memory)?;
        report.omissions.push(AnalysisOmission::DepthLimit {
            artifact_index: index,
            maximum: options.limits.max_depth,
        });
        return Ok(());
    }

    // The source stays in the report while the child candidates are staged
    let input_bytes = std::mem::take(
        &mut report
            .artifacts
            .get_mut(index)
            .ok_or(AnalyzerError::AllocationFailure)?
            .bytes,
    );
    let context = ArtifactContext {
        index,
        depth,
        input_bytes: &input_bytes,
        limits: options.limits,
    };
    let mut found = PendingArtifacts::new(memory)?;
    let inspection = inspect_artifact(&context, budget, report, &mut found, memory)?;
    restore_inspected_artifact(index, input_bytes, inspection, report)?;
    for candidate in std::mem::take(&mut found.values) {
        add_candidate(report, candidate, queue, options.limits, memory)?;
    }
    Ok(())
}

fn push_omission(
    report: &mut ArtifactAnalysis,
    memory: &mut memory::Charge,
    omission: AnalysisOmission,
) -> Result<(), AnalyzerError> {
    memory::reserve_one(&mut report.omissions, memory)?;
    report.omissions.push(omission);
    Ok(())
}

fn restore_inspected_artifact(
    index: usize,
    bytes: Vec<u8>,
    inspection: ArtifactInspection,
    report: &mut ArtifactAnalysis,
) -> Result<(), AnalyzerError> {
    let artifact = report
        .artifacts
        .get_mut(index)
        .ok_or(AnalyzerError::AllocationFailure)?;
    artifact.bytes = bytes;
    artifact.signature_match_count = inspection.signature_match_count;
    artifact.signatures_scanned = inspection.signatures_scanned;
    artifact.validation = inspection.validation;
    Ok(())
}

fn analysis_status(report: &ArtifactAnalysis) -> AnalysisStatus {
    let incomplete_regions = report.region_transform_reports.iter().any(|entry| {
        !entry.report.coverage.complete
            || entry.report.regions.iter().any(|region| {
                region.proposal_report.omissions
                    != crate::recovery::proposals::TransformProposalOmissions::default()
            })
    });
    if !report.omissions.is_empty() || incomplete_regions {
        AnalysisStatus::Partial
    } else if report.artifacts.iter().any(|artifact| {
        artifact.validation.state == ArtifactValidationState::Validated
            || artifact
                .origins
                .iter()
                .any(|origin| matches!(origin, ArtifactOrigin::Transformation { .. }))
    }) {
        AnalysisStatus::Complete
    } else {
        AnalysisStatus::Unsupported
    }
}

pub(super) fn validate_limits(limits: AnalyzerLimits) -> Result<(), AnalyzerError> {
    for (field, valid) in [
        ("input bytes", limits.max_input_bytes > 0),
        ("artifact count", limits.max_artifacts > 0),
        ("output bytes", limits.max_total_output_bytes > 0),
        ("signature scan bytes", limits.max_signature_scan_bytes > 0),
    ] {
        if !valid {
            return Err(AnalyzerError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn validator_for(limits: AnalyzerLimits) -> Result<ArtifactValidator, AnalyzerError> {
    let mut zip_limits = ZipArtifactLimits::default();
    zip_limits.max_archive_bytes = zip_limits.max_archive_bytes.min(limits.max_input_bytes);
    let policy = ArtifactValidationPolicy {
        max_input_bytes: limits.max_input_bytes,
        png_limits: PngLimits::default(),
        der_limits: DerLimits::default(),
        zip_limits,
    };
    ArtifactValidator::new(policy).map_err(|_| AnalyzerError::InvalidLimit {
        field: "artifact validator",
    })
}

fn embedded_limits(limits: AnalyzerLimits) -> EmbeddedDiscoveryLimits {
    let mut zip_limits = ZipArtifactLimits::default();
    zip_limits.max_archive_bytes = zip_limits.max_archive_bytes.min(limits.max_input_bytes);
    EmbeddedDiscoveryLimits {
        max_scan_bytes: limits.max_input_bytes,
        max_validation_attempts: limits.max_artifacts.saturating_mul(2).max(1),
        max_candidates: limits.max_artifacts,
        png_limits: PngLimits::default(),
        zip_limits,
        max_zip_operation_expanded_bytes: 0,
    }
}

fn derivation_limits(limits: AnalyzerLimits, max_work_bytes: usize) -> DerivationLimits {
    let mut derivation_limits = DerivationLimits::default();
    derivation_limits.max_input_bytes = derivation_limits
        .max_input_bytes
        .min(limits.max_transform_input_bytes);
    derivation_limits.max_output_bytes = derivation_limits
        .max_output_bytes
        .min(limits.max_transform_output_bytes);
    derivation_limits.max_intermediate_bytes = derivation_limits
        .max_intermediate_bytes
        .min(limits.max_transform_output_bytes);
    derivation_limits.max_work_bytes = derivation_limits.max_work_bytes.min(max_work_bytes);
    derivation_limits
}

fn summarize_validation(outcome: &ArtifactValidationOutcome<'_>) -> ValidationSummary {
    match outcome {
        ArtifactValidationOutcome::Validated {
            format,
            range,
            boundary,
            structure,
        } => ValidationSummary {
            state: ArtifactValidationState::Validated,
            format: Some(format_label(*format)),
            boundary: Some(boundary_label(*boundary)),
            range: Some(*range),
            structure_count: structure_count(structure),
        },
        ArtifactValidationOutcome::BoundaryUnproven {
            format, structure, ..
        } => ValidationSummary {
            state: ArtifactValidationState::BoundaryUnproven,
            format: Some(format_label(*format)),
            boundary: None,
            range: None,
            structure_count: structure_count(structure),
        },
        ArtifactValidationOutcome::Rejected { format, .. } => ValidationSummary {
            state: ArtifactValidationState::Rejected,
            format: Some(format_label(*format)),
            boundary: None,
            range: None,
            structure_count: 0,
        },
        ArtifactValidationOutcome::Unsupported { .. } => unsupported_validation(),
        ArtifactValidationOutcome::Omitted { format, .. } => ValidationSummary {
            state: ArtifactValidationState::Omitted,
            format: format.map(format_label),
            boundary: None,
            range: None,
            structure_count: 0,
        },
    }
}

const fn structure_count(structure: &ArtifactStructure<'_>) -> usize {
    match structure {
        ArtifactStructure::Der(report) => report.nodes.len(),
        ArtifactStructure::Executable(report) => report.sections.len(),
        ArtifactStructure::Png(report) => report.chunks.len(),
        ArtifactStructure::Zip(report) => report.entry_count,
    }
}

const fn unsupported_validation() -> ValidationSummary {
    ValidationSummary {
        state: ArtifactValidationState::Unsupported,
        format: None,
        boundary: None,
        range: None,
        structure_count: 0,
    }
}

const fn format_label(format: ArtifactValidationFormat) -> AnalysisFormat {
    match format {
        ArtifactValidationFormat::Der => AnalysisFormat::Der,
        ArtifactValidationFormat::Elf => AnalysisFormat::Elf,
        ArtifactValidationFormat::PortableExecutable => AnalysisFormat::PortableExecutable,
        ArtifactValidationFormat::Png => AnalysisFormat::Png,
        ArtifactValidationFormat::Zip => AnalysisFormat::Zip,
    }
}

const fn boundary_label(boundary: ArtifactBoundaryEvidence) -> AnalysisBoundary {
    match boundary {
        ArtifactBoundaryEvidence::PngIend => AnalysisBoundary::PngIend,
        ArtifactBoundaryEvidence::DerEncodedLength => AnalysisBoundary::DerEncodedLength,
        ArtifactBoundaryEvidence::ZipEndRecord => AnalysisBoundary::ZipEndRecord,
    }
}

/// Construct the exact origin of a member extracted by the canonical ZIP parser
#[must_use]
pub fn archive_member_origin(
    parent_index: usize,
    archive_length: usize,
    metadata: &super::zip::ZipArtifactEntryMetadata,
) -> ArtifactOrigin {
    let (raw_name_sha256, raw_name_hex_preview) = archive_member_name(metadata);
    ArtifactOrigin::ArchiveMember {
        parent_index,
        archive_range: complete_range(archive_length),
        entry_index: metadata.index,
        raw_name_sha256,
        raw_name_hex_preview,
        compressed_size: metadata.compressed_size,
        expanded_size: metadata.expanded_size,
    }
}

/// Construct a member origin anchored to a validated source archive range
#[must_use]
pub fn source_archive_member_origin(
    archive_sha256: &str,
    archive_length: usize,
    metadata: &super::zip::ZipArtifactEntryMetadata,
) -> ArtifactOrigin {
    let (raw_name_sha256, raw_name_hex_preview) = archive_member_name(metadata);
    ArtifactOrigin::SourceArchiveMember {
        archive_range: complete_range(archive_length),
        archive_sha256: archive_sha256.to_owned(),
        entry_index: metadata.index,
        raw_name_sha256,
        raw_name_hex_preview,
        compression_method: metadata.compression_method,
        compressed_size: metadata.compressed_size,
        expanded_size: metadata.expanded_size,
        crc32: metadata.crc32,
        local_header_offset: metadata.local_header_offset,
    }
}

fn archive_member_name(metadata: &super::zip::ZipArtifactEntryMetadata) -> (String, String) {
    (
        sha256(&metadata.raw_name),
        bytes_hex_preview(&metadata.raw_name, 32),
    )
}

fn bytes_hex_preview(bytes: &[u8], maximum: usize) -> String {
    let preview = bytes.get(..bytes.len().min(maximum)).unwrap_or_default();
    let mut output = String::with_capacity(preview.len().saturating_mul(2));
    for byte in preview {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    if value < 10 {
        char::from(b'0' + value)
    } else {
        char::from(b'a' + (value - 10))
    }
}

const fn complete_range(length: usize) -> FileRange {
    FileRange { offset: 0, length }
}

fn add_candidate(
    report: &mut ArtifactAnalysis,
    candidate: PendingArtifact,
    queue: &mut QueueState,
    limits: AnalyzerLimits,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    if candidate.bytes.is_empty() {
        return Ok(());
    }
    let mut digest_memory = memory::sibling(memory, 0)?;
    let digest = memory::digest(&candidate.bytes, &mut digest_memory)?;
    if let Some(index) = report
        .artifacts
        .iter()
        .position(|artifact| artifact.sha256 == digest && artifact.bytes == candidate.bytes)
    {
        return record_duplicate_origin(report, candidate, index, memory);
    }
    let next_total =
        match candidate_output_size(&candidate, report, queue.total_output_bytes, limits) {
            Ok(next_total) => next_total,
            Err(limit) => {
                memory::reserve_one(&mut report.omissions, memory)?;
                report
                    .omissions
                    .push(candidate_limit_omission(limit, &candidate, limits));
                return Ok(());
            }
        };

    let index = report.artifacts.len();
    let mut origins = Vec::new();
    memory::reserve_one(&mut origins, memory)?;
    memory::reserve_one(&mut report.artifacts, memory)?;
    memory::reserve_one(&mut queue.depth_by_index, &mut queue.depth_memory)?;
    let PendingArtifact {
        memory: candidate_memory,
        bytes,
        origin,
        depth,
    } = candidate;
    origins.push(origin);
    let artifact = AnalyzedArtifact {
        index,
        origins,
        sha256: digest,
        signature_match_count: 0,
        signatures_scanned: false,
        validation: unsupported_validation(),
        bytes,
    };
    report.artifacts.push(artifact);
    queue.depth_by_index.push(depth);
    memory::absorb(memory, candidate_memory);
    memory::absorb(memory, digest_memory);
    queue.total_output_bytes = next_total;
    Ok(())
}

fn record_duplicate_origin(
    report: &mut ArtifactAnalysis,
    candidate: PendingArtifact,
    existing_index: usize,
    memory: &mut memory::Charge,
) -> Result<(), AnalyzerError> {
    let existing = report
        .artifacts
        .get_mut(existing_index)
        .ok_or(AnalyzerError::AllocationFailure)?;
    if !existing.origins.contains(&candidate.origin) {
        memory::reserve_one(&mut existing.origins, memory)?;
        let retained = origin_owned_bytes(&candidate.origin)?;
        let PendingArtifact {
            memory: mut candidate_memory,
            bytes,
            origin,
            ..
        } = candidate;
        drop(bytes);
        memory::resize(&mut candidate_memory, retained)?;
        existing.origins.push(origin);
        memory::absorb(memory, candidate_memory);
    }
    Ok(())
}

fn origin_owned_bytes(origin: &ArtifactOrigin) -> Result<usize, AnalyzerError> {
    match origin {
        ArtifactOrigin::ArchiveMember {
            raw_name_sha256,
            raw_name_hex_preview,
            ..
        } => raw_name_sha256
            .capacity()
            .checked_add(raw_name_hex_preview.capacity())
            .ok_or(AnalyzerError::AllocationFailure),
        ArtifactOrigin::SourceArchiveMember {
            archive_sha256,
            raw_name_sha256,
            raw_name_hex_preview,
            ..
        } => archive_sha256
            .capacity()
            .checked_add(raw_name_sha256.capacity())
            .and_then(|bytes| bytes.checked_add(raw_name_hex_preview.capacity()))
            .ok_or(AnalyzerError::AllocationFailure),
        ArtifactOrigin::Transformation { cue_origins, .. } => cue_origins
            .capacity()
            .checked_mul(std::mem::size_of::<RegionCueOrigin>())
            .ok_or(AnalyzerError::AllocationFailure),
        ArtifactOrigin::Source
        | ArtifactOrigin::SourceRange { .. }
        | ArtifactOrigin::EmbeddedObject { .. } => Ok(0),
    }
}

#[derive(Clone, Copy)]
enum CandidateLimit {
    Depth,
    ArtifactCount,
    OutputBytes { remaining: usize },
}

fn candidate_limit_omission(
    limit: CandidateLimit,
    candidate: &PendingArtifact,
    limits: AnalyzerLimits,
) -> AnalysisOmission {
    match limit {
        CandidateLimit::Depth => AnalysisOmission::DepthLimit {
            artifact_index: origin_parent(&candidate.origin).unwrap_or_default(),
            maximum: limits.max_depth,
        },
        CandidateLimit::ArtifactCount => AnalysisOmission::ArtifactLimit {
            maximum: limits.max_artifacts,
        },
        CandidateLimit::OutputBytes { remaining } => AnalysisOmission::OutputLimit {
            parent_index: origin_parent(&candidate.origin).unwrap_or_default(),
            length: candidate.bytes.len(),
            remaining,
        },
    }
}

const fn candidate_output_size(
    candidate: &PendingArtifact,
    report: &ArtifactAnalysis,
    total_output_bytes: usize,
    limits: AnalyzerLimits,
) -> Result<usize, CandidateLimit> {
    if candidate.depth > limits.max_depth {
        return Err(CandidateLimit::Depth);
    }
    if report.artifacts.len() >= limits.max_artifacts {
        return Err(CandidateLimit::ArtifactCount);
    }
    let Some(next_total) = total_output_bytes.checked_add(candidate.bytes.len()) else {
        return Err(CandidateLimit::OutputBytes { remaining: 0 });
    };
    if next_total > limits.max_total_output_bytes {
        return Err(CandidateLimit::OutputBytes {
            remaining: limits
                .max_total_output_bytes
                .saturating_sub(total_output_bytes),
        });
    }
    Ok(next_total)
}

const fn origin_parent(origin: &ArtifactOrigin) -> Option<usize> {
    match origin {
        ArtifactOrigin::Source
        | ArtifactOrigin::SourceRange { .. }
        | ArtifactOrigin::SourceArchiveMember { .. } => None,
        ArtifactOrigin::EmbeddedObject { parent_index, .. }
        | ArtifactOrigin::ArchiveMember { parent_index, .. }
        | ArtifactOrigin::Transformation { parent_index, .. } => Some(*parent_index),
    }
}
