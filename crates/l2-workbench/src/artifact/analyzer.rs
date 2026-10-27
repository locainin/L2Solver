//! Analyze one byte object through the existing bounded artifact and derivation engines

use super::{
    ArtifactBoundaryEvidence, ArtifactStructure, ArtifactValidationFormat,
    ArtifactValidationOutcome, ArtifactValidationPolicy, ArtifactValidator, DerLimits,
    EmbeddedDiscoveryLimits, EmbeddedFormat, FileRange, PngLimits, scan_file_signatures,
    zip::{ZipArtifactLimits, ZipArtifactOmissionReason},
};
use crate::{
    derivation::{self, DerivationLimits, DerivationStatus, Operation},
    recovery::proposals::{
        TransformEvidence, TransformProposal, TransformProposalBudget, propose_transforms,
        transform_proposal_scan_work_bound,
    },
    recovery::regions::{
        RegionCueOrigin, TransformRegionLimits, TransformRegionReport, propose_region_transforms,
        transform_region_scan_work_bound,
    },
    sha256,
};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, error::Error, fmt};

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
    /// Shared live-memory admission prevented retaining this source for analysis
    SourceMemoryLimit {
        /// Source bytes that were not loaded
        length: u64,
        /// Bytes requested for this source
        requested: u64,
        /// Bytes already charged to the shared job budget
        used: u64,
        /// Aggregate live-memory limit
        maximum: u64,
    },
    /// The shared job budget prevented retaining an evidence artifact
    CaseMemoryLimit {
        /// Additional bytes requested from the shared budget
        requested: u64,
        /// Bytes already charged at the time of admission
        used: u64,
        /// Aggregate live-memory limit
        maximum: u64,
    },
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
    /// Accounted byte work consumed by this analysis
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
        }
    }
}

impl Error for AnalyzerError {}

struct PendingArtifact {
    bytes: Vec<u8>,
    origin: ArtifactOrigin,
    depth: usize,
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

struct TransformExecutionCandidate {
    recipe: crate::derivation::Recipe,
    evidence: TransformEvidence,
    operation: Operation,
    input_range: FileRange,
    cue_origins: Vec<RegionCueOrigin>,
}

fn inspect_artifact(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
) -> Result<ArtifactInspection, AnalyzerError> {
    let (signature_match_count, signatures_scanned) = scan_signatures(context, budget, report);
    let validation = validate_and_expand_zip(context, budget, report, found)?;
    discover_embedded_objects(context, validation, budget, report, found)?;
    derive_candidates(context, budget, report, found)?;
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
) -> (usize, bool) {
    let scan_charge = context.input_bytes.len();
    if scan_charge <= budget.signature_scan_remaining && budget.work.charge(scan_charge) {
        let signatures = scan_file_signatures(context.input_bytes);
        budget.signature_scan_remaining -= scan_charge;
        (signatures.matches.len(), true)
    } else if scan_charge > budget.signature_scan_remaining {
        report.omissions.push(AnalysisOmission::SignatureScanLimit {
            artifact_index: context.index,
            requested: scan_charge,
            remaining: budget.signature_scan_remaining,
        });
        (0, false)
    } else {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::SignatureScan,
            requested: scan_charge,
            remaining: budget.work.remaining,
        });
        (0, false)
    }
}

fn validate_and_expand_zip(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
) -> Result<ValidationSummary, AnalyzerError> {
    let validation_charge = context.input_bytes.len();
    if !budget.work.charge(validation_charge) {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::ArtifactValidation,
            requested: validation_charge,
            remaining: budget.work.remaining,
        });
        return Ok(unsupported_validation());
    }

    let validator = validator_for(context.limits)?;
    let mut parser_zip_remaining = budget.zip_remaining.min(budget.work.remaining);
    let parser_zip_start = parser_zip_remaining;
    let validation =
        validator.validate_with_zip_budget(context.input_bytes, &mut parser_zip_remaining);
    let zip_work = parser_zip_start - parser_zip_remaining;
    budget.zip_remaining -= zip_work;
    let charged_zip_work = budget.work.charge(zip_work);
    debug_assert!(charged_zip_work);

    let summary = summarize_validation(&validation);
    match validation {
        ArtifactValidationOutcome::Validated {
            format: ArtifactValidationFormat::Zip,
            structure: ArtifactStructure::Zip(mut zip_report),
            ..
        } => {
            append_zip_omissions(context.index, &zip_report, report);
            for entry in std::mem::take(&mut zip_report.entries) {
                if let Some(member_bytes) = entry.content {
                    push_pending(
                        found,
                        PendingArtifact {
                            bytes: member_bytes,
                            origin: archive_member_origin(
                                context.index,
                                context.input_bytes.len(),
                                &entry.metadata,
                            ),
                            depth: context.depth.saturating_add(1),
                        },
                    )?;
                }
            }
        }
        ArtifactValidationOutcome::Omitted { format, reason, .. } => {
            report.omissions.push(AnalysisOmission::ValidationLimit {
                artifact_index: context.index,
                format: format.map(format_label),
                reason: format!("{reason:?}"),
            });
        }
        _ => {}
    }
    Ok(summary)
}

fn append_zip_omissions(
    artifact_index: usize,
    zip_report: &super::zip::ZipArtifactReport,
    report: &mut ArtifactAnalysis,
) {
    if zip_report.omitted_entry_count == 0 {
        return;
    }
    for entry in &zip_report.entries {
        if let Some(reason) = entry.omission {
            report.omissions.push(AnalysisOmission::ZipMember {
                artifact_index,
                entry_index: entry.metadata.index,
                reason,
            });
        }
    }
}

fn discover_embedded_objects(
    context: &ArtifactContext<'_>,
    validation: ValidationSummary,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
) -> Result<(), AnalyzerError> {
    let discovery_charge = context.input_bytes.len();
    if !budget.work.charge(discovery_charge) {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::EmbeddedDiscovery,
            requested: discovery_charge,
            remaining: budget.work.remaining,
        });
        return Ok(());
    }

    let mut discovery_limits = embedded_limits(context.limits);
    // ZIP members were expanded by validation; discovery only finds exact ranges
    discovery_limits.max_zip_operation_expanded_bytes = 0;
    let skip_start_format =
        embedded_format_for_validated_full_range(validation, context.input_bytes.len());
    let discovery = super::embedded::discover_embedded_objects_with_work_and_skip_start(
        context.input_bytes,
        discovery_limits,
        budget.work.remaining,
        skip_start_format,
    )
    .map_err(|_| AnalyzerError::AllocationFailure)?;
    let charged_discovery_work = budget.work.charge(discovery.validation_input_bytes);
    debug_assert!(charged_discovery_work);
    if discovery.omissions.output_candidate_count > 0
        || discovery.omissions.unvalidated_candidate_count > 0
        || discovery.omissions.unscanned_range.is_some()
    {
        report.omissions.push(AnalysisOmission::EmbeddedDiscovery {
            artifact_index: context.index,
            output_candidates: discovery.omissions.output_candidate_count,
            unvalidated_candidates: discovery.omissions.unvalidated_candidate_count,
            zip_entry_count_limited: discovery.omissions.zip_entry_count_limited,
            unscanned_range: discovery.omissions.unscanned_range,
        });
    }
    for candidate in discovery.candidates {
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
        push_pending(
            found,
            PendingArtifact {
                bytes: try_copy_bytes(candidate_bytes)?,
                origin: ArtifactOrigin::EmbeddedObject {
                    parent_index: context.index,
                    range: candidate.range,
                    format: candidate.format,
                },
                depth: context.depth.saturating_add(1),
            },
        )?;
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
    found: &mut Vec<PendingArtifact>,
) -> Result<(), AnalyzerError> {
    if context.input_bytes.len() > context.limits.max_transform_input_bytes {
        report
            .omissions
            .push(AnalysisOmission::TransformInputLimit {
                artifact_index: context.index,
                length: context.input_bytes.len(),
                maximum: context.limits.max_transform_input_bytes,
            });
        return Ok(());
    }
    let Some(proposal_charge) = transform_proposal_scan_work_bound(context.input_bytes.len())
    else {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::TransformProposal,
            requested: usize::MAX,
            remaining: budget.work.remaining,
        });
        return Ok(());
    };
    if !budget.work.charge(proposal_charge) {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::TransformProposal,
            requested: proposal_charge,
            remaining: budget.work.remaining,
        });
        return Ok(());
    }

    let proposals = propose_transforms(
        context.input_bytes,
        TransformProposalBudget {
            max_candidates: 7,
            max_reports: 7,
        },
    );
    let complete_range = complete_range(context.input_bytes.len());
    let whole_input_candidates = proposals
        .proposals
        .into_iter()
        .map(|proposal| execution_candidate(proposal, complete_range, Vec::new()))
        .collect::<Result<Vec<_>, _>>()?;
    execute_transform_candidates(context, budget, report, found, whole_input_candidates)?;
    derive_region_candidates(context, budget, report, found)
}

fn derive_region_candidates(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
) -> Result<(), AnalyzerError> {
    let input_length = context.input_bytes.len();
    let region_limits = TransformRegionLimits::for_input(input_length);
    let Some(proposal_charge) = transform_region_scan_work_bound(region_limits) else {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::TransformProposal,
            requested: usize::MAX,
            remaining: budget.work.remaining,
        });
        return Ok(());
    };
    if !budget.work.charge(proposal_charge) {
        report.omissions.push(AnalysisOmission::WorkLimit {
            artifact_index: context.index,
            stage: AnalysisStage::TransformProposal,
            requested: proposal_charge,
            remaining: budget.work.remaining,
        });
        return Ok(());
    }

    let region_report = propose_region_transforms(
        context.input_bytes,
        &[],
        region_limits,
        TransformProposalBudget {
            max_candidates: 7,
            max_reports: 7,
        },
    );
    let mut candidates = Vec::new();
    for region in &region_report.regions {
        let input_range = FileRange {
            offset: region.range.start,
            length: region.range.end - region.range.start,
        };
        for proposal in region.proposal_report.proposals.iter().cloned() {
            candidates.push(execution_candidate(
                proposal,
                input_range,
                region.cue_origins.clone(),
            )?);
        }
    }
    report
        .region_transform_reports
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    report
        .region_transform_reports
        .push(ArtifactRegionTransformReport {
            artifact_index: context.index,
            report: region_report,
        });
    execute_transform_candidates(context, budget, report, found, candidates)
}

fn execution_candidate(
    proposal: TransformProposal,
    input_range: FileRange,
    cue_origins: Vec<RegionCueOrigin>,
) -> Result<TransformExecutionCandidate, AnalyzerError> {
    let operation = proposal
        .recipe
        .steps
        .last()
        .cloned()
        .ok_or(AnalyzerError::AllocationFailure)?;
    Ok(TransformExecutionCandidate {
        recipe: proposal.recipe,
        evidence: proposal.evidence,
        operation,
        input_range,
        cue_origins,
    })
}

fn execute_transform_candidates(
    context: &ArtifactContext<'_>,
    budget: &mut AnalysisBudget,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
    proposals: Vec<TransformExecutionCandidate>,
) -> Result<(), AnalyzerError> {
    for proposal in proposals {
        if budget.work.remaining == 0 {
            report.omissions.push(AnalysisOmission::WorkLimit {
                artifact_index: context.index,
                stage: AnalysisStage::TransformExecution,
                requested: 1,
                remaining: 0,
            });
            break;
        }
        let derivation_limits = derivation_limits(context.limits, budget.work.remaining);
        let result =
            derivation::run_with_limits(context.input_bytes, &proposal.recipe, derivation_limits);
        match result {
            Ok(derivation) => {
                if !budget.work.charge(derivation.work_bytes) {
                    report.omissions.push(AnalysisOmission::WorkLimit {
                        artifact_index: context.index,
                        stage: AnalysisStage::TransformExecution,
                        requested: derivation.work_bytes,
                        remaining: budget.work.remaining,
                    });
                    continue;
                }
                record_transform_result(context, proposal, derivation, report, found)?;
            }
            Err(error) => report.omissions.push(AnalysisOmission::TransformFailed {
                artifact_index: context.index,
                operation: proposal.operation,
                message: error.to_string(),
            }),
        }
    }
    Ok(())
}

fn record_transform_result(
    context: &ArtifactContext<'_>,
    proposal: TransformExecutionCandidate,
    result: derivation::DerivationReport,
    report: &mut ArtifactAnalysis,
    found: &mut Vec<PendingArtifact>,
) -> Result<(), AnalyzerError> {
    if result.status != DerivationStatus::Completed {
        report.omissions.push(AnalysisOmission::TransformFailed {
            artifact_index: context.index,
            operation: proposal.operation,
            message: format!("canonical operation stopped at step {:?}", result.status),
        });
    } else if !result.output.is_empty() && result.output != context.input_bytes {
        push_pending(
            found,
            PendingArtifact {
                bytes: result.output,
                origin: ArtifactOrigin::Transformation {
                    parent_index: context.index,
                    input_range: proposal.input_range,
                    operation: proposal.operation,
                    evidence: proposal.evidence,
                    cue_origins: proposal.cue_origins,
                },
                depth: context.depth.saturating_add(1),
            },
        )?;
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
    validate_limits(options.limits)?;
    if !crate::hashing::is_sha256_digest(source_sha256) {
        return Err(AnalyzerError::InvalidSourceHash);
    }
    let mut report = empty_analysis_report(bytes.len(), source_sha256);
    if let Some(omission) = source_input_omission(bytes.len(), options.limits) {
        report.omissions.push(omission);
        report.status = AnalysisStatus::Partial;
        return Ok(report);
    }
    let (work_bytes, zip_expanded_work_bytes) = analyze_queue(bytes, options, &mut report)?;
    report.work_bytes = work_bytes;
    report.zip_expanded_work_bytes = zip_expanded_work_bytes;
    let has_validated_object = report
        .artifacts
        .iter()
        .any(|artifact| artifact.validation.state == ArtifactValidationState::Validated);
    if options.recovery == RecoveryMode::Salvage && !has_validated_object {
        // No current partial-repair parser can safely rebuild unsupported bytes
        report.omissions.push(AnalysisOmission::SalvageUnsupported);
    }
    report.status = analysis_status(&report);
    Ok(report)
}

fn empty_analysis_report(source_length: usize, source_sha256: &str) -> ArtifactAnalysis {
    ArtifactAnalysis {
        source_sha256: source_sha256.to_owned(),
        source_length,
        artifacts: Vec::new(),
        status: AnalysisStatus::Unsupported,
        omissions: Vec::new(),
        region_transform_reports: Vec::new(),
        work_bytes: 0,
        zip_expanded_work_bytes: 0,
    }
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
) -> Result<(usize, usize), AnalyzerError> {
    add_source_artifact(source_bytes, report)?;
    let mut total_output_bytes = source_bytes.len();
    let mut budget = AnalysisBudget::new(options.limits);
    let mut pending = VecDeque::new();
    pending
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    pending.push_back(0_usize);
    let mut depth_by_index = vec![0_usize];

    while let Some(index) = pending.pop_front() {
        process_queue_item(
            index,
            options,
            report,
            &mut budget,
            &mut total_output_bytes,
            &mut depth_by_index,
            &mut pending,
        )?;
    }
    Ok((
        budget.work.used,
        options.limits.max_zip_expanded_bytes - budget.zip_remaining,
    ))
}

fn add_source_artifact(
    source_bytes: &[u8],
    report: &mut ArtifactAnalysis,
) -> Result<(), AnalyzerError> {
    let bytes = try_copy_bytes(source_bytes)?;
    let mut origins = Vec::new();
    origins
        .try_reserve_exact(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    origins.push(ArtifactOrigin::Source);
    report
        .artifacts
        .try_reserve_exact(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    report.artifacts.push(AnalyzedArtifact {
        index: 0,
        origins,
        sha256: report.source_sha256.clone(),
        signature_match_count: 0,
        signatures_scanned: false,
        validation: unsupported_validation(),
        bytes,
    });
    Ok(())
}

fn process_queue_item(
    index: usize,
    options: ArtifactAnalysisOptions,
    report: &mut ArtifactAnalysis,
    budget: &mut AnalysisBudget,
    total_output_bytes: &mut usize,
    depth_by_index: &mut Vec<usize>,
    pending: &mut VecDeque<usize>,
) -> Result<(), AnalyzerError> {
    let depth = *depth_by_index
        .get(index)
        .ok_or(AnalyzerError::AllocationFailure)?;
    if depth > options.limits.max_depth {
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
    let mut found = Vec::new();
    let inspection = inspect_artifact(&context, budget, report, &mut found)?;
    restore_inspected_artifact(index, input_bytes, inspection, report)?;
    for candidate in found {
        add_candidate(
            report,
            candidate,
            total_output_bytes,
            depth_by_index,
            pending,
            options.limits,
        )?;
    }
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
    ArtifactOrigin::ArchiveMember {
        parent_index,
        archive_range: complete_range(archive_length),
        entry_index: metadata.index,
        raw_name_sha256: sha256(&metadata.raw_name),
        raw_name_hex_preview: bytes_hex_preview(&metadata.raw_name, 32),
        compressed_size: metadata.compressed_size,
        expanded_size: metadata.expanded_size,
    }
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

fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, AnalyzerError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn push_pending(
    pending: &mut Vec<PendingArtifact>,
    candidate: PendingArtifact,
) -> Result<(), AnalyzerError> {
    pending
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    pending.push(candidate);
    Ok(())
}

fn add_candidate(
    report: &mut ArtifactAnalysis,
    candidate: PendingArtifact,
    total_output_bytes: &mut usize,
    depth_by_index: &mut Vec<usize>,
    pending: &mut VecDeque<usize>,
    limits: AnalyzerLimits,
) -> Result<(), AnalyzerError> {
    if candidate.bytes.is_empty() {
        return Ok(());
    }
    let digest = sha256(&candidate.bytes);
    if record_duplicate_origin(report, &candidate, &digest)? {
        return Ok(());
    }
    let next_total = match candidate_output_size(&candidate, report, *total_output_bytes, limits) {
        Ok(next_total) => next_total,
        Err(limit) => {
            report
                .omissions
                .push(candidate_limit_omission(limit, &candidate, limits));
            return Ok(());
        }
    };

    let index = report.artifacts.len();
    let mut origins = Vec::new();
    origins
        .try_reserve_exact(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    origins.push(candidate.origin);
    let artifact = AnalyzedArtifact {
        index,
        origins,
        sha256: digest,
        signature_match_count: 0,
        signatures_scanned: false,
        validation: unsupported_validation(),
        bytes: candidate.bytes,
    };
    report
        .artifacts
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    depth_by_index
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    pending
        .try_reserve(1)
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    report.artifacts.push(artifact);
    depth_by_index.push(candidate.depth);
    pending.push_back(index);
    *total_output_bytes = next_total;
    Ok(())
}

fn record_duplicate_origin(
    report: &mut ArtifactAnalysis,
    candidate: &PendingArtifact,
    digest: &str,
) -> Result<bool, AnalyzerError> {
    let Some(existing_index) = report
        .artifacts
        .iter()
        .position(|artifact| artifact.sha256 == digest && artifact.bytes == candidate.bytes)
    else {
        return Ok(false);
    };
    let existing = report
        .artifacts
        .get_mut(existing_index)
        .ok_or(AnalyzerError::AllocationFailure)?;
    if !existing.origins.contains(&candidate.origin) {
        existing
            .origins
            .try_reserve(1)
            .map_err(|_| AnalyzerError::AllocationFailure)?;
        existing.origins.push(candidate.origin.clone());
    }
    Ok(true)
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
        ArtifactOrigin::Source | ArtifactOrigin::SourceRange { .. } => None,
        ArtifactOrigin::EmbeddedObject { parent_index, .. }
        | ArtifactOrigin::ArchiveMember { parent_index, .. }
        | ArtifactOrigin::Transformation { parent_index, .. } => Some(*parent_index),
    }
}
