//! Public discovery inputs, parameters, and report types

use crate::{
    carrier::Ambiguity,
    derivation::{self, BitRemainder, Constraint},
    evidence::SourceRange,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// One caller-selected sample with its exact byte-to-source mapping
#[derive(Clone, Debug)]
pub struct DiscoverySample<'a> {
    /// Stable, nonzero identifier within the submitted sample set
    pub id: u64,
    /// Stable, nonzero session identifier; sessions may vary within one service cohort
    pub session_id: u64,
    /// Caller-supplied sequence value; it is never inferred from source offsets
    pub sequence: u64,
    /// Exact capture, source, interface, and link-layer scope identity
    pub source_scope: String,
    /// Exact ordered direction identity for this sample set
    pub direction: String,
    /// Exact local endpoint identity for this sample set
    pub local_identity: String,
    /// Bytes retained by the caller or evidence case
    pub bytes: &'a [u8],
    /// Complete output-to-source mapping for every input byte
    pub mappings: Vec<DiscoveryMapping>,
    /// Whether the selected byte or session identity has unresolved alternatives
    pub ambiguity: Ambiguity,
}

/// One output byte interval mapped to a literal source-file interval
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryMapping {
    /// Zero-based byte offset in the selected sample
    pub offset: usize,
    /// Exact byte interval in a retained source
    pub range: SourceRange,
}

/// Reset behavior used while gathering selected bits
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetMode {
    /// Start a new bit group for every supplied sample
    PerSample,
    /// Continue across samples in one session, then reset for the next session
    PerSession,
    /// Continue across all supplied samples in the selected order
    Continuous,
}

/// Explicit order hypothesis for the caller-selected sample set
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleOrder {
    /// Preserve the order in which sample IDs were supplied
    InputOrder,
    /// Order by the supplied sequence, then by stable sample ID
    SequenceAscending,
    /// Reverse the supplied sequence order, then use stable sample ID order
    SequenceDescending,
}

/// Byte representation selected from a native evidence node
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryView {
    /// Use the retained bytes on the selected node
    Bytes,
    /// Decode the transport payload directly from a retained packet node
    Payload,
}

/// Caller-controlled parameter space for a reproducible discovery pass
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPlan {
    /// Selected bits packed into each output byte; valid values are one through eight
    pub widths: Vec<u8>,
    /// Bit position selected from each source byte; valid values are zero through seven
    pub phases: Vec<u8>,
    /// Number of source bytes skipped at the start of each reset unit
    pub start_offsets: Vec<usize>,
    /// Explicit bitstream reset behavior
    pub reset_modes: Vec<ResetMode>,
    /// Explicit sample order hypotheses
    pub sample_orders: Vec<SampleOrder>,
    /// Explicit handling for a final partial output group
    pub remainder: BitRemainder,
    /// Maximum source bytes accepted across the selected samples
    pub max_input_bytes: usize,
    /// Maximum estimated transform and validation work for this invocation
    pub max_work_bytes: usize,
    /// Maximum parameter combinations attempted in this invocation
    pub max_candidates: usize,
    /// Minimum ASCII-printable output run length retained as a candidate observation
    pub minimum_printable_run_bytes: usize,
    /// Maximum encoded bytes retained for source and printable-run receipts
    pub max_report_bytes: usize,
    /// Caller-supplied structural, length, checksum, or authentication checks
    pub constraints: Vec<Constraint>,
}

/// Stable identity that prevents evidence from crossing capture scopes or endpoints
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryIdentity {
    /// Canonical source, interface, and link-layer scope identity
    pub source_scope: String,
    /// Exact directional identity selected by the caller
    pub direction: String,
    /// Exact local endpoint identity selected by the caller
    pub local_identity: String,
}

/// Retained receipt for one complete source-backed input sample
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySampleReceipt {
    /// Stable sample identifier
    pub sample_id: u64,
    /// Session membership retained from the caller or evidence graph
    pub session_id: u64,
    /// Stable input partition shared across every candidate
    pub partition: Partition,
    /// Caller-supplied sequence value
    pub sequence: u64,
    /// Exact scope identity retained for this original sample
    pub source_scope: String,
    /// Original direction including the packet's endpoint tuple
    pub direction: String,
    /// Original local endpoint identity including its port when available
    pub local_identity: String,
    /// Exact input byte count
    pub input_length: usize,
    /// SHA-256 digest of the exact selected input bytes
    pub input_sha256: String,
    /// Complete output-to-source map for these bytes
    pub mappings: Vec<DiscoveryMapping>,
    /// Selected source bit window before each candidate's phase is applied
    pub source_bit_start: usize,
    /// Number of selected source bits before phase selection
    pub source_bit_count: usize,
}

/// Candidate and control partition whose bytes were tested
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Partition {
    Discovery,
    Control,
}

/// Candidate transformation parameters and their exact source bit mapping
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitMappingReceipt {
    /// Zero-based beginning of the selected bit window in each reset unit
    pub start_bit: usize,
    /// Number of source bits between selected bit positions
    pub stride_bits: usize,
    /// Selected bit position within each source byte
    pub phase: u8,
    /// Number of selected bits packed into each output byte
    pub bits_per_byte: u8,
    /// Explicit policy for a final incomplete group
    pub remainder: BitRemainder,
}

/// Output length, ASCII letter case, and check results for one partition
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSummary {
    /// Independent output units under the requested reset mode
    pub unit_count: usize,
    /// Units where the requested bit selection could not be applied
    pub failed_units: usize,
    /// Bytes produced across successful units
    pub output_length: usize,
    /// SHA-256 of successful output bytes in the explicit unit order, when all units passed
    pub output_sha256: Option<String>,
    /// Output-length observations retained without assigning a format meaning
    pub lengths: LengthHypothesis,
    /// ASCII letter case counts retained without assigning a case scheme
    pub case: CaseHypothesis,
    /// Aggregated explicit validation results by plan constraint
    pub constraints: Vec<ConstraintSummary>,
    /// Maximal ASCII-printable output runs with exact contributing source-bit ranges
    pub printable_runs: Vec<PrintableRun>,
    /// Eligible runs omitted after the caller-supplied report budget was reached
    pub printable_runs_omitted: usize,
}

/// One maximal printable byte run from a complete transformed unit
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrintableRun {
    /// Stable identifier within this discovery invocation
    pub run_id: usize,
    /// Candidate transformation that produced the run
    pub candidate_id: usize,
    /// Discovery or held-out control partition
    pub partition: Partition,
    /// Stable unit index within the partition and candidate
    pub unit_index: usize,
    /// Samples joined in the explicit order for this reset unit
    pub sample_ids: Vec<u64>,
    /// Zero-based output byte offset within the transformed unit
    pub output_offset: usize,
    /// Exact ASCII bytes in this printable run
    pub text: String,
    /// Source bytes whose selected bits form the run
    pub source_bit_mappings: Vec<SourceBitMapping>,
}

/// One consecutive source-byte span contributing one selected source bit per byte
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBitMapping {
    /// Zero-based bit index in the concatenated selected output bit stream
    pub output_bit_start: usize,
    /// Number of consecutive selected source bits represented by this range
    pub bit_count: usize,
    /// Exact original bytes that supplied those selected bits
    pub source: SourceRange,
    /// Bit index within each source byte; zero is its most significant bit
    pub source_bit_offset: u8,
    /// Distance between selected source bits in adjacent source bytes
    pub source_stride_bits: u8,
}

/// Measured input/output lengths for the independent transformed units
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LengthHypothesis {
    /// Minimum source unit length
    pub input_minimum: Option<usize>,
    /// Maximum source unit length
    pub input_maximum: Option<usize>,
    /// Minimum successful transformed unit length
    pub output_minimum: Option<usize>,
    /// Maximum successful transformed unit length
    pub output_maximum: Option<usize>,
    /// Number of distinct transformed unit lengths
    pub distinct_output_lengths: usize,
    /// Successful units whose output length equaled their source length
    pub equal_length_units: usize,
}

/// ASCII letter case observations over successful transformed output bytes
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseHypothesis {
    /// ASCII letters in the output
    pub ascii_letters: usize,
    /// Uppercase ASCII letters in the output
    pub uppercase_letters: usize,
    /// Lowercase ASCII letters in the output
    pub lowercase_letters: usize,
    /// ASCII bytes that were not letters
    pub other_ascii_bytes: usize,
    /// Bytes outside ASCII
    pub non_ascii_bytes: usize,
}

/// Aggregated status counts for one caller-declared constraint
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintSummary {
    /// Zero-based position in the input plan
    pub constraint_index: usize,
    /// Constraint class; parameter values that may contain secrets are not copied
    pub kind: ConstraintKind,
    /// Successful validation results
    pub satisfied: usize,
    /// Candidate outputs that contradicted the condition
    pub violated: usize,
    /// Invalid expectations detected by the canonical validator
    pub invalid: usize,
    /// Units where the transform failed before validation
    pub not_evaluated: usize,
}

/// Public constraint kind without copying expected values or key material
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintKind {
    Length,
    Prefix,
    Sha256,
    Utf8,
    Json,
    Crc32,
    AesGcm,
}

/// One candidate in the deterministic bit-plane hypothesis enumeration
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryCandidate {
    /// Stable zero-based candidate number in enumeration order
    pub id: usize,
    /// Selected bit-plane width
    pub width: u8,
    /// Selected source bit position within each source byte
    pub phase: u8,
    /// Number of complete source bytes skipped at the start of each reset unit
    pub source_byte_offset: usize,
    /// Reset behavior applied to samples
    pub reset_mode: ResetMode,
    /// Sample ordering used within each control partition
    pub sample_order: SampleOrder,
    /// Exact source bit mapping parameters
    pub bit_mapping: BitMappingReceipt,
    /// Results over the discovery partition
    pub discovery: Option<PartitionSummary>,
    /// Results over the later held-out control partition, when one exists
    pub control: Option<PartitionSummary>,
    /// Candidate IDs with identical complete discovery output bytes
    pub competitor_count: usize,
    /// Work charged against the deterministic search budget
    pub work_bytes: usize,
}

/// Parameters of identical output candidates are grouped but retained individually
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompetingOutput {
    /// Discovery or control stream represented by this digest
    pub partition: Partition,
    /// Exact digest of a complete output stream
    pub sha256: String,
    /// Candidate IDs that produced the same output bytes
    pub candidate_ids: Vec<usize>,
}

/// Search completion state without making a covert-channel claim
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryLimit {
    WorkBytes,
    CandidateCount,
    PrintableRunReportBytes,
}

/// Full bounded discovery report with source receipts, competing outputs, and controls
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReport {
    /// Scope, direction, and local identity shared by every selected sample
    pub identity: DiscoveryIdentity,
    /// Input samples and exact source-range receipts
    pub sample_receipts: Vec<DiscoverySampleReceipt>,
    /// Cohort packet nodes skipped because the selected payload view was empty
    pub omitted_empty_sample_ids: Vec<u64>,
    /// Number of parameter combinations in the validated plan
    pub parameter_space_size: usize,
    /// Sum of exact selected input byte lengths
    pub input_bytes: usize,
    /// Caller-supplied source-input budget
    pub input_budget_bytes: usize,
    /// Number of candidate combinations actually attempted
    pub attempted_parameters: usize,
    /// Number of reset-unit transforms attempted
    pub attempted_transforms: usize,
    /// Total deterministic work charged to transformations
    pub work_bytes: usize,
    /// Caller-supplied transform and validation work budget
    pub work_budget_bytes: usize,
    /// Caller-supplied candidate-count budget
    pub candidate_budget: usize,
    /// Encoded source receipts and empty-node IDs plus estimated printable-run receipt bytes
    pub report_bytes: usize,
    /// Caller-supplied source and printable-run receipt budget
    pub report_budget_bytes: usize,
    /// False when eligible printable-run receipts exceeded the report budget
    pub printable_runs_complete: bool,
    /// Number of eligible printable runs examined
    pub attempted_printable_runs: usize,
    /// False only when the work ceiling stopped enumeration
    pub enumeration_complete: bool,
    /// Explicit reason enumeration stopped early
    pub limits: Vec<DiscoveryLimit>,
    /// Candidate records in deterministic enumeration order
    pub candidates: Vec<DiscoveryCandidate>,
    /// Exact outputs shared by multiple candidates, by partition
    pub competing_outputs: Vec<CompetingOutput>,
    /// Interpretation limits of this analysis
    pub limitations: Vec<&'static str>,
}

/// A bounded, explicit discovery request or source-evidence failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    InvalidPlan(&'static str),
    InvalidSelection,
    AllocationFailed,
    InputBudgetExceeded { observed: usize, limit: usize },
    ReportBudgetExceeded { limit: usize },
    AmbiguousSample { sample_id: u64 },
    InvalidMapping { sample_id: u64 },
    MixedIdentity,
    MissingNode { node_id: u64 },
    MissingBlob { node_id: u64 },
    UnsupportedNodeKind { node_id: u64 },
    UnresolvedCaseContext { node_id: u64 },
    InvalidCaseMapping { node_id: u64 },
    InvalidPacketPayload { node_id: u64 },
    ResultStore(String),
    Derivation(derivation::DerivationError),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(reason) => write!(formatter, "invalid discovery plan: {reason}"),
            Self::InvalidSelection => {
                formatter.write_str("discovery needs at least one selected node or sample")
            }
            Self::AllocationFailed => formatter
                .write_str("discovery could not reserve memory within the selected budgets"),
            Self::InputBudgetExceeded { observed, limit } => write!(
                formatter,
                "selected input contains {observed} bytes, above the plan budget of {limit}"
            ),
            Self::ReportBudgetExceeded { limit } => write!(
                formatter,
                "complete source mappings exceed the plan report budget of {limit} bytes"
            ),
            Self::AmbiguousSample { sample_id } => write!(
                formatter,
                "sample {sample_id} has unresolved byte or session attribution"
            ),
            Self::InvalidMapping { sample_id } => write!(
                formatter,
                "sample {sample_id} does not have one exact gap-free source mapping"
            ),
            Self::MixedIdentity => formatter
                .write_str("samples cross source scope, direction, or local endpoint identity"),
            Self::MissingNode { node_id } => {
                write!(formatter, "evidence node {node_id} is unavailable")
            }
            Self::MissingBlob { node_id } => {
                write!(formatter, "evidence node {node_id} has no retained bytes")
            }
            Self::UnsupportedNodeKind { node_id } => write!(
                formatter,
                "evidence node {node_id} is not a packet or reconstructed byte node"
            ),
            Self::UnresolvedCaseContext { node_id } => write!(
                formatter,
                "evidence node {node_id} lacks exact scope, direction, order, or session context"
            ),
            Self::InvalidCaseMapping { node_id } => write!(
                formatter,
                "evidence node {node_id} has a missing, invalid, or inconsistent byte mapping receipt"
            ),
            Self::InvalidPacketPayload { node_id } => write!(
                formatter,
                "packet node {node_id} has no complete, unfragmented TCP or UDP payload"
            ),
            Self::ResultStore(reason) => {
                write!(formatter, "discovery result store failed: {reason}")
            }
            Self::Derivation(error) => error.fmt(formatter),
        }
    }
}

impl Error for DiscoveryError {}

impl From<derivation::DerivationError> for DiscoveryError {
    fn from(error: derivation::DerivationError) -> Self {
        Self::Derivation(error)
    }
}
