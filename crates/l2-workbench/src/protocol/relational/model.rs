use crate::{
    artifact::{
        ArtifactResourceOmissionReason, ArtifactValidationFailure, ArtifactValidationFormat,
    },
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
};
use serde::Serialize;
use std::{cmp::Ordering, error::Error, fmt};

/// One exact message in a reconstructed session with its observed direction and bytes
#[derive(Clone, Debug)]
pub struct RelationalRecordSample<'a> {
    /// Stable nonzero sample identity retained in checks
    pub sample: u64,
    /// Capture source, scope, session, and direction for this message
    pub context: crate::protocol::MessageContext,
    /// Stable capture-order key for this session, independent of Case node insertion order
    pub session_order: u64,
    /// Complete observed message bytes
    pub bytes: &'a [u8],
}

/// Bounded domains for session-relative locator and transform discovery
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationalTransformLimits {
    /// Maximum distinct source/scope/framing/schema cohorts retained by recovery
    pub max_cohorts: usize,
    /// Maximum number of complete sessions supplied to the analysis
    pub max_sessions: usize,
    /// Maximum messages retained for one session
    pub max_records_per_session: usize,
    /// Maximum bytes accepted from one message
    pub max_record_bytes: usize,
    /// Maximum aggregate bytes accepted across all messages
    pub max_total_bytes: usize,
    /// Maximum marker width used to identify a message family
    pub max_marker_bytes: usize,
    /// Inclusive maximum marker offset in each message
    pub max_marker_offset: usize,
    /// Maximum bytes read from each session-specific seed range
    pub max_seed_bytes: usize,
    /// Inclusive maximum seed or payload offset considered in each message
    pub max_locator_offset: usize,
    /// Maximum valid seed or payload locators retained for each locator role
    pub max_locator_candidates: usize,
    /// Maximum transform configurations attempted
    pub max_candidates: usize,
    /// Maximum retained rules; the limit is shared across locator pairs and their configurations
    pub max_retained_candidates: usize,
    /// Maximum canonical derivation work charged across discovery and holdout
    pub max_work_bytes: usize,
}

impl Default for RelationalTransformLimits {
    fn default() -> Self {
        Self {
            max_cohorts: 128,
            max_sessions: 32,
            max_records_per_session: 256,
            max_record_bytes: crate::protocol::MAX_MESSAGE_BYTES,
            max_total_bytes: crate::protocol::MAX_PROTOCOL_BYTES,
            max_marker_bytes: 2,
            max_marker_offset: 8,
            max_seed_bytes: 32,
            max_locator_offset: 16,
            max_locator_candidates: 8_192,
            max_candidates: 65_536,
            max_retained_candidates: 512,
            max_work_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Finite SHA-256 counter-XOR family and parser constraints for rule discovery
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalTransformPlan {
    /// Input, candidate, work, and report bounds for this search
    pub limits: RelationalTransformLimits,
    /// Scope in which the exact structural parser must accept transformed bytes
    pub parser_scope: RelationalParserScope,
    /// Exact structural parsers that can falsify a decoded byte-range hypothesis
    pub parser_formats: Vec<ArtifactValidationFormat>,
    /// Encodings tested for the counter appended or prepended to each digest input
    pub counter_widths: Vec<CounterWidth>,
    /// Byte orders tested for each serialized counter
    pub counter_byte_orders: Vec<CounterByteOrder>,
    /// Orders tested for seed bytes and counter bytes in each SHA-256 input
    pub seed_orders: Vec<SeedCounterOrder>,
    /// Explicit first counter values tested for each located payload
    pub initial_counters: Vec<u64>,
    /// Whether counter blocks continue across selected records or restart per record
    pub counter_resets: Vec<RelationalCounterReset>,
}

impl Default for RelationalTransformPlan {
    fn default() -> Self {
        Self {
            limits: RelationalTransformLimits::default(),
            parser_scope: RelationalParserScope::EachSession,
            parser_formats: vec![ArtifactValidationFormat::Png, ArtifactValidationFormat::Zip],
            counter_widths: vec![
                CounterWidth::OneByte,
                CounterWidth::TwoBytes,
                CounterWidth::FourBytes,
                CounterWidth::EightBytes,
            ],
            counter_byte_orders: vec![CounterByteOrder::BigEndian, CounterByteOrder::LittleEndian],
            seed_orders: vec![
                SeedCounterOrder::SeedThenCounter,
                SeedCounterOrder::CounterThenSeed,
            ],
            initial_counters: vec![0, 1],
            counter_resets: vec![
                RelationalCounterReset::Continuous,
                RelationalCounterReset::PerRecord,
            ],
        }
    }
}

/// Unit whose transformed bytes must satisfy the selected structural parser
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalParserScope {
    /// Each complete session must contain one exact parser-accepted object
    EachSession,
    /// Ordered outputs from the frozen session cohort are checked as one object
    AcrossSessions,
}

/// How counter state is applied when a selector matches multiple payload records
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalCounterReset {
    /// Concatenate selected payload ranges and continue counters across the stream
    Continuous,
    /// Start the configured counter separately for each selected payload record
    PerRecord,
}

/// Marker and byte range learned independently from each session's messages
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RelationalByteRangeLocator {
    /// Direction of messages selected by the marker
    pub direction: crate::protocol::Direction,
    /// Offset of the stable marker in each selected message
    pub marker_offset: usize,
    /// Marker bytes observed during discovery and checked again on held-out sessions
    pub marker: Vec<u8>,
    /// Start of the located value or payload, relative to the message start
    pub value_offset: usize,
    /// Fixed seed length; `None` means payload bytes extend through each message end
    pub value_length: Option<usize>,
    /// Optional integer field immediately before the located seed, frozen from discovery
    pub declared_length: Option<RelationalLengthField>,
}

/// Integer field checked against the located seed length in every session
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RelationalLengthField {
    /// Start of the length field relative to the selected message
    pub offset: usize,
    /// Number of bytes used to encode the field
    pub width: CounterWidth,
    /// Byte order used to decode the field
    pub byte_order: crate::protocol::ByteOrder,
}

impl Ord for RelationalLengthField {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.offset,
            self.width.byte_length(),
            byte_order_rank(self.byte_order),
        )
            .cmp(&(
                other.offset,
                other.width.byte_length(),
                byte_order_rank(other.byte_order),
            ))
    }
}

impl PartialOrd for RelationalLengthField {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn byte_order_rank(byte_order: crate::protocol::ByteOrder) -> u8 {
    match byte_order {
        crate::protocol::ByteOrder::BigEndian => 0,
        crate::protocol::ByteOrder::LittleEndian => 1,
    }
}

/// Explicit parameters for one discovered SHA-256 counter-XOR rule
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RelationalSha256CounterXor {
    /// First block counter used for each message or continuous stream
    pub initial_counter: u64,
    /// Number of bytes used to serialize each counter
    pub counter_width: CounterWidth,
    /// Byte order used to serialize each counter
    pub counter_byte_order: CounterByteOrder,
    /// Order of the session seed and serialized counter in each hash input
    pub seed_order: SeedCounterOrder,
}

/// Frozen rule locating session-specific material and ciphertext ranges
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalTransformRule {
    /// Locator that selects exactly one seed-bearing message in each session
    pub seed_locator: RelationalByteRangeLocator,
    /// Locator that selects one or more ciphertext messages in each session
    pub payload_locator: RelationalByteRangeLocator,
    /// Explicit SHA-256 counter-XOR parameters
    pub operation: RelationalOperationTemplate,
    /// Counter reset rule for multiple selected payload messages
    pub counter_reset: RelationalCounterReset,
    /// Unit whose transformed bytes must satisfy the selected structural parser
    pub parser_scope: RelationalParserScope,
    /// Strict parser selected to test the complete transformed range
    pub parser_format: ArtifactValidationFormat,
}

/// Exact output from replaying one frozen rule against one complete session
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalAppliedOutput {
    /// Session checked by the rule
    pub session: RelationalSessionId,
    /// Capture-order key used when combining independently transformed sessions
    pub session_order: u64,
    /// Sample whose located range supplied this session's seed bytes
    pub seed_sample: u64,
    /// Payload samples used in their retained capture order
    pub payload_samples: Vec<u64>,
    /// Half-open ranges aligned with payload samples in the concatenated decoded bytes
    pub payload_ranges: Vec<crate::protocol::ByteRange>,
    /// Complete transformed bytes for this session
    pub bytes: Vec<u8>,
    /// True when the rule's parser scope was validated during this session replay
    pub parser_validation_deferred: bool,
    /// Canonical derivation work consumed while replaying the rule
    pub work_bytes: usize,
}

/// Read-only context supplied to an evaluator before candidate retention
#[derive(Clone, Copy, Debug)]
pub struct RelationalTransformEvaluationContext<'a> {
    /// Complete sessions used to learn the frozen rule
    pub discovery_sessions: &'a [RelationalSessionId],
    /// Complete sessions used to falsify the frozen rule
    pub heldout_sessions: &'a [RelationalSessionId],
    /// Remaining shared search and structural-evaluation work allowance
    pub work_bytes_remaining: usize,
}

/// Output and assessment bounds for evaluated candidate retention
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelationalTransformEvaluationOptions {
    /// Maximum combined decoded output bytes retained for selected candidates
    ///
    /// This is validated against the plan's aggregate byte limit
    /// A zero value disables output capture
    pub max_retained_output_bytes: usize,
}

/// Deterministic priority and caller-owned evidence produced by a candidate evaluator
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalCandidateEvaluation<T> {
    /// Higher values replace lower-priority retained candidates; ties keep earlier candidates
    pub priority: u8,
    /// Structural-evaluation work charged to the shared plan budget
    pub work_bytes: usize,
    /// Compact structural result or caller-specific evidence for the retained candidate
    pub assessment: T,
}

/// Decoded outputs captured for one retained candidate
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalCandidateOutputs {
    /// Successful same-pass outputs from discovery sessions
    pub discovery: Vec<RelationalAppliedOutput>,
    /// Successful same-pass outputs from held-out sessions
    pub heldout: Vec<RelationalAppliedOutput>,
}

/// Caller assessment aligned with one candidate in the evaluated report
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalRetainedEvaluation<T> {
    /// Caller assessment made before candidate retention
    pub assessment: T,
    /// Captured outputs, absent when capture was disabled or the byte bound was reached
    pub outputs: Option<RelationalCandidateOutputs>,
}

/// Search report and bounded evaluator results for retained candidates
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalCandidateEvaluationReport<T> {
    /// Search accounting and retained frozen rules
    pub report: RelationalTransformReport,
    /// Evaluations aligned by index with `report.candidates`
    pub evaluations: Vec<RelationalRetainedEvaluation<T>>,
    /// Decoded output bytes retained across all candidate evaluations
    pub output_bytes_retained: usize,
    /// Retained candidates whose output bytes could not fit the configured byte bound
    pub output_capture_omissions: usize,
    /// Whether every retained candidate output set requested by the byte bound was captured
    pub output_capture_complete: bool,
}

/// Search or evaluator failure from callback-based candidate retention
#[derive(Debug)]
#[non_exhaustive]
pub enum RelationalEvaluationError<E> {
    /// Candidate discovery or canonical replay failed
    Search(RelationalTransformError),
    /// The caller-provided evaluator failed
    Evaluator(E),
    /// The evaluator reported more work than remained in the shared search budget
    EvaluatorWorkLimit { requested: usize, remaining: usize },
}

impl<E> fmt::Display for RelationalEvaluationError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(error) => write!(formatter, "relational search: {error}"),
            Self::Evaluator(error) => write!(formatter, "relational candidate evaluation: {error}"),
            Self::EvaluatorWorkLimit {
                requested,
                remaining,
            } => write!(
                formatter,
                "relational candidate evaluator used {requested} work bytes; {remaining} remained"
            ),
        }
    }
}

impl<E> Error for RelationalEvaluationError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::Evaluator(error) => Some(error),
            Self::EvaluatorWorkLimit { .. } => None,
        }
    }
}

impl<E> From<RelationalTransformError> for RelationalEvaluationError<E> {
    fn from(error: RelationalTransformError) -> Self {
        Self::Search(error)
    }
}

/// Explicit family and finite parameters for a relational transformation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "family", content = "parameters", rename_all = "snake_case")]
pub enum RelationalOperationTemplate {
    /// SHA-256 counter blocks `XORed` with each selected payload range
    Sha256CounterXor(RelationalSha256CounterXor),
}

impl RelationalOperationTemplate {
    /// Return the finite parameters when this template selects SHA-256 counter-XOR
    #[must_use]
    pub(super) const fn sha256_counter_xor(self) -> RelationalSha256CounterXor {
        match self {
            Self::Sha256CounterXor(parameters) => parameters,
        }
    }
}

/// Source identity for one complete context group
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RelationalSessionId {
    /// Capture source identity
    pub source: String,
    /// Capture scope identity
    pub scope: String,
    /// Session identity within the source and scope
    pub session: u64,
}

/// Whether all selected sessions supported or falsified a frozen rule
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalFitStatus {
    /// Every complete session in this split passed the selected parser and exact-range check
    ConstraintsSatisfied,
    /// Locators and transforms passed; artifact parsing is deferred to the full session cohort
    TransformConstraintsSatisfied,
    /// At least one session contradicted the locator, transform, or parser constraint
    Contradicted,
    /// Resource limits prevented a complete result for this split
    UnresolvedOnBudget,
    /// Rule generation did not produce a discovery fit, so holdout was not run
    NotEvaluated,
}

/// Exact reason that one session failed a frozen locator or parser rule
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationalFalsification {
    /// Marker selected no seed-bearing message or more than one such message
    SeedMessageCount { observed: usize },
    /// Marker selected no payload-bearing message
    NoPayloadMessages,
    /// The located seed did not fit within its selected message
    SeedRangeUnavailable,
    /// The seed's declared-length field was truncated or decoded to a different value
    SeedLengthMismatch {
        /// Fixed seed length established during discovery
        expected: usize,
        /// Decoded field value; absent when the selected message did not contain the field
        observed: Option<u64>,
    },
    /// A selected payload message had no bytes after its located offset
    EmptyPayloadRange,
    /// The canonical transform rejected the supplied parameters or bytes
    TransformFailed { reason: String },
    /// The selected parser rejected the transformed bytes
    ParserRejected {
        format: ArtifactValidationFormat,
        reason: ArtifactValidationFailure,
    },
    /// The parser inspected a candidate but did not prove its format-defined end
    BoundaryUnproven { format: ArtifactValidationFormat },
    /// The parser accepted only a proper subrange of the transformed bytes
    ParserRangeMismatch {
        format: ArtifactValidationFormat,
        offset: usize,
        length: usize,
    },
    /// The selected parser could not identify an applicable structure
    ParserUnsupported { format: ArtifactValidationFormat },
    /// The parser could not finish under its explicit resource policy
    ParserOmitted {
        format: ArtifactValidationFormat,
        reason: ArtifactResourceOmissionReason,
    },
}

/// One per-session result for a frozen locator, transform, and parser rule
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalSessionCheck {
    /// Complete session context checked by this rule
    pub session: RelationalSessionId,
    /// Messages used to resolve the seed and payload locators
    pub seed_sample: Option<u64>,
    /// Every selected payload message in capture order
    pub payload_samples: Vec<u64>,
    /// Result state for the exact parser and range checks
    pub status: RelationalFitStatus,
    /// Output length when the transform completed
    pub output_length: Option<usize>,
    /// Output digest when the transform completed
    pub output_sha256: Option<String>,
    /// Exact contradiction or unresolved parser result
    pub falsification: Option<RelationalFalsification>,
}

/// Discovery or held-out support and counterexamples for one frozen rule
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalFit {
    /// Aggregate status for the sessions in this split
    pub status: RelationalFitStatus,
    /// Sessions that passed the locator, transform, and exact parser checks
    pub supported_sessions: Vec<RelationalSessionId>,
    /// Sessions that falsified at least one required condition
    pub contradicted_sessions: Vec<RelationalSessionId>,
    /// Sessions whose result could not be resolved under the configured limits
    pub unresolved_sessions: Vec<RelationalSessionId>,
    /// Per-session receipts retained for every examined member
    pub checks: Vec<RelationalSessionCheck>,
}

/// Why bounded rule discovery stopped before all configured hypotheses were tested
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalSearchLimit {
    /// The maximum number of transform configurations was reached
    CandidateCount,
    /// The aggregate canonical derivation work ceiling was reached
    WorkBytes,
    /// A seed or payload locator domain reached its independent bound
    LocatorCount,
    /// The total or per-pair retained rule bound omitted one or more reports
    RetainedCandidates,
}

/// One locator and transform candidate scored on separate session sets
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalTransformCandidate {
    /// Frozen locator and transform rule; no training-session seed is embedded
    pub rule: RelationalTransformRule,
    /// Evidence used to generate and evaluate the rule
    pub discovery: RelationalFit,
    /// Independent checks against the held-out session set, when available
    pub heldout: RelationalFit,
    /// Summary of independent support, contradiction, or discovery-only evidence
    pub status: RelationalTransformStatus,
}

/// Overall result state for a relational transform candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalTransformStatus {
    /// Discovery constraints passed but no independent session was available for corroboration
    DiscoveryOnlyHypothesis,
    /// The frozen rule passed the exact parser checks for every held-out session
    HeldoutConstraintsSatisfied,
    /// Frozen locator and transform checks passed; the across-session parser gate is pending
    AwaitingAcrossSessionValidation,
    /// At least one held-out session contradicted the frozen rule
    ContradictedByHeldoutSession,
    /// Discovery support was incomplete, so held-out application was not justified
    DiscoveryContradicted,
    /// Work or report bounds prevented a conclusive held-out result
    UnresolvedOnBudget,
}

/// Full session split, retained rules, exact tested count, and remaining budgets
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationalTransformReport {
    /// Complete-session partition used to prevent training and holdout leakage
    pub split_basis: crate::protocol::HoldoutBasis,
    /// Sessions used to discover locator and transform rules
    pub discovery_sessions: Vec<RelationalSessionId>,
    /// Sessions withheld until every candidate rule was frozen
    pub heldout_sessions: Vec<RelationalSessionId>,
    /// Retained supported, falsified, or unresolved rule candidates
    pub candidates: Vec<RelationalTransformCandidate>,
    /// Number of transform configurations actually applied
    pub candidates_examined: usize,
    /// Number of one-byte counter byte-order configurations skipped as exact aliases
    pub equivalent_candidate_aliases: usize,
    /// Number of reportable candidates omitted after the report-retention ceiling
    pub omitted_candidates: usize,
    /// Whether the omitted count covers every untested or unretained rule
    pub omitted_candidates_exact: bool,
    /// Remaining transform-attempt allowance; exact even when the search stops early
    pub candidate_limit_remaining: usize,
    /// Number of seed and payload locators generated before their independent bounds
    pub locator_candidates_examined: usize,
    /// Remaining seed-plus-payload locator allowance
    pub locator_candidate_limit_remaining: usize,
    /// Canonical derivation work charged across discovery and held-out checks
    pub work_bytes: usize,
    /// Remaining canonical derivation work allowance
    pub work_bytes_remaining: usize,
    /// Whether every configuration admitted by the locator and family plan was tested
    pub search_exhaustive_within_plan: bool,
    /// Every candidate, work, locator, or report ceiling reached during discovery
    pub search_limits: Vec<RelationalSearchLimit>,
    /// First explicit limit reached, retained for concise summaries
    pub search_limit: Option<RelationalSearchLimit>,
}

/// Invalid sample, search plan, parser policy, or derivation execution
#[derive(Debug)]
pub enum RelationalTransformError {
    /// The selected search plan violates one of its explicit constraints
    InvalidPlan(&'static str),
    /// The input cohort violates one of its explicit constraints
    InvalidInput(&'static str),
    /// A sample is larger than the configured per-message bound
    RecordTooLarge {
        sample: u64,
        length: usize,
        maximum: usize,
    },
    /// Aggregate message bytes exceed the configured input bound
    TotalBytesTooLarge { total: usize, maximum: usize },
    /// The input contains more complete sessions than the configured bound
    TooManySessions { count: usize, maximum: usize },
    /// The input contains too many messages for one session
    TooManyRecords {
        session: u64,
        count: usize,
        maximum: usize,
    },
    /// A bounded allocation failed before a candidate report could be retained
    AllocationFailed,
    /// The canonical derivation executor rejected its explicit operation
    Derivation(crate::derivation::DerivationError),
    /// A frozen rule no longer satisfies its locators, transform, or parser
    RuleContradicted(String),
    /// Replay stopped because its caller supplied work allowance was insufficient
    RuleWorkLimit,
    /// The shared recovery job was cancelled or could not record progress
    Job(crate::job::JobError),
}

impl fmt::Display for RelationalTransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(message) | Self::InvalidInput(message) => {
                formatter.write_str(message)
            }
            Self::RecordTooLarge {
                sample,
                length,
                maximum,
            } => write!(
                formatter,
                "sample {sample} has {length} bytes; maximum is {maximum}"
            ),
            Self::TotalBytesTooLarge { total, maximum } => {
                write!(
                    formatter,
                    "relational input has {total} bytes; maximum is {maximum}"
                )
            }
            Self::TooManySessions { count, maximum } => {
                write!(
                    formatter,
                    "relational input has {count} sessions; maximum is {maximum}"
                )
            }
            Self::TooManyRecords {
                session,
                count,
                maximum,
            } => write!(
                formatter,
                "session {session} has {count} records; maximum is {maximum}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("relational discovery could not reserve bounded storage")
            }
            Self::Derivation(error) => write!(formatter, "relational derivation: {error}"),
            Self::RuleContradicted(reason) => {
                write!(formatter, "relational rule contradicted: {reason}")
            }
            Self::RuleWorkLimit => {
                formatter.write_str("relational rule replay exceeded its work allowance")
            }
            Self::Job(error) => write!(formatter, "relational recovery job failed: {error}"),
        }
    }
}

impl Error for RelationalTransformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Derivation(error) => Some(error),
            Self::Job(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crate::derivation::DerivationError> for RelationalTransformError {
    fn from(error: crate::derivation::DerivationError) -> Self {
        Self::Derivation(error)
    }
}

impl From<crate::job::JobError> for RelationalTransformError {
    fn from(error: crate::job::JobError) -> Self {
        Self::Job(error)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Selector {
    pub(super) direction: crate::protocol::Direction,
    pub(super) marker_offset: usize,
    pub(super) marker: Vec<u8>,
}
