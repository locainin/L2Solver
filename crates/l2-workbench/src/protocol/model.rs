use serde::{Deserialize, Serialize};

pub use crate::measurement::{ByteOrder, LengthMeaning};

/// One caller-labeled message in the supplied capture order
#[derive(Clone, Debug)]
pub struct MessageSample<'a> {
    /// Stable nonzero identifier retained in reports
    pub sample: u64,
    /// Caller-provided message role; role is never inferred from bytes
    pub role: MessageRole,
    /// Exact message bytes selected by the caller
    pub bytes: &'a [u8],
    /// Complete capture context, when this sample belongs to a reconstructed TCP session
    pub context: Option<MessageContext>,
}

/// Context that keeps equal bytes scoped to one capture, network scope, and TCP session
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct MessageContext {
    /// Stable source identity, such as a content-derived capture identifier
    pub source: String,
    /// Stable serialized capture scope
    pub scope: String,
    /// Stable session identifier within the source and scope
    pub session: u64,
    /// Direction relative to the session's canonical endpoint order
    pub direction: Direction,
}

/// Direction label that does not assign client or server roles
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// First canonical endpoint to second canonical endpoint
    FirstToSecond,
    /// Second canonical endpoint to first canonical endpoint
    SecondToFirst,
}

impl Direction {
    pub(super) const fn opposite(self) -> Self {
        match self {
            Self::FirstToSecond => Self::SecondToFirst,
            Self::SecondToFirst => Self::FirstToSecond,
        }
    }
}

/// One contiguous reconstructed directional byte run
#[derive(Clone, Debug)]
pub struct ByteRunSample<'a> {
    /// Stable nonzero identifier retained in reports
    pub sample: u64,
    /// Optional complete capture context
    pub context: Option<MessageContext>,
    /// Exact observed bytes without gaps or conflicting positions
    pub bytes: &'a [u8],
}

/// Configurable protocol input, hypothesis, and report budgets
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolLimits {
    /// Maximum number of input samples or contiguous runs
    pub max_samples: usize,
    /// Maximum bytes in one caller-selected message
    pub max_message_bytes: usize,
    /// Maximum aggregate bytes read from messages or contiguous runs
    pub max_total_bytes: usize,
    /// Maximum bytes scanned from one contiguous TCP run
    pub max_run_bytes: usize,
    /// Inclusive maximum offset considered when inferring length prefixes
    pub max_prefix_offset: usize,
    /// Maximum framing or correlation hypotheses retained
    pub max_candidates: usize,
    /// Maximum boundary examples retained for each hypothesis
    pub max_retained_frames: usize,
    /// Maximum logical storage estimate for retained evidence and report records
    pub max_report_bytes: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_samples: super::MAX_PROTOCOL_SAMPLES,
            max_message_bytes: super::MAX_MESSAGE_BYTES,
            max_total_bytes: super::MAX_PROTOCOL_BYTES,
            max_run_bytes: super::MAX_PROTOCOL_RUN_BYTES,
            max_prefix_offset: super::MAX_PROTOCOL_PREFIX_OFFSET,
            max_candidates: super::MAX_FRAMING_CANDIDATES,
            max_retained_frames: super::MAX_PROTOCOL_RETAINED_FRAMES,
            max_report_bytes: super::MAX_PROTOCOL_REPORT_BYTES,
        }
    }
}

/// Whether discovery and holdout were separated by sample order or session
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldoutBasis {
    /// Samples without session context were split in supplied order
    SampleOrder,
    /// Complete context groups were kept on one side of the split
    CompleteSessions,
}

/// Explicit caller role used by correlation analysis
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// Caller labels this sample as a request
    Request,
    /// Caller labels this sample as a response
    Response,
    /// Message is used for framing only
    Unclassified,
}

/// One framing interpretation generated from discovery messages
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FramingKind {
    /// A byte's first occurrence is the final byte in each tested message
    Delimiter { byte: u8 },
    /// Each tested message has this exact byte size
    FixedSize { bytes: usize },
    /// A one-, two-, four-, or eight-byte integer predicts message size
    LengthPrefix {
        /// Zero-based field offset
        offset: usize,
        /// Field width in bytes
        width: usize,
        /// Byte order under test
        byte_order: ByteOrder,
        /// Relationship between the integer and full message size
        meaning: LengthMeaning,
    },
}

/// One captured mismatch between a candidate and a message sample
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FramingCounterexample {
    /// Caller-supplied sample identifier
    pub sample: u64,
    /// Candidate boundary or size
    pub expected: Option<u64>,
    /// Observed boundary, size, or encoded value
    pub observed: Option<u64>,
}

/// Fit counts and bounded counterexamples for one sample split
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FitSummary {
    /// Number of samples in this split
    pub sample_count: usize,
    /// Samples with enough bytes to test the candidate
    pub compared: usize,
    /// Samples matching the candidate
    pub supported: usize,
    /// Number of contradicting samples
    pub counterexample_count: usize,
    /// Samples too short to test the candidate
    pub untestable_samples: usize,
    /// Bounded counterexample examples
    pub counterexamples: Vec<FramingCounterexample>,
    /// Counterexamples omitted from the bounded examples
    pub omitted_counterexamples: usize,
}

/// Candidate scored independently on discovery and holdout samples
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FramingCandidate {
    /// Explicit candidate interpretation
    pub kind: FramingKind,
    /// Fit among the first half of supplied samples
    pub discovery: FitSummary,
    /// Fit among the remaining samples
    pub holdout: FitSummary,
}

/// Candidate framing interpretations and their deterministic sample split
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FramingReport {
    /// All framing candidates generated from discovery samples
    pub candidates: Vec<FramingCandidate>,
    /// Candidate hypotheses omitted after reaching the configured limit
    pub omitted_candidates: usize,
    /// Sample identifiers used to generate candidates
    pub discovery_samples: Vec<u64>,
    /// Sample identifiers held out from candidate generation
    pub holdout_samples: Vec<u64>,
    /// Basis used to separate discovery from holdout
    pub split_basis: HoldoutBasis,
    /// Inclusive maximum offset searched for inferred length prefixes
    pub prefix_offset_limit: usize,
    /// Limits on interpreting candidate matches
    pub limitations: Vec<&'static str>,
}

/// State assigned to one response under an explicit field hypothesis
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationStatus {
    /// Exactly one earlier request shares the selected field bytes
    Unique,
    /// More than one earlier request shares the selected field bytes
    Ambiguous,
    /// No pending earlier request shares the selected field bytes
    Unmatched,
    /// The response does not contain the complete selected field
    Untestable,
    /// Equal field bytes exist only in a different source, scope, session, or direction
    ContextMismatch,
    /// Equal field bytes exist in another session, but no compatible earlier request exists
    CrossSessionEqual,
}

/// One capture-order response transition under a caller-selected field pair
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FieldTransition {
    /// Response sample identifier
    pub response_sample: u64,
    /// State after comparing only earlier pending requests
    pub status: CorrelationStatus,
    /// Number of earlier requests in the compatible session and opposite direction
    pub candidate_count: usize,
    /// Bounded request IDs when the transition is ambiguous
    pub candidate_requests: Vec<u64>,
    /// Matched request ID when exactly one candidate exists
    pub request_sample: Option<u64>,
    /// Equal earlier requests outside this response's session and direction context
    pub equal_outside_context_count: usize,
    /// Equal earlier requests from another session
    pub cross_session_equal_count: usize,
    /// Bounded equal request IDs outside this response's context
    pub equal_outside_context_requests: Vec<u64>,
    /// Equal request IDs outside context omitted from the bounded examples
    pub omitted_equal_outside_context_requests: usize,
    /// Compatible request IDs omitted from the bounded examples
    pub omitted_candidate_requests: usize,
}

/// Matching transitions for one independently processed sample split
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationSplit {
    /// Sample IDs processed in caller order
    pub samples: Vec<u64>,
    /// Request-to-response transitions in caller order
    pub transitions: Vec<FieldTransition>,
    /// Requests left pending at the end of this split
    pub pending_requests: usize,
    /// Requests whose field bytes were unavailable
    pub untestable_requests: usize,
}

/// Capture-order correlation results for one explicit field-position pair
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationReport {
    /// Request field offset selected by the caller
    pub request_offset: usize,
    /// Response field offset selected by the caller
    pub response_offset: usize,
    /// Field width selected by the caller
    pub width: usize,
    /// Basis used to separate discovery from holdout
    pub split_basis: HoldoutBasis,
    /// Correlation state from the discovery split
    pub discovery: CorrelationSplit,
    /// Correlation state from the independent holdout split
    pub holdout: CorrelationSplit,
    /// Limits on interpreting field equality as a protocol transaction
    pub limitations: Vec<&'static str>,
}

/// One observed request/response field mismatch for a candidate hypothesis
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationCounterexample {
    /// Session containing the two observations, when context was supplied
    pub session: Option<u64>,
    /// Earlier request sample identifier
    pub request_sample: u64,
    /// Later response sample identifier
    pub response_sample: u64,
    /// Request field bytes as lowercase hexadecimal
    pub request_value_hex: String,
    /// Response field bytes as lowercase hexadecimal
    pub response_value_hex: String,
}

/// Session-level fit and bounded counterexamples for one field relationship
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationCandidateFit {
    /// Number of session cohorts in the split
    pub session_count: usize,
    /// Cohorts with at least one earlier request and later response field
    pub compared_sessions: usize,
    /// Cohorts with at least one equal value in the opposite direction
    pub supported_sessions: usize,
    /// Compared cohorts with no equal request/response field pair
    pub counterexample_count: usize,
    /// Cohorts without fields available on both sides
    pub untestable_sessions: usize,
    /// Bounded request/response mismatches
    pub counterexamples: Vec<CorrelationCounterexample>,
    /// Mismatches omitted from the bounded examples
    pub omitted_counterexamples: usize,
}

/// Another field position with the same observed support and contradiction pattern
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationAlias {
    /// Request field offset of the aliased candidate
    pub request_offset: usize,
    /// Response field offset of the aliased candidate
    pub response_offset: usize,
    /// Shared field width
    pub width: usize,
    /// Discovery cohorts supporting the alias
    pub discovery_supported_sessions: usize,
    /// Holdout cohorts supporting the alias
    pub holdout_supported_sessions: usize,
}

/// Candidate equality relationship between explicit request and response fields
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationCandidate {
    /// Candidate request field offset
    pub request_offset: usize,
    /// Candidate response field offset
    pub response_offset: usize,
    /// Candidate field width
    pub width: usize,
    /// Session-cohort results used to generate this candidate
    pub discovery: CorrelationCandidateFit,
    /// Independent session-cohort results
    pub holdout: CorrelationCandidateFit,
    /// Bounded indistinguishable field-position candidates
    pub aliases: Vec<CorrelationAlias>,
    /// Number of aliases omitted by the report bound
    pub omitted_aliases: usize,
}

/// Bounded candidate relationships between request and response cohorts
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorrelationCandidateReport {
    /// Candidate equality relationships retained in deterministic order
    pub candidates: Vec<CorrelationCandidate>,
    /// Sample identifiers used for candidate generation
    pub discovery_samples: Vec<u64>,
    /// Sample identifiers held out from candidate generation
    pub holdout_samples: Vec<u64>,
    /// Basis used to separate discovery from holdout
    pub split_basis: HoldoutBasis,
    /// Candidate relationships omitted after reaching the configured limit
    pub omitted_candidates: usize,
    /// Next observation that can separate currently compatible candidates
    pub next_observation: &'static str,
    /// Limits on interpreting byte equality as an application transaction
    pub limitations: Vec<&'static str>,
}

/// A half-open interval in one contiguous stream
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ByteRange {
    /// First included offset
    pub start: usize,
    /// First excluded offset
    pub end: usize,
}

/// Result state for one candidate interpretation of a stream
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryStatus {
    /// The candidate partitioned every observed byte
    Complete,
    /// The candidate stopped at a partial delimiter or advertised frame
    IncompleteTail,
    /// The candidate encoded a zero or structurally impossible length
    InvalidCandidate,
}

/// Candidate message ranges from applying one explicit framing interpretation
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryCandidate {
    /// Candidate framing interpretation; retained even when another candidate aliases it
    pub kind: FramingKind,
    /// First bounded frame ranges in the supplied run
    pub frames: Vec<ByteRange>,
    /// Total number of complete candidate frames
    pub frame_count: usize,
    /// Frames omitted after the configured report bound
    pub omitted_frames: usize,
    /// Unframed or truncated suffix, if any
    pub trailing: Option<ByteRange>,
    /// Candidate interpretation result
    pub status: BoundaryStatus,
    /// Offset where the candidate could not continue, if any
    pub issue_offset: Option<usize>,
}

/// Indices of retained candidates that produce the same observed partition
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryAliasGroup {
    /// Indices into `BoundaryExtractionReport::candidates`; details are stored once
    pub candidate_indices: Vec<usize>,
}

/// Candidate framing interpretations applied to one contiguous stream
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryExtractionReport {
    /// Caller-supplied run identifier
    pub sample: u64,
    /// Complete capture context, when the source run has one
    pub context: Option<MessageContext>,
    /// Candidate results, with aliases retained
    pub candidates: Vec<BoundaryCandidate>,
    /// Candidate hypotheses omitted after reaching the configured limit
    pub omitted_candidates: usize,
    /// Candidate hypotheses evaluated within the configured search plan
    pub evaluated_candidates: usize,
    /// Evaluated hypotheses whose candidate details did not fit the report budget
    pub omitted_candidate_details: usize,
    /// Alias candidate references omitted because alias metadata did not fit the report budget
    pub omitted_alias_candidates: usize,
    /// Inclusive maximum offset used by configured prefix inference
    pub prefix_offset_limit: usize,
    /// Whether every candidate in the configured search plan was evaluated
    pub search_exhaustive_within_plan: bool,
    /// Whether all evaluated candidate, frame, and alias details were retained
    pub report_details_complete: bool,
    /// Candidate groups whose observed boundaries remain indistinguishable
    pub aliases: Vec<BoundaryAliasGroup>,
    /// Next observation most likely to distinguish remaining candidates
    pub next_observation: &'static str,
    /// Limits on interpreting candidate partitions as message grammar
    pub limitations: Vec<&'static str>,
}

/// Bounded input, candidate, or explicit-field validation failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// At least four samples are needed for a two-part evaluation
    InsufficientSamples { count: usize },
    /// At least one contiguous run is needed for framing bootstrap
    InsufficientRuns { count: usize },
    /// The sample count exceeds the configured ceiling
    TooManySamples { count: usize, maximum: usize },
    /// The derived candidate count exceeds the configured ceiling
    TooManyCandidates { count: usize, maximum: usize },
    /// Context is present for some samples but absent for others
    IncompleteContext { sample: u64 },
    /// Fewer than two context groups are available for an independent holdout
    InsufficientSessionGroups { count: usize },
    /// A context has an empty source/scope or zero session identity
    InvalidContext { sample: u64 },
    /// The source identity for reconstructed byte-run analysis is empty
    InvalidSourceIdentity,
    /// A requested source mapping interval is outside its reconstructed run
    InvalidBoundaryRange {
        start: usize,
        end: usize,
        run_length: usize,
    },
    /// One message exceeds the per-message ceiling
    MessageTooLarge {
        sample: u64,
        length: usize,
        maximum: usize,
    },
    /// The aggregate sample bytes exceed the analysis ceiling
    TotalBytesTooLarge { total: usize, maximum: usize },
    /// One contiguous run exceeds the configured run scan limit
    RunTooLarge {
        sample: u64,
        length: usize,
        maximum: usize,
    },
    /// A sample identifier is zero or repeats in one call
    InvalidSampleId { sample: u64 },
    /// Field width is zero or wider than the supported maximum
    InvalidFieldWidth { width: usize, maximum: usize },
    /// Explicit field extent exceeds the supported message boundary
    InvalidFieldRange {
        offset: usize,
        width: usize,
        maximum: usize,
    },
    /// A configured analysis budget is zero
    InvalidLimits,
    /// Retaining a candidate range failed because memory could not be allocated
    AllocationFailed,
    /// The candidate list is empty
    NoFramingCandidates,
    /// A framing interpretation is invalid or repeats another candidate
    InvalidFramingCandidate,
    /// A parser has already been finalized
    ParserFinalized,
    /// A deserialized parser checkpoint has inconsistent internal evidence
    InvalidParserState,
    /// Supplied bytes are not in increasing stream-offset order
    OutOfOrderChunk { offset: usize, next_offset: usize },
    /// Source ranges do not cover every byte supplied to the parser
    IncompleteSourceMap,
    /// A stream offset or length cannot be represented
    StreamOffsetOverflow,
}
