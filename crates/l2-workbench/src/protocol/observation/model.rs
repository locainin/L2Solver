use super::ObservationError;
use crate::evidence::{ByteMapping, EvidenceStatus, SourceRange};
use crate::measurement::ByteOrder;
use crate::protocol::{
    ByteRange, Direction, FramingKind, MessageContext, MessageRole, MessageSample,
};
use serde::{Deserialize, Serialize};

/// Input bytes with the provenance system that describes their coordinates
#[derive(Clone, Debug)]
pub struct ObservationInput<'a> {
    /// Caller-labeled message and its full capture context
    pub message: MessageSample<'a>,
    /// Literal source mappings or the identity of an already-derived input
    pub provenance: ObservationProvenance<'a>,
}

/// Provenance for the exact bytes in one observation input
#[derive(Clone, Debug)]
pub enum ObservationProvenance<'a> {
    /// Output-relative mappings to literal source file intervals
    Literal {
        /// Existing provenance mappings for the complete input byte slice
        mappings: &'a [ByteMapping],
    },
    /// Coordinates in an already-derived byte view
    Derived {
        /// Stable identity of the transformed or sliced input
        identity: &'a str,
        /// Half-open interval occupied by the complete input in that identity
        range: ByteRange,
    },
}

/// One requested byte interval relative to one selected message
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SampleRange {
    /// Caller-supplied message identifier
    pub sample: u64,
    /// Half-open byte interval within that message
    pub range: ByteRange,
}

/// Bounded work and retention policy for one observation pass
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationLimits {
    /// Maximum input messages considered in caller order
    pub max_samples: usize,
    /// Maximum bytes retained from any one message
    pub max_message_bytes: usize,
    /// Maximum aggregate input bytes considered
    pub max_total_bytes: usize,
    /// Highest candidate length-field offset considered, inclusive
    pub max_prefix_offset: usize,
    /// Maximum length-field hypotheses retained
    pub max_hypotheses: usize,
    /// Maximum analysis steps spent on facts, regions, and constraints
    pub max_work_units: usize,
    /// Maximum raw byte facts retained
    pub max_byte_observations: usize,
    /// Maximum per-message length constraints retained
    pub max_constraints: usize,
    /// Maximum requested region ranges retained
    pub max_region_ranges: usize,
    /// Maximum width of one requested region range
    pub max_region_width: usize,
    /// Maximum exact byte values retained across region groups
    pub max_region_values: usize,
    /// Maximum region occurrences retained across all groups
    pub max_region_occurrences: usize,
    /// Maximum literal source ranges retained for one byte fact
    pub max_origin_ranges_per_observation: usize,
    /// Maximum logical bytes retained in the report
    pub max_report_bytes: usize,
    /// Maximum size of one source or derived identity string
    pub max_identity_bytes: usize,
    /// Maximum literal mappings examined for one input
    pub max_mappings_per_input: usize,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            max_samples: super::super::MAX_PROTOCOL_SAMPLES,
            max_message_bytes: super::super::MAX_MESSAGE_BYTES,
            max_total_bytes: super::super::MAX_PROTOCOL_BYTES,
            max_prefix_offset: super::super::MAX_PROTOCOL_PREFIX_OFFSET,
            max_hypotheses: super::super::MAX_FRAMING_CANDIDATES,
            max_work_units: 2_000_000,
            max_byte_observations: 65_536,
            max_constraints: 262_144,
            max_region_ranges: 4_096,
            max_region_width: 256,
            max_region_values: 16_384,
            max_region_occurrences: 65_536,
            max_origin_ranges_per_observation: 32,
            max_report_bytes: super::super::MAX_PROTOCOL_REPORT_BYTES,
            max_identity_bytes: 1_024,
            max_mappings_per_input: 4_096,
        }
    }
}

/// Explicit byte windows and budgets for an observation pass
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationPlan {
    /// Per-sample byte intervals to compare inside their source messages
    pub region_ranges: Vec<SampleRange>,
    /// Work and report retention ceilings
    pub limits: ObservationLimits,
}

/// Literal source coordinates or derived-view coordinates for one fact
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ObservationOrigin {
    /// Exact interval in a source file or capture
    Literal(SourceRange),
    /// Interval in a named transformed or sliced byte view
    Derived {
        /// Stable identity of the derived input
        identity: String,
        /// Half-open interval in that derived input
        range: ByteRange,
    },
}

/// One retained, source-backed sequence of bytes
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByteObservation {
    /// Caller-supplied message identifier
    pub sample: u64,
    /// Caller-provided role, retained without inferring it from the bytes
    pub role: MessageRole,
    /// Complete source, scope, session, and direction context when available
    pub context: Option<MessageContext>,
    /// Half-open interval relative to the selected message
    pub range: ByteRange,
    /// Exact bytes observed in that interval
    pub bytes: Vec<u8>,
    /// Literal or derived input coordinates that support these bytes
    pub origins: Vec<ObservationOrigin>,
    /// Whether the retained origins cover the whole interval without overlap or gaps
    pub origin_complete: bool,
}

/// One integer decoding of a retained byte observation
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IntegerInterpretation {
    /// Index in [`ObservationReport::byte_observations`]
    pub byte_observation: usize,
    /// Explicit byte ordering used for this interpretation
    pub byte_order: ByteOrder,
    /// Unsigned integer decoded from the exact retained bytes
    pub value: u64,
}

/// Per-sample result for one unverified framing interpretation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintOutcome {
    /// The observed integer equals the candidate's expected message length
    Supported,
    /// The observed integer differs from the candidate's expected message length
    Contradicted,
    /// The input does not contain enough bytes to evaluate the candidate
    Untestable,
}

/// One test of a semantic length hypothesis against one message
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialConstraint {
    /// Caller-supplied message identifier
    pub sample: u64,
    /// Candidate interpretation; equality does not promote it to a fact
    pub hypothesis: FramingKind,
    /// Expected message length under the candidate, when testable
    pub expected: Option<u64>,
    /// Integer observed in the candidate field, when testable
    pub observed: Option<u64>,
    /// Result for this one sample, separate from hypothesis status
    pub outcome: ConstraintOutcome,
    /// The semantic interpretation remains a hypothesis until independently validated
    pub semantic_status: EvidenceStatus,
    /// Index in [`ObservationReport::integer_interpretations`] when retained
    pub integer_interpretation: Option<usize>,
}

/// Session-independent key for comparing facts within one source direction
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ObservationCohort {
    /// Stable source identity; different sources never merge
    pub source: String,
    /// Stable serialized capture scope
    pub scope: String,
    /// Direction relative to the session's canonical endpoint order
    pub direction: Direction,
}

/// One exact byte value observed in a region cohort
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegionValue {
    /// Exact bytes shared by the listed occurrences
    pub bytes: Vec<u8>,
    /// Indices into [`ObservationReport::byte_observations`]
    pub observation_indices: Vec<usize>,
}

/// Work and coverage counts for one requested cohort and byte range
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegionCoverage {
    /// Inputs that requested this cohort and range
    pub requested_occurrences: usize,
    /// Requested inputs with a retained raw byte observation
    pub observed_occurrences: usize,
    /// Inputs whose message did not contain the complete requested range
    pub untestable_occurrences: usize,
    /// Occurrences omitted by work or retention limits
    pub omitted_occurrences: usize,
}

/// Exact values and occurrence coverage for one range in one comparison cohort
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegionObservation {
    /// Source/scope/direction comparison key; session stays on each byte fact
    pub cohort: ObservationCohort,
    /// Half-open range relative to each selected message
    pub range: ByteRange,
    /// Exact value groups, including singletons
    pub values: Vec<RegionValue>,
    /// Requested, observed, untestable, and omitted occurrence counts
    pub coverage: RegionCoverage,
}

/// Aggregate completeness and resource accounting for one bounded pass
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationCoverage {
    /// Number of input samples supplied to the pass
    pub samples_seen: usize,
    /// Number of samples admitted by input byte and count limits
    pub samples_retained: usize,
    /// Input samples skipped after reaching a configured admission limit
    pub omitted_samples: usize,
    /// Aggregate bytes measured in the input window considered under the sample limit
    pub input_bytes_seen: usize,
    /// Samples after the input-count limit whose byte lengths were not examined
    pub input_bytes_unmeasured_samples: usize,
    /// Aggregate bytes admitted for analysis
    pub input_bytes_retained: usize,
    /// Input bytes skipped after reaching a configured admission limit
    pub omitted_input_bytes: usize,
    /// Context records omitted because their source or scope name exceeded the limit
    pub omitted_contexts: usize,
    /// Bytes of source and scope names omitted from context records
    pub omitted_context_bytes: usize,
    /// Length hypotheses generated within the configured cap
    pub hypotheses_retained: usize,
    /// Length hypotheses omitted after reaching their cap
    pub omitted_hypotheses: usize,
    /// Numeric interpretations retained for raw byte facts
    pub integer_interpretations_retained: usize,
    /// Numeric interpretations omitted by report or count limits
    pub omitted_integer_interpretations: usize,
    /// Per-sample constraints retained
    pub constraints_retained: usize,
    /// Per-sample constraints omitted by work, report, or count limits
    pub omitted_constraints: usize,
    /// Raw byte facts retained
    pub byte_observations_retained: usize,
    /// Raw byte facts omitted by work, report, or count limits
    pub omitted_byte_observations: usize,
    /// Literal or derived origin ranges retained
    pub origins_retained: usize,
    /// Origin ranges omitted by work or retention limits
    pub omitted_origins: usize,
    /// Origin mappings whose overlap could not be checked within the work budget
    pub omitted_origin_checks: usize,
    /// Distinct requested ranges retained
    pub region_ranges_retained: usize,
    /// Requested ranges omitted by the region range limit
    pub omitted_region_ranges: usize,
    /// Exact region values retained
    pub region_values_retained: usize,
    /// Exact region values omitted by count or report limits
    pub omitted_region_values: usize,
    /// Region occurrences linked to a retained raw observation
    pub region_occurrences_retained: usize,
    /// Region occurrences omitted by work or retention limits
    pub omitted_region_occurrences: usize,
    /// Requested region occurrences without a comparable source context
    pub unscoped_region_occurrences: usize,
    /// Requested region occurrences with no complete input range
    pub untestable_region_occurrences: usize,
    /// Actual bounded analysis steps performed
    pub work_units: usize,
    /// Work steps skipped after reaching the work ceiling
    pub omitted_work_units: usize,
    /// Logical report bytes retained under the configured ceiling
    pub report_bytes_retained: usize,
    /// True only when all supplied samples, facts, hypotheses, and requested regions fit
    pub complete: bool,
}

/// Source-backed facts, numeric readings, hypotheses, and bounded coverage
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReport {
    /// Retained source-backed byte sequences
    pub byte_observations: Vec<ByteObservation>,
    /// Numeric interpretations of retained raw byte sequences
    pub integer_interpretations: Vec<IntegerInterpretation>,
    /// Per-sample outcomes for unverified length hypotheses
    pub partial_constraints: Vec<PartialConstraint>,
    /// Exact region values grouped only within compatible source cohorts
    pub regions: Vec<RegionObservation>,
    /// Input, work, and retention coverage
    pub coverage: ObservationCoverage,
}

impl From<&MessageContext> for ObservationCohort {
    fn from(context: &MessageContext) -> Self {
        Self {
            source: context.source.clone(),
            scope: context.scope.clone(),
            direction: context.direction,
        }
    }
}

/// Validate a byte range's ordering without guessing whether it fits a message
pub(super) const fn validate_range(range: ByteRange) -> Result<(), ObservationError> {
    if range.start >= range.end {
        return Err(ObservationError::InvalidRange { range });
    }
    Ok(())
}
