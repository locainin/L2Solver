use crate::{
    evidence::{ByteMapping, SourceRange},
    measurement::Clock,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// Maximum bytes in one verified sample
pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024;
/// Maximum reconstructed bytes across one extraction request
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum source ranges attached to one sample
pub const MAX_SAMPLE_RANGES: usize = 1024;
/// Maximum source ranges read across one extraction request
pub const MAX_TOTAL_RANGES: usize = 131_072;
/// Maximum distinct verified source handles
pub const MAX_SOURCES: usize = 256;
/// Maximum samples in one extraction request
pub const MAX_SAMPLES: usize = 4096;
/// Maximum caller-selected carrier rules
pub const MAX_RULES: usize = 32;
/// Maximum retained carrier observations
pub const MAX_OBSERVATIONS: usize = 65_536;
/// Maximum retained source ranges in a report
pub const MAX_REPORT_RANGES: usize = 131_072;
/// Maximum retained projected values in a report
pub const MAX_REPORT_VALUE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum detailed omissions retained while total counts continue to grow
pub const MAX_OMISSION_DETAILS: usize = 256;
/// Maximum event identity size in UTF-8 bytes
pub const MAX_EVENT_ID_BYTES: usize = 128;

/// Caller-selected identity ambiguity retained with each extracted value
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Ambiguity {
    /// One source mapping and event assignment were supplied
    #[default]
    None,
    /// Multiple source or event assignments remain possible
    MultipleCandidates,
}

/// Exact timebase value attached to a caller-ordered event sample
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSample {
    /// Capture clock identity and resolution
    pub clock: Clock,
    /// Exact source ticks, or a retained missing timestamp
    pub ticks: Option<u64>,
}

/// One mapped sample selected for carrier extraction
pub struct Sample<'a> {
    /// Stable nonzero identifier within the extraction request
    pub id: u64,
    /// Caller-provided event identity used only to group order and timing
    pub event_id: Option<&'a str>,
    /// Caller-provided ordering value; no order is inferred from source offsets
    pub sequence: Option<u64>,
    /// Length of the selected exact byte view
    pub length: usize,
    /// Output-to-source mappings that must cover and agree on every selected byte
    pub mappings: &'a [ByteMapping],
    /// Source timestamp metadata for timing extraction
    pub time: Option<ClockSample>,
    /// Whether source or event attribution remains ambiguous
    pub ambiguity: Ambiguity,
}

/// Order in which bits are read from each source byte
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitOrder {
    /// Read bit seven through bit zero
    MostSignificantFirst,
    /// Read bit zero through bit seven
    LeastSignificantFirst,
}

/// Explicit byte order for an unsigned numeric field
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericByteOrder {
    /// Most significant byte is stored first
    BigEndian,
    /// Least significant byte is stored first
    LittleEndian,
}

/// Bounded width for an unsigned field without truncation
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldWidth {
    /// One byte
    One,
    /// Two bytes
    Two,
    /// Four bytes
    Four,
    /// Eight bytes
    Eight,
}

impl FieldWidth {
    /// Return this field's exact byte count
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }
}

/// Caller-specified numeric field projection
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// Zero-based field offset in the selected sample
    pub offset: usize,
    /// Exact width; values are returned as full unsigned integers
    pub width: FieldWidth,
    /// Byte order supplied by the caller
    pub byte_order: NumericByteOrder,
}

/// Candidate meaning retained with an explicitly selected length field
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LengthMeaning {
    /// Candidate field represents the complete selected sample length
    WholeMessage,
    /// Candidate field represents bytes after the field
    BytesAfterField,
}

/// Explicit carrier projections; no rule is inferred from input content
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rule {
    /// Exact mapped bytes
    Bytes,
    /// Source bits packed in the requested read order
    Bits { order: BitOrder },
    /// Exact selected sample length
    MessageLength,
    /// Explicit unsigned length field and caller-stated interpretation
    LengthField {
        field: Field,
        meaning: LengthMeaning,
    },
    /// Caller-provided event sequence value
    Sequence,
    /// Explicit unsigned order field read from sample bytes
    OrderField { field: Field },
    /// Adjacent event timing under exact supplied clocks
    Timing,
    /// Labels in an explicit uncompressed DNS wire name field
    DnsLabels {
        /// Zero-based start of the encoded name in the selected sample
        offset: usize,
        /// Apply ASCII lowercase only for equality keys; raw label bytes remain available
        ascii_case_fold: bool,
    },
    /// ASCII uppercase/lowercase pattern over all ASCII letters
    Capitalization,
}

/// Exact projected carrier value
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    /// Exact selected bytes
    Bytes { bytes: Vec<u8> },
    /// Packed sequence of source bits with its exact logical bit length
    Bits {
        order: BitOrder,
        bit_length: u64,
        packed: Vec<u8>,
    },
    /// Unsigned length, order, or numeric field value
    Unsigned { value: u64 },
    /// One exact DNS label and its selected comparison form
    DnsLabel { raw: Vec<u8>, comparison: Vec<u8> },
    /// One byte per ASCII letter; one means uppercase and zero means lowercase
    Capitalization { pattern: Vec<u8> },
    /// One adjacent timing interval with exact clock applicability
    Timing {
        /// Caller-provided sequence value for the earlier sample
        from_sequence: Option<u64>,
        /// Caller-provided sequence value for the later sample
        to_sequence: Option<u64>,
        /// Exact source ticks for the earlier sample, when available
        from_ticks: Option<u64>,
        /// Exact source ticks for the later sample, when available
        to_ticks: Option<u64>,
        delta_ticks: Option<u64>,
        status: TimingStatus,
        left_clock: Option<Clock>,
        right_clock: Option<Clock>,
    },
}

/// Exact status for an adjacent timing projection
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingStatus {
    /// Exact nonnegative source tick difference under one shared timebase
    Measured,
    /// One sample has no timestamp
    MissingTimestamp,
    /// Source tick values move backwards
    Backwards,
    /// Capture scopes differ
    ScopeMismatch,
    /// Clock identity or resolution differs
    ClockMismatch,
    /// Caller sequence is missing or not increasing
    OrderUnresolved,
    /// Event identity or source clocks do not provide a usable interval
    Unsupported,
}

/// One extracted projection with exact source evidence and caller rule
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// Stable one-based identifier within this report
    pub id: u64,
    /// One sample, or both endpoints for a timing interval
    pub sample_ids: Vec<u64>,
    /// Caller event identity, if the projection has one
    pub event_id: Option<String>,
    /// Extraction rule, including offsets, widths, and order parameters
    pub rule: Rule,
    /// Optional component index for repeated values such as DNS labels
    pub component_index: Option<usize>,
    /// Exact value, withheld when a requested projection could not be evaluated
    pub value: Option<Value>,
    /// Source ranges supporting the projected value or interval
    pub ranges: Vec<SourceRange>,
    /// Identity ambiguity carried from source selection
    pub ambiguity: Ambiguity,
}

/// Reason a requested carrier projection was omitted or unresolved
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    /// A required event sequence value was absent
    MissingSequence,
    /// A timed sample did not have an event identity
    MissingEventIdentity,
    /// A timing group did not contain a pair
    InsufficientTimingSamples,
    /// A requested numeric field exceeded sample bounds
    FieldOutOfBounds,
    /// The selected DNS name was incomplete or malformed
    InvalidDnsName,
    /// DNS compression prevents a one-to-one local source range mapping
    CompressedDnsName,
    /// A DNS root name contained no non-root labels
    EmptyDnsName,
    /// A report retention limit omitted the selected projection
    ReportBudget,
    /// A projection was dispatched to the wrong extraction path
    UnsupportedRule,
    /// A requested timing interval could not be measured
    TimingUnresolved,
}

/// One bounded, explicit omission record
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Omission {
    /// Affected sample or interval's first sample, when known
    pub sample_id: Option<u64>,
    /// Rule that requested the omitted projection
    pub rule: Rule,
    /// Why no exact value was retained
    pub reason: OmissionReason,
}

/// One source-backed member of an exact projection relationship
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipMember {
    /// Local observation identifier
    pub observation_id: u64,
    /// Caller sample identifier
    pub sample_id: u64,
    /// Caller event identity, if supplied
    pub event_id: Option<String>,
    /// Exact ranges supporting this member
    pub ranges: Vec<SourceRange>,
    /// Attribution uncertainty retained for review
    pub ambiguity: Ambiguity,
}

/// Cross-source or cross-event exact-value equality, without causal meaning
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    /// Shared extraction rule
    pub rule: Rule,
    /// Digest of the canonical comparable projection value
    pub value_sha256: String,
    /// Source-backed members of this exact equality group
    pub members: Vec<RelationshipMember>,
    /// Total exact-value members before report retention limits
    pub member_count: usize,
    /// Members omitted because source-range or group limits were reached
    pub omitted_members: usize,
    /// Whether members reference more than one content-derived source
    pub cross_sources: bool,
    /// Whether known event identities differ
    pub cross_events: bool,
    /// Highest ambiguity present in any member
    pub ambiguity: Ambiguity,
}

/// Bounded carrier results; completeness covers extraction and report retention
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Exact requested projections and their parameters
    pub rules: Vec<Rule>,
    /// Whether all requested extraction and relationship work completed
    pub complete: bool,
    /// Exact projected values and provenance
    pub observations: Vec<Observation>,
    /// Exact cross-source or cross-event value relationships
    pub relationships: Vec<Relationship>,
    /// Bounded explanations for omitted projections
    pub omissions: Vec<Omission>,
    /// Total omissions, including detail records beyond the retention limit
    pub omitted_count: usize,
}

/// Validation, verification, and budget failure for carrier operations
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierError {
    /// A source identity is not `sha256:` plus 64 lowercase hexadecimal digits
    InvalidSourceId,
    /// The source reader's exact length differs from its declared length
    SourceLengthMismatch,
    /// The source reader's bytes do not match its content-derived identity
    SourceHashMismatch,
    /// The verified source changed before a requested range was read
    SourceChanged,
    /// Source seek or read failed
    SourceIo,
    /// A requested byte range is invalid or points to another source
    InvalidSourceRange,
    /// A source range cannot fit the bounded in-memory read
    RangeTooLarge,
    /// The selected sample is empty or over its byte limit
    InvalidSampleLength,
    /// Mapped source ranges disagree on a selected byte
    ConflictingRanges,
    /// Mapped source ranges leave selected bytes unsupported
    IncompleteMapping,
    /// Mapped source bytes disagree with the retained sample bytes
    SampleContentMismatch,
    /// A sample identifier repeats or is zero
    InvalidSampleId,
    /// An event identity is empty, too long, or contains control characters
    InvalidEventId,
    /// Too many sources, samples, rules, ranges, or inputs were supplied
    RequestLimit,
    /// Rules are empty or repeated
    InvalidRules,
    /// The selected sample is not suitable for the existing bounded search API
    SearchInputLimit,
    /// Existing hypothesis search rejected its explicit plan
    SearchPlan,
    /// Existing derivation rejected its explicit recipe
    DerivationRecipe,
    /// Composition recipe was empty or exceeded a fixed bound
    InvalidCompositionRecipe,
    /// A composition selector matched multiple extraction observations
    AmbiguousCompositionPart,
    /// A selected projection and its explicit output encoding disagree
    InvalidCompositionEncoding,
    /// A value exceeded its explicitly selected output representation
    CompositionOverflow,
    /// Explicit length division used a zero divisor
    CompositionArithmetic,
    /// Extraction or a selected carrier did not produce a complete stream
    IncompleteComposition,
    /// A projected value could not be serialized for canonical comparison
    Serialization,
}

impl fmt::Display for CarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSourceId => "invalid content-derived source identity",
            Self::SourceLengthMismatch => "source length did not match its declaration",
            Self::SourceHashMismatch => "source bytes did not match their content identity",
            Self::SourceChanged => "verified source changed before its range was read",
            Self::SourceIo => "source seek or read failed",
            Self::InvalidSourceRange => "source range was invalid or referenced another source",
            Self::RangeTooLarge => "source range exceeded the bounded byte limit",
            Self::InvalidSampleLength => "sample length was empty or exceeded its limit",
            Self::ConflictingRanges => "source ranges disagreed on a selected byte",
            Self::IncompleteMapping => "source ranges did not cover every selected byte",
            Self::SampleContentMismatch => "source mappings do not match retained node bytes",
            Self::InvalidSampleId => "sample identifiers must be unique and nonzero",
            Self::InvalidEventId => "event identity was empty, oversized, or contained controls",
            Self::RequestLimit => "carrier request exceeded a fixed resource limit",
            Self::InvalidRules => "carrier rules were empty or repeated",
            Self::SearchInputLimit => "sample exceeded the existing hypothesis-search input limit",
            Self::SearchPlan => "existing hypothesis search rejected the supplied plan",
            Self::DerivationRecipe => "existing derivation rejected the supplied recipe",
            Self::InvalidCompositionRecipe => {
                "composition recipe was empty or exceeded its fixed limit"
            }
            Self::AmbiguousCompositionPart => "composition selector matched multiple observations",
            Self::InvalidCompositionEncoding => {
                "selected projection did not match its explicit encoding"
            }
            Self::CompositionOverflow => {
                "projected value exceeded its explicit output representation"
            }
            Self::CompositionArithmetic => "explicit length arithmetic was undefined",
            Self::IncompleteComposition => {
                "selected projections did not produce a complete byte stream"
            }
            Self::Serialization => "carrier value could not be encoded canonically",
        };
        formatter.write_str(message)
    }
}

impl Error for CarrierError {}
