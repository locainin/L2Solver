use super::super::RecordLengthMeaning;
use super::super::discovery::{
    RecordDiscoveryLimits, RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace,
};
use crate::protocol::{ByteOrder, ByteRange};
use crate::protocol::{
    MAX_COUNTEREXAMPLES, MAX_FRAMING_CANDIDATES, MAX_PROTOCOL_PREFIX_OFFSET, MAX_PROTOCOL_SAMPLES,
};

// One-byte integers have a single meaningful byte order
const SINGLE_BYTE_ORDERS: [ByteOrder; 1] = [ByteOrder::BigEndian];
// Wider integer fields support both byte orders
const MULTI_BYTE_ORDERS: [ByteOrder; 2] = [ByteOrder::BigEndian, ByteOrder::LittleEndian];

// Count every valid integer field, payload boundary, byte order, and length meaning
const fn derive_length_check_domain(maximum_offset: usize) -> Option<usize> {
    let [first_width, second_width, third_width, fourth_width] = INTEGER_WIDTHS;
    let Some(total) = add_width_domain(0, first_width, maximum_offset) else {
        return None;
    };
    let Some(total) = add_width_domain(total, second_width, maximum_offset) else {
        return None;
    };
    let Some(total) = add_width_domain(total, third_width, maximum_offset) else {
        return None;
    };
    add_width_domain(total, fourth_width, maximum_offset)
}

const fn add_width_domain(mut total: usize, width: usize, maximum_offset: usize) -> Option<usize> {
    let order_count = if width == SINGLE_BYTE_ORDERS.len() {
        SINGLE_BYTE_ORDERS.len()
    } else {
        MULTI_BYTE_ORDERS.len()
    };
    let mut offset = 0_usize;
    loop {
        // Include a boundary only when the integer field ends within the prefix domain
        let Some(field_end) = offset.checked_add(width) else {
            return None;
        };
        if field_end <= maximum_offset {
            // Count boundaries after the field and all supported interpretations
            let Some(remaining) = maximum_offset.checked_sub(field_end) else {
                return None;
            };
            let Some(boundary_count) = remaining.checked_add(1) else {
                return None;
            };
            let Some(ordered_checks) = boundary_count.checked_mul(order_count) else {
                return None;
            };
            let Some(checks) = ordered_checks.checked_mul(LENGTH_MEANINGS.len()) else {
                return None;
            };
            let Some(updated_total) = total.checked_add(checks) else {
                return None;
            };
            total = updated_total;
        }
        if offset == maximum_offset {
            break;
        }
        let Some(next_offset) = offset.checked_add(1) else {
            return None;
        };
        offset = next_offset;
    }
    Some(total)
}

const DEFAULT_MAX_LENGTH_CHECKS: usize =
    match derive_length_check_domain(MAX_PROTOCOL_PREFIX_OFFSET) {
        Some(count) => count,
        None => panic!("default length-check domain overflowed"),
    };

/// Budgets for deriving record field domains from already framed messages
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecordSchemaProposalLimits {
    /// Candidate evaluation limits shared with canonical record discovery
    pub discovery: RecordDiscoveryLimits,
    /// Inclusive largest field start and payload boundary considered
    pub max_field_offset: usize,
    /// Maximum raw field layouts examined in each field domain
    pub max_field_checks_per_domain: usize,
    /// Maximum identifier and sequence field pairs checked for ordering invariants
    pub max_pair_checks: usize,
    /// Maximum length field, meaning, and payload boundary combinations checked
    pub max_length_checks: usize,
}

impl Default for RecordSchemaProposalLimits {
    fn default() -> Self {
        Self {
            discovery: RecordDiscoveryLimits {
                max_candidates: MAX_FRAMING_CANDIDATES,
                max_messages: MAX_PROTOCOL_SAMPLES,
                max_survivors: MAX_FRAMING_CANDIDATES,
                max_falsifications: MAX_COUNTEREXAMPLES,
                record_limits: super::super::RecordLimits::default(),
            },
            max_field_offset: MAX_PROTOCOL_PREFIX_OFFSET,
            max_field_checks_per_domain: MAX_FRAMING_CANDIDATES,
            max_pair_checks: MAX_FRAMING_CANDIDATES,
            max_length_checks: DEFAULT_MAX_LENGTH_CHECKS,
        }
    }
}

impl RecordSchemaProposalLimits {
    pub(super) fn validate(self) -> Result<(), super::super::RecordDiscoveryError> {
        if self.discovery.max_candidates == 0
            || self.discovery.max_messages == 0
            || self.discovery.max_survivors == 0
            || self.discovery.max_falsifications == 0
            || self.max_field_checks_per_domain == 0
            || self.max_pair_checks == 0
            || self.max_length_checks == 0
        {
            return Err(super::super::RecordDiscoveryError::InvalidLimits);
        }
        super::super::parse::validate_assembly_limits(self.discovery.record_limits)
            .map_err(super::super::RecordDiscoveryError::RecordOperation)
    }
}

/// Holdout material available after bounded candidate generation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordSchemaProposalValidationBasis {
    /// No held-out messages were supplied; candidates remain discovery-only
    DiscoveryOnly,
    /// Caller-separated held-out messages are available for canonical parser validation
    HeldOutMessagesAvailable,
}

impl RecordSchemaProposalValidationBasis {
    /// Stable machine-readable validation label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiscoveryOnly => "discovery_only",
            Self::HeldOutMessagesAvailable => "held_out_messages_available",
        }
    }
}

/// Bounded record field domains proposed from training messages
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaProposalReport {
    /// Whether caller supplied held-out messages for later parser validation
    pub validation_basis: RecordSchemaProposalValidationBasis,
    /// Number of messages used to derive field domains
    pub training_message_count: usize,
    /// Number of messages kept out of candidate generation
    pub held_out_message_count: usize,
    /// Independent projections of candidate fields; their product may include unsupported relations
    pub candidate_space: Option<RecordSchemaDiscoverySpace>,
    /// Compatible pair and length-layout combinations when the count fits in `usize`
    pub candidate_combinations: Option<usize>,
    /// Raw field layouts examined across identifier and integer field domains
    pub examined_field_checks: usize,
    /// Checks skipped in visited field domains; work-limit stops can leave later domains uncounted
    pub omitted_field_checks: usize,
    /// Identifier and sequence field pairs checked for ordering invariants
    pub examined_pair_checks: usize,
    /// Checks skipped in visited pair domains; work-limit stops can leave later domains uncounted
    pub omitted_pair_checks: usize,
    /// Length field, meaning, and payload boundary combinations checked
    pub examined_length_checks: usize,
    /// Length checks not reached under the length cap or shared work budget
    pub omitted_length_checks: usize,
    /// Layout/view associations excluded by the view cap or left unprocessed at a work-limit stop
    /// A source span is counted once for each distinct layout that uses it
    pub omitted_record_views: usize,
    /// Bounded record spans selected by repeated-boundary analysis in training-message order
    pub repeated_boundary_cues: Vec<RecordBoundaryCue>,
    /// Compatible combinations beyond the configured canonical parser candidate budget
    pub omitted_schema_combinations: Option<usize>,
    /// Whether all bounded candidate-generation checks and schema combinations were examined
    pub search_exhaustive_within_plan: bool,
    /// Whether the work-byte budget stopped generation before all eligible domains were checked
    pub work_limit_reached: bool,
    /// Limits of the structural evidence used to build the candidate domains
    pub limitations: [&'static str; 2],
}

/// One canonical-parser record span selected from a training message
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordBoundaryCue {
    /// Zero-based position in the training-message list
    pub message_index: usize,
    /// Half-open byte interval relative to that training message
    pub range: ByteRange,
}

/// Proposal and strict-parser results from one relation-preserving automatic analysis
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaAnalysisReport {
    /// Bounded field checks and the explanatory candidate projections
    pub proposal: RecordSchemaProposalReport,
    /// Strict parsing results, absent only when proposal found no candidate fields
    pub discovery: Option<RecordSchemaDiscoveryReport>,
    /// Logical work bytes charged while generating and checking this strategy, when metered
    pub work_bytes: Option<usize>,
}

/// Strategy that produced one strictly validated record schema
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordSchemaStrategy {
    /// One record occupies each caller-framed message
    FixedLayout,
    /// Repeated length fields locate record views inside caller-framed messages
    RepeatedBoundaries,
}

/// Independent fixed-layout and repeated-boundary analyses with shared search budgets
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaMultiStrategyAnalysisReport {
    /// Results from the established one-record-per-message strategy
    pub fixed_layout: RecordSchemaAnalysisReport,
    /// Limits assigned to fixed-layout search
    pub fixed_layout_limits: RecordSchemaProposalLimits,
    /// Results from length-derived boundaries and bounded record-header views
    pub repeated_boundaries: Option<RecordSchemaAnalysisReport>,
    /// Limits assigned to repeated-boundary search, absent when the input caps cannot be split
    pub repeated_boundary_limits: Option<RecordSchemaProposalLimits>,
}

pub(super) const LIMITATIONS: [&str; 2] = [
    "Field relations follow the message or repeated-boundary views named by the selected strategy; the strict parser must still validate every proposal",
    "Sequence base is zero for gap diagnostics and no terminal sequence is inferred",
];

pub(super) const LENGTH_MEANINGS: [RecordLengthMeaning; 3] = [
    RecordLengthMeaning::PayloadBytes,
    RecordLengthMeaning::WholeRecord,
    RecordLengthMeaning::BytesAfterLengthField,
];

pub(super) const INTEGER_WIDTHS: [usize; 4] = [1, 2, 4, 8];

pub(super) const fn default_sequence_base() -> u64 {
    0
}
