use super::super::{ByteField, IntegerField, RecordCount};
use super::super::{RecordLengthMeaning, RecordLimits, RecordSchema};
use super::error::RecordDiscoveryError;
use std::collections::HashSet;

/// Hashable schema fields used to collapse repeated caller-domain entries
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct CandidateKey {
    records_offset: usize,
    count: CandidateCountKey,
    identifier_offset: usize,
    identifier_width: usize,
    sequence_offset: usize,
    sequence_width: usize,
    sequence_byte_order: CandidateByteOrder,
    length_offset: usize,
    length_width: usize,
    length_byte_order: CandidateByteOrder,
    data_offset: usize,
    length_meaning: CandidateLengthMeaning,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CandidateCountKey {
    UntilEnd,
    Exact(u64),
    Field {
        offset: usize,
        width: usize,
        byte_order: CandidateByteOrder,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CandidateByteOrder {
    BigEndian,
    LittleEndian,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CandidateLengthMeaning {
    PayloadBytes,
    WholeRecord,
    BytesAfterLengthField,
}

/// Caller-selected finite domains for repeated framed records
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaDiscoverySpace {
    /// Candidate offsets of the first record in each message
    pub records_offsets: Vec<usize>,
    /// Candidate sources for the number of records in each message
    pub counts: Vec<RecordCount>,
    /// Candidate opaque identifier offsets and widths
    pub identifier_fields: Vec<ByteField>,
    /// Candidate sequence offsets, widths, and byte orders
    pub sequence_fields: Vec<IntegerField>,
    /// Candidate length offsets, widths, and byte orders
    pub length_fields: Vec<IntegerField>,
    /// Candidate first payload offsets
    pub data_offsets: Vec<usize>,
    /// Candidate interpretation of the decoded record length
    pub length_meanings: Vec<RecordLengthMeaning>,
    /// Explicit base used only to report observed sequence gaps
    pub sequence_base: u64,
}

impl RecordSchemaDiscoverySpace {
    pub(super) const fn validate(&self) -> Result<(), RecordDiscoveryError> {
        if self.records_offsets.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "records_offsets",
            });
        }
        if self.counts.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain { field: "counts" });
        }
        // Each dimension must contribute at least one explicit candidate
        if self.identifier_fields.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "identifier_fields",
            });
        }
        if self.sequence_fields.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "sequence_fields",
            });
        }
        if self.length_fields.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "length_fields",
            });
        }
        if self.data_offsets.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "data_offsets",
            });
        }
        if self.length_meanings.is_empty() {
            return Err(RecordDiscoveryError::EmptyDomain {
                field: "length_meanings",
            });
        }
        Ok(())
    }

    pub(crate) fn candidate_count(&self) -> Option<usize> {
        // Cardinality overflow stays unknown rather than wrapping a search budget
        [
            self.records_offsets.len(),
            self.counts.len(),
            self.identifier_fields.len(),
            self.sequence_fields.len(),
            self.length_fields.len(),
            self.data_offsets.len(),
            self.length_meanings.len(),
        ]
        .into_iter()
        .try_fold(1_usize, usize::checked_mul)
    }

    pub(super) fn candidate_at(&self, mut ordinal: usize) -> Option<RecordSchema> {
        // Decode the tuple index in reverse field order for stable domain traversal
        let meaning_index = ordinal % self.length_meanings.len();
        ordinal /= self.length_meanings.len();
        let data_index = ordinal % self.data_offsets.len();
        ordinal /= self.data_offsets.len();
        let length_index = ordinal % self.length_fields.len();
        ordinal /= self.length_fields.len();
        let sequence_index = ordinal % self.sequence_fields.len();
        ordinal /= self.sequence_fields.len();
        let identifier_index = ordinal % self.identifier_fields.len();
        ordinal /= self.identifier_fields.len();
        let count_index = ordinal % self.counts.len();
        ordinal /= self.counts.len();
        let records_offset_index = ordinal % self.records_offsets.len();

        Some(RecordSchema {
            records_offset: *self.records_offsets.get(records_offset_index)?,
            count: *self.counts.get(count_index)?,
            identifier: *self.identifier_fields.get(identifier_index)?,
            sequence: *self.sequence_fields.get(sequence_index)?,
            length: *self.length_fields.get(length_index)?,
            data_offset: *self.data_offsets.get(data_index)?,
            length_meaning: *self.length_meanings.get(meaning_index)?,
            sequence_base: self.sequence_base,
            terminal_sequence: None,
        })
    }
}

/// Explicit resource bounds for one schema discovery run
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecordDiscoveryLimits {
    /// Maximum schema candidates evaluated within the supplied finite search plan
    pub max_candidates: usize,
    /// Maximum number of training and held-out messages
    pub max_messages: usize,
    /// Maximum surviving schemas retained in the discovery report
    pub max_survivors: usize,
    /// Maximum rejected candidates retained with their first failure
    pub max_falsifications: usize,
    /// Existing parser and assembly safety limits
    pub record_limits: RecordLimits,
}

impl RecordDiscoveryLimits {
    pub(super) fn validate(self) -> Result<(), RecordDiscoveryError> {
        if self.max_candidates == 0
            || self.max_messages == 0
            || self.max_survivors == 0
            || self.max_falsifications == 0
        {
            return Err(RecordDiscoveryError::InvalidLimits);
        }
        super::super::parse::validate_assembly_limits(self.record_limits)
            .map_err(RecordDiscoveryError::RecordOperation)
    }
}

/// Dataset partition in which a candidate first failed parsing
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDiscoveryPartition {
    /// Message belonged to the schema discovery inputs
    Training,
    /// Message was held out from candidate discovery
    HeldOut,
}

impl RecordDiscoveryPartition {
    /// Stable machine-readable partition label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Training => "training",
            Self::HeldOut => "held_out",
        }
    }
}

/// Validation inputs available to the schema search
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDiscoveryValidationBasis {
    /// Caller-separated held-out messages were checked; this does not establish independence
    HeldOutMessages,
    /// Only discovery messages were checked because no held-out messages were supplied
    TrainingOnly,
}

impl RecordDiscoveryValidationBasis {
    /// Stable machine-readable validation label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeldOutMessages => "held_out_messages",
            Self::TrainingOnly => "training_only",
        }
    }
}

/// A schema that parsed every supplied message
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSchemaHypothesis {
    /// Exact schema retained from the finite caller-defined search space
    pub schema: RecordSchema,
    /// Number of messages parsed from the training partition
    pub training_message_count: usize,
    /// Number of messages parsed from the held-out partition
    pub held_out_message_count: usize,
    /// Number of individual records parsed from the training partition
    pub training_record_count: usize,
    /// Number of individual records parsed from the held-out partition
    pub held_out_record_count: usize,
}

/// First parse failure that falsified one candidate schema
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaFalsification {
    /// Exact candidate schema that failed
    pub schema: RecordSchema,
    /// Partition containing the first contradictory message
    pub partition: RecordDiscoveryPartition,
    /// Zero-based message position within the failed partition
    pub message_index: usize,
    /// Existing strict parser error that rejected the message
    pub error: super::super::RecordError,
}

/// Results of bounded record schema discovery, without ranking candidates
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSchemaDiscoveryReport {
    /// Whether candidate validation included held-out messages
    pub validation_basis: RecordDiscoveryValidationBasis,
    /// Total candidate count in this search plan when representable
    pub candidate_combinations: Option<usize>,
    /// Number of candidate combinations evaluated before the candidate limit
    pub examined_combinations: usize,
    /// Number of candidate combinations that were not examined, or unknown on overflow
    pub unexamined_combinations: Option<usize>,
    /// Whether every schema combination in the finite search space was examined
    pub search_exhaustive_within_plan: bool,
    /// Whether every surviving schema and falsification example is retained
    pub report_details_complete: bool,
    /// Whether the shared logical work-byte budget stopped candidate evaluation
    pub work_limit_reached: bool,
    /// Number of candidates that could not be completed under parser resource limits
    pub resource_limited_candidates: usize,
    /// Surviving unique schemas retained within the explicit survivor limit
    pub surviving: Vec<RecordSchemaHypothesis>,
    /// Surviving schemas omitted by the explicit survivor limit
    pub omitted_survivors: usize,
    /// Bounded examples of falsified unique schemas
    pub falsifications: Vec<RecordSchemaFalsification>,
    /// Total unique schemas falsified within the examined search space
    pub falsified_count: usize,
    /// Falsification examples omitted by the explicit report limit
    pub omitted_falsification_examples: usize,
}

pub(super) const fn candidate_key(schema: &RecordSchema) -> CandidateKey {
    CandidateKey {
        records_offset: schema.records_offset,
        count: count_key(schema.count),
        identifier_offset: schema.identifier.offset,
        identifier_width: schema.identifier.width,
        sequence_offset: schema.sequence.offset,
        sequence_width: schema.sequence.width,
        sequence_byte_order: byte_order_key(schema.sequence.byte_order),
        length_offset: schema.length.offset,
        length_width: schema.length.width,
        length_byte_order: byte_order_key(schema.length.byte_order),
        data_offset: schema.data_offset,
        length_meaning: length_meaning_key(schema.length_meaning),
    }
}

pub(super) fn seen_candidate(
    seen: &mut HashSet<CandidateKey>,
    schema: &RecordSchema,
) -> Result<bool, RecordDiscoveryError> {
    let key = candidate_key(schema);
    if seen.contains(&key) {
        return Ok(false);
    }
    seen.try_reserve(1).map_err(|_| {
        RecordDiscoveryError::RecordOperation(super::super::RecordError::AllocationFailed)
    })?;
    Ok(seen.insert(key))
}

const fn count_key(value: RecordCount) -> CandidateCountKey {
    match value {
        RecordCount::UntilEnd => CandidateCountKey::UntilEnd,
        RecordCount::Exact { records } => CandidateCountKey::Exact(records),
        RecordCount::Field { field } => CandidateCountKey::Field {
            offset: field.offset,
            width: field.width,
            byte_order: byte_order_key(field.byte_order),
        },
    }
}

const fn byte_order_key(value: super::super::super::ByteOrder) -> CandidateByteOrder {
    match value {
        super::super::super::ByteOrder::BigEndian => CandidateByteOrder::BigEndian,
        super::super::super::ByteOrder::LittleEndian => CandidateByteOrder::LittleEndian,
    }
}

const fn length_meaning_key(value: RecordLengthMeaning) -> CandidateLengthMeaning {
    match value {
        RecordLengthMeaning::PayloadBytes => CandidateLengthMeaning::PayloadBytes,
        RecordLengthMeaning::WholeRecord => CandidateLengthMeaning::WholeRecord,
        RecordLengthMeaning::BytesAfterLengthField => CandidateLengthMeaning::BytesAfterLengthField,
    }
}
