use crate::protocol::{ByteOrder, ByteRange};
use serde::{Deserialize, Serialize, ser::SerializeStruct};

/// Default selected input ceiling for one explicit record parse
pub const DEFAULT_MAX_RECORD_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Default record ceiling used to bound report growth
pub const DEFAULT_MAX_RECORDS: usize = 1_000_000;
/// Default identifier width ceiling for one record
pub const DEFAULT_MAX_IDENTIFIER_BYTES: usize = 4 * 1024;
/// Default logical storage ceiling for parsed record metadata
pub const DEFAULT_MAX_RECORD_REPORT_BYTES: usize = 128 * 1024 * 1024;
/// Default number of independent object identifiers accepted in one assembly
pub const DEFAULT_MAX_RECORD_GROUPS: usize = 100_000;
/// Default aggregate ceiling for materialized record candidates
pub const DEFAULT_MAX_RECORD_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
/// Default number of sequence issue examples retained per group
pub const DEFAULT_MAX_RECORD_ISSUE_EXAMPLES: usize = 64;

/// A byte field relative to the beginning of one record
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteField {
    /// Zero-based field offset
    pub offset: usize,
    /// Exact field width
    pub width: usize,
}

/// An unsigned integer field relative to its enclosing byte region
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegerField {
    /// Zero-based field offset
    pub offset: usize,
    /// Integer width of one, two, four, or eight bytes
    pub width: usize,
    /// Explicit byte order
    pub byte_order: ByteOrder,
}

/// How the parser determines the number of repeated records
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordCount {
    /// Parse records until every selected input byte is consumed
    UntilEnd,
    /// Parse exactly the caller-supplied number of records
    Exact {
        /// Exact expected record count
        records: u64,
    },
    /// Decode the count from a field before `records_offset`
    Field {
        /// Count field relative to the beginning of the selected input
        field: IntegerField,
    },
}

/// Relationship between a decoded length and one complete record
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordLengthMeaning {
    /// The value is the payload length beginning at `data_offset`
    PayloadBytes,
    /// The value is the entire record length
    WholeRecord,
    /// The value is the bytes after the end of the length field
    BytesAfterLengthField,
}

/// Complete caller-selected layout for a repeated binary record stream
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSchema {
    /// First record offset after any stream preamble
    pub records_offset: usize,
    /// Explicit record count source
    pub count: RecordCount,
    /// Opaque object identifier bytes relative to each record
    pub identifier: ByteField,
    /// Unsigned sequence field relative to each record
    pub sequence: IntegerField,
    /// Unsigned length field relative to each record
    pub length: IntegerField,
    /// First payload byte relative to each record
    pub data_offset: usize,
    /// Meaning assigned to the decoded length
    pub length_meaning: RecordLengthMeaning,
    /// First sequence value expected for a complete object
    pub sequence_base: u64,
    /// Inclusive final sequence required for a complete object
    ///
    /// When absent, parsing and candidate assembly remain available without a completeness claim
    #[serde(default)]
    pub terminal_sequence: Option<u64>,
}

/// Configurable resource limits for parsing and assembling records
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordLimits {
    /// Maximum selected input size
    pub max_input_bytes: usize,
    /// Maximum parsed records
    pub max_records: usize,
    /// Maximum opaque identifier width
    pub max_identifier_bytes: usize,
    /// Maximum logical storage used by parsed metadata
    pub max_report_bytes: usize,
    /// Maximum distinct identifiers assembled in one call
    pub max_groups: usize,
    /// Maximum aggregate bytes materialized across record groups
    pub max_output_bytes: usize,
    /// Maximum examples retained for each sequence issue class
    pub max_issue_examples: usize,
}

impl Default for RecordLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_RECORD_INPUT_BYTES,
            max_records: DEFAULT_MAX_RECORDS,
            max_identifier_bytes: DEFAULT_MAX_IDENTIFIER_BYTES,
            max_report_bytes: DEFAULT_MAX_RECORD_REPORT_BYTES,
            max_groups: DEFAULT_MAX_RECORD_GROUPS,
            max_output_bytes: DEFAULT_MAX_RECORD_OUTPUT_BYTES,
            max_issue_examples: DEFAULT_MAX_RECORD_ISSUE_EXAMPLES,
        }
    }
}

/// One record with exact ranges into the caller-owned input
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedRecord {
    /// Zero-based record position in parse order
    pub index: usize,
    /// Complete record range
    pub record: ByteRange,
    /// Exact opaque identifier bytes
    pub identifier: Vec<u8>,
    /// Decoded unsigned sequence value
    pub sequence: u64,
    /// Payload range within the selected input
    pub payload: ByteRange,
}

/// Strict parse result bound to one schema and complete input length
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordParseReport {
    /// Exact schema applied to the input
    pub(super) schema: RecordSchema,
    /// Complete selected input length
    pub(super) input_length: usize,
    /// SHA-256 of the complete selected input
    pub(super) input_sha256: String,
    /// Declared count when supplied directly or decoded from a field
    pub(super) declared_count: Option<u64>,
    /// Parsed records in observed order
    pub(super) records: Vec<ParsedRecord>,
}

/// One source and its validated parse report for global record assembly
#[derive(Clone, Copy, Debug)]
pub struct RecordAssemblyInput<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) report: &'a RecordParseReport,
    pub(super) input_sha256: Option<&'a str>,
}

impl<'a> RecordAssemblyInput<'a> {
    /// Bind a parse report to the exact source bytes used to create it
    #[must_use]
    pub const fn new(bytes: &'a [u8], report: &'a RecordParseReport) -> Self {
        Self {
            bytes,
            report,
            input_sha256: None,
        }
    }
}

impl RecordParseReport {
    /// Return the exact schema used for this report
    #[must_use]
    pub const fn schema(&self) -> &RecordSchema {
        &self.schema
    }

    /// Return the complete selected input length
    #[must_use]
    pub const fn input_length(&self) -> usize {
        self.input_length
    }

    /// Return the digest binding this report to its selected input
    #[must_use]
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Return the supplied or decoded record count
    #[must_use]
    pub const fn declared_count(&self) -> Option<u64> {
        self.declared_count
    }

    /// Return parsed records in observed order
    #[must_use]
    pub fn records(&self) -> &[ParsedRecord] {
        &self.records
    }

    /// Return the logical allocation charged to parsed record metadata
    #[must_use]
    pub fn metadata_bytes(&self) -> usize {
        parsed_record_metadata_bytes(&self.records)
    }
}

pub(super) fn parsed_record_metadata_bytes(records: &[ParsedRecord]) -> usize {
    records.iter().fold(0_usize, |total, record| {
        total.saturating_add(
            std::mem::size_of::<ParsedRecord>().saturating_add(record.identifier.len()),
        )
    })
}

/// Exact payload mapping into one materialized group candidate
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordAssemblyPart {
    /// Zero-based source position in the caller-supplied input order
    pub input_index: usize,
    /// Zero-based record position in observed parse order
    pub record_index: usize,
    /// Decoded sequence value
    pub sequence: u64,
    /// Exact payload range in the selected input
    pub input: ByteRange,
    /// Exact payload range in the assembled output
    pub output: ByteRange,
}

/// Evidence receipt for one identifier group
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordGroupReceipt {
    /// Exact opaque identifier bytes
    pub identifier: Vec<u8>,
    /// Number of observed records in this group
    pub record_count: usize,
    /// Required first sequence value
    pub sequence_base: u64,
    /// Lowest observed sequence value
    pub minimum_sequence: u64,
    /// Highest observed sequence value
    pub maximum_sequence: u64,
    /// True only when the operator terminal and exact contiguous sequence are both satisfied
    pub complete: bool,
    /// Missing sequence values from the base through the observed or operator terminal
    pub missing_sequence_count: u128,
    /// Bounded missing sequence examples
    pub missing_sequences: Vec<u64>,
    /// Missing sequence values omitted from the bounded examples
    pub omitted_missing_sequences: u128,
    /// Bounded sequence values observed more than once
    pub duplicate_sequences: Vec<u64>,
    /// Duplicate sequence values omitted from the bounded examples
    pub omitted_duplicate_sequences: usize,
    /// Bounded sequence values below the configured base
    pub sequences_before_base: Vec<u64>,
    /// Values below the base omitted from the bounded examples
    pub omitted_sequences_before_base: usize,
    /// Materialized payload length for the observed group candidate
    pub output_length: Option<usize>,
    /// SHA-256 of the observed group candidate payload bytes
    pub output_sha256: Option<String>,
    /// Input-to-candidate output mappings in sequence and source order
    pub parts: Vec<RecordAssemblyPart>,
    /// Distinct observed sequences beyond the configured terminal sequence
    pub sequences_after_terminal: Vec<u64>,
    /// Distinct sequences beyond the terminal omitted from bounded examples
    pub omitted_sequences_after_terminal: usize,
}

/// One group receipt and the payload bytes observed for that identifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordGroupOutcome {
    pub(super) receipt: RecordGroupReceipt,
    pub(super) candidate_bytes: Vec<u8>,
}

impl RecordGroupOutcome {
    /// Return the immutable evidence receipt
    #[must_use]
    pub const fn receipt(&self) -> &RecordGroupReceipt {
        &self.receipt
    }

    /// Return bytes as a complete object only when the explicit sequence contract is satisfied
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        self.receipt
            .complete
            .then_some(self.candidate_bytes.as_slice())
    }

    /// Return observed payload bytes in deterministic sequence and source order
    #[must_use]
    pub fn candidate_bytes(&self) -> &[u8] {
        &self.candidate_bytes
    }
}

/// Borrowed serializable summary of a multi-identifier assembly
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordAssemblyReport<'a> {
    /// Number of independently parsed sources assembled globally
    pub input_count: usize,
    /// Selected source byte length
    pub input_length: usize,
    /// Aggregate bytes materialized across observed group candidates
    pub output_bytes: usize,
    /// Inclusive final sequence supplied as the operator's completion basis, if any
    pub terminal_sequence: Option<u64>,
    /// Per-identifier outcomes in bytewise identifier order
    pub groups: &'a [RecordGroupOutcome],
}

impl Serialize for RecordAssemblyReport<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut report = serializer.serialize_struct("RecordAssemblyReport", 5)?;
        report.serialize_field("input_count", &self.input_count)?;
        report.serialize_field("input_length", &self.input_length)?;
        report.serialize_field("output_bytes", &self.output_bytes)?;
        report.serialize_field("terminal_sequence", &self.terminal_sequence)?;
        report.serialize_field("groups", &GroupReceiptView(self.groups))?;
        report.end()
    }
}

struct GroupReceiptView<'a>(&'a [RecordGroupOutcome]);

impl Serialize for GroupReceiptView<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut groups = serializer.serialize_seq(Some(self.0.len()))?;
        for group in self.0 {
            groups.serialize_element(&group.receipt)?;
        }
        groups.end()
    }
}

/// Candidate bytes and receipts for a multi-identifier assembly
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordAssemblyOutcome {
    pub(super) input_count: usize,
    pub(super) input_length: usize,
    pub(super) output_bytes: usize,
    pub(super) terminal_sequence: Option<u64>,
    pub(super) report_bytes: usize,
    pub(super) groups: Vec<RecordGroupOutcome>,
}

impl RecordAssemblyOutcome {
    /// Return the serializable assembly report
    #[must_use]
    pub fn report(&self) -> RecordAssemblyReport<'_> {
        RecordAssemblyReport {
            input_count: self.input_count,
            input_length: self.input_length,
            output_bytes: self.output_bytes,
            terminal_sequence: self.terminal_sequence,
            groups: &self.groups,
        }
    }

    /// Return logical bytes charged for parse metadata and retained assembly receipts
    #[must_use]
    pub const fn report_bytes(&self) -> usize {
        self.report_bytes
    }

    /// Return all group outcomes in bytewise identifier order
    #[must_use]
    pub fn groups(&self) -> &[RecordGroupOutcome] {
        &self.groups
    }

    /// Find one group by its exact opaque identifier
    #[must_use]
    pub fn group(&self, identifier: &[u8]) -> Option<&RecordGroupOutcome> {
        self.groups
            .iter()
            .find(|group| group.receipt.identifier == identifier)
    }
}

/// Record schema, input, resource, or source-consistency failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// A configured limit is zero or internally inconsistent
    InvalidLimits,
    /// One named schema field is invalid
    InvalidSchema { field: &'static str },
    /// Selected input exceeds the configured ceiling
    InputTooLarge { length: usize, maximum: usize },
    /// Identifier width exceeds the configured ceiling
    IdentifierTooLarge { width: usize, maximum: usize },
    /// Declared or observed record count exceeds the configured ceiling
    TooManyRecords { count: u64, maximum: usize },
    /// Parsed metadata exceeds the configured logical storage ceiling
    ReportTooLarge { bytes: usize, maximum: usize },
    /// Input ends before the configured first record
    TruncatedPreamble { needed: usize, available: usize },
    /// Input ends before a complete declared or observed record
    TruncatedRecord {
        record: usize,
        offset: usize,
        needed: usize,
        available: usize,
    },
    /// A length cannot describe a positive record containing the configured payload offset
    InvalidRecordLength { record: usize, encoded: u64 },
    /// A decoded offset or length cannot fit the platform address space
    LengthOverflow { record: usize },
    /// Exact parsing left bytes after the declared records
    TrailingBytes { offset: usize, remaining: usize },
    /// A caller-supplied parse report does not match its selected source bytes
    InvalidReport,
    /// Minimum distinct identifier count observed when the configured ceiling is crossed
    TooManyGroups { count: usize, maximum: usize },
    /// Materialized group candidate bytes exceed the aggregate output ceiling
    OutputTooLarge { length: usize, maximum: usize },
    /// A bounded allocation failed
    AllocationFailed,
}
