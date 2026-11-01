pub use crate::validation::ChecksumByteOrder;
use serde::{Deserialize, Serialize};

/// Checked runtime budgets for canonical byte transformations
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationLimits {
    /// Maximum caller-supplied bytes
    pub max_input_bytes: usize,
    /// Maximum output from one transformation
    pub max_output_bytes: usize,
    /// Maximum successful intermediate output bytes in one recipe
    pub max_intermediate_bytes: usize,
    /// Maximum bytes processed and emitted across all operations in one recipe
    pub max_work_bytes: usize,
    /// Maximum configured steps in one recipe
    pub max_steps: usize,
    /// Maximum explicit checks in one recipe
    pub max_constraints: usize,
    /// Maximum bytes in variable-length recipe parameters
    pub max_recipe_parameter_bytes: usize,
}

impl Default for DerivationLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: super::MAX_INPUT_BYTES,
            max_output_bytes: super::MAX_OUTPUT_BYTES,
            max_intermediate_bytes: super::MAX_INTERMEDIATE_BYTES,
            // At most one input-sized read per default step plus every retained output
            max_work_bytes: super::DEFAULT_MAX_WORK_BYTES,
            max_steps: super::MAX_STEPS,
            max_constraints: super::MAX_CONSTRAINTS,
            max_recipe_parameter_bytes: super::MAX_RECIPE_PARAMETER_BYTES,
        }
    }
}
use std::fmt;

/// Caller-supplied bytes that stay hidden in debug output and serialized receipts
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Keep caller material for one explicit operation
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("byte_length", &self.0.len())
            .field("sha256", &crate::sha256(&self.0))
            .finish()
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        key_identity(&self.0).serialize(serializer)
    }
}

/// Literal bytes, a retained-node range, or a range relative to the selected input
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperandRef {
    Literal(SecretBytes),
    NodeRange {
        node_id: u64,
        offset: u64,
        length: u64,
    },
    /// A byte range relative to the selected input node for this execution
    SelectedInputRange {
        offset: u64,
        length: u64,
    },
}

impl OperandRef {
    /// Keep literal operand bytes hidden in debug output and serialized receipts
    #[must_use]
    pub const fn literal(bytes: SecretBytes) -> Self {
        Self::Literal(bytes)
    }

    pub(crate) fn as_literal_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Literal(bytes) => Some(bytes.as_bytes()),
            Self::NodeRange { .. } | Self::SelectedInputRange { .. } => None,
        }
    }
}

impl From<SecretBytes> for OperandRef {
    fn from(bytes: SecretBytes) -> Self {
        Self::Literal(bytes)
    }
}

impl From<Vec<u8>> for OperandRef {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Literal(SecretBytes::new(bytes))
    }
}

impl Serialize for OperandRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Literal(bytes) => bytes.serialize(serializer),
            Self::NodeRange {
                node_id,
                offset,
                length,
            } => NodeRangeRef {
                source: "node_range",
                node_id: *node_id,
                offset: *offset,
                length: *length,
            }
            .serialize(serializer),
            Self::SelectedInputRange { offset, length } => SelectedInputRangeRef {
                source: "selected_input_range",
                offset: *offset,
                length: *length,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for OperandRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            // Existing recipes use byte arrays for every literal operand
            Literal(Vec<u8>),
            Reference(TaggedReference),
        }

        #[derive(Deserialize)]
        #[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
        enum TaggedReference {
            NodeRange {
                node_id: u64,
                offset: u64,
                length: u64,
            },
            SelectedInputRange {
                offset: u64,
                length: u64,
            },
        }

        match Wire::deserialize(deserializer)? {
            Wire::Literal(bytes) => Ok(Self::from(bytes)),
            Wire::Reference(TaggedReference::NodeRange {
                node_id,
                offset,
                length,
            }) => Ok(Self::NodeRange {
                node_id,
                offset,
                length,
            }),
            Wire::Reference(TaggedReference::SelectedInputRange { offset, length }) => {
                Ok(Self::SelectedInputRange { offset, length })
            }
        }
    }
}

#[derive(Serialize)]
struct NodeRangeRef {
    source: &'static str,
    node_id: u64,
    offset: u64,
    length: u64,
}

#[derive(Serialize)]
struct SelectedInputRangeRef {
    source: &'static str,
    offset: u64,
    length: u64,
}

/// Ordered byte operations and explicit checks for one candidate derivation
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub steps: Vec<Operation>,
    pub constraints: Vec<Constraint>,
}

/// One fully parameterized transformation; no key or format is inferred
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    HexDecode {},
    HexEncode {
        case: HexCase,
    },
    Base64Decode {
        alphabet: Base64Alphabet,
        padding: Base64Padding,
    },
    Base64Encode {
        alphabet: Base64Alphabet,
        padding: Base64Padding,
    },
    XorRepeat {
        key: Vec<u8>,
        offset: usize,
    },
    /// XOR each byte with SHA-256(seed and counter) blocks in the supplied order
    Sha256CounterXor {
        seed: OperandRef,
        initial_counter: u64,
        counter_width: CounterWidth,
        counter_byte_order: CounterByteOrder,
        seed_order: SeedCounterOrder,
    },
    /// Release plaintext only after the supplied AES-GCM tag authenticates
    AesGcmDecrypt {
        key: OperandRef,
        nonce: OperandRef,
        associated_data: OperandRef,
        tag_layout: AesGcmTagLayout,
    },
    /// Derive bytes from the current input password and an explicit salt kept hidden in receipts
    /// Reports retain the password's SHA-256 fingerprint and the derived output
    ScryptDerive {
        salt: OperandRef,
        log_n: u8,
        r: u32,
        p: u32,
        output_length: usize,
    },
    /// Add one value to each byte with wrapping modulo 256
    ByteAdd {
        value: u8,
    },
    /// Rotate each byte left by the supplied count modulo 8
    RotateBits {
        count: u8,
    },
    Slice {
        start: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
    },
    /// Gather positions in the supplied order, allowing deliberate repetition
    Select {
        indices: Vec<usize>,
    },
    /// Index 0 is byte 0's MSB; listed positions (including repeats) are read in order
    /// Each full group packs into the low bits of a byte, with the first bit as its MSB
    SelectBits {
        indices: Vec<usize>,
        bits_per_byte: u8,
    },
    /// Select a compact phase from an exact bit window, then pack selected bits into low output bits
    SelectBitRange {
        start_bit: usize,
        bit_count: usize,
        stride_bits: usize,
        phase: usize,
        bits_per_byte: u8,
        remainder: BitRemainder,
    },
    Reverse {},
    /// Map each output position to one unique input position
    Permute {
        indices: Vec<usize>,
    },
    GzipDecompress {},
    ZlibDecompress {},
}

/// Number of bytes used to encode the SHA-256 counter
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterWidth {
    OneByte,
    TwoBytes,
    FourBytes,
    EightBytes,
}

impl CounterWidth {
    /// Number of serialized bytes in the counter
    #[must_use]
    pub const fn byte_length(self) -> usize {
        match self {
            Self::OneByte => 1,
            Self::TwoBytes => 2,
            Self::FourBytes => 4,
            Self::EightBytes => 8,
        }
    }

    /// Largest counter that fits the selected width
    #[must_use]
    pub const fn maximum_counter(self) -> u64 {
        match self {
            Self::OneByte => 0xff,
            Self::TwoBytes => 0xffff,
            Self::FourBytes => 0xffff_ffff,
            Self::EightBytes => u64::MAX,
        }
    }
}

/// Byte order used to encode the SHA-256 counter
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterByteOrder {
    BigEndian,
    LittleEndian,
}

/// Position of the caller-supplied seed relative to each encoded counter
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedCounterOrder {
    SeedThenCounter,
    CounterThenSeed,
}

/// Explicit location of the fixed 16-byte AES-GCM tag in the input
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "layout", rename_all = "snake_case", deny_unknown_fields)]
pub enum AesGcmTagLayout {
    Appended,
    /// The tag occupies this byte range and is removed before decryption
    Detached {
        tag_offset: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HexCase {
    Lower,
    Upper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Base64Alphabet {
    Standard,
    UrlSafe,
}

/// Required emits canonical padding; forbidden emits no padding
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Base64Padding {
    Required,
    Forbidden,
}

/// Explicit handling for selected bits that do not fill the final output group
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitRemainder {
    /// Fail when selected bit count does not fill every output group
    Reject,
    /// Keep full groups and discard trailing selected bits
    Drop,
    /// Fill the final group with zero bits
    ZeroFill,
    /// Fill the final group with one bits
    OneFill,
}

/// A user-specified condition on the final byte string
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Constraint {
    Length {
        bytes: usize,
    },
    Prefix {
        bytes: Vec<u8>,
    },
    Sha256 {
        expected_hex: String,
    },
    Utf8 {},
    /// Checks JSON syntax and structure without retaining a parsed value
    Json {},
    /// Checks CRC-32 over one explicit data range against a separate four-byte field
    Crc32 {
        data_offset: usize,
        data_length: usize,
        checksum_offset: usize,
        byte_order: ChecksumByteOrder,
    },
    /// Checks authenticated AES-GCM decryption of the complete selected byte string
    AesGcm {
        key: OperandRef,
        nonce: OperandRef,
        associated_data: OperandRef,
    },
}

impl fmt::Debug for Constraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { bytes } => formatter
                .debug_struct("Length")
                .field("bytes", bytes)
                .finish(),
            Self::Prefix { bytes } => formatter
                .debug_struct("Prefix")
                .field("bytes", bytes)
                .finish(),
            Self::Sha256 { expected_hex } => formatter
                .debug_struct("Sha256")
                .field("expected_hex", expected_hex)
                .finish(),
            Self::Utf8 {} => formatter.write_str("Utf8"),
            Self::Json {} => formatter.write_str("Json"),
            Self::Crc32 {
                data_offset,
                data_length,
                checksum_offset,
                byte_order,
            } => formatter
                .debug_struct("Crc32")
                .field("data_offset", data_offset)
                .field("data_length", data_length)
                .field("checksum_offset", checksum_offset)
                .field("byte_order", byte_order)
                .finish(),
            Self::AesGcm {
                key,
                nonce,
                associated_data,
            } => formatter
                .debug_struct("AesGcm")
                .field("key", key)
                .field("nonce", nonce)
                .field("associated_data", associated_data)
                .finish(),
        }
    }
}

#[derive(Debug, Serialize)]
struct KeyIdentity {
    byte_length: usize,
    sha256: String,
}

fn key_identity(key: &[u8]) -> KeyIdentity {
    KeyIdentity {
        byte_length: key.len(),
        sha256: crate::sha256(key),
    }
}

/// Completion describes the recipe run, not whether any external system accepts the bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DerivationStatus {
    Completed,
    Failed { step_index: usize },
}

/// The recorded outcome of one recipe step
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepStatus {
    Applied,
    Failed { error: StepFailure },
    Skipped { after_step: usize },
}

/// A bounded, machine-readable reason an operation could not be applied
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepFailure {
    OperandRequiresCase,
    InvalidHexLength {
        length: usize,
    },
    InvalidHexDigit {
        offset: usize,
    },
    InvalidBase64,
    EmptyXorKey,
    CounterValueOutOfRange {
        initial_counter: u64,
        maximum: u64,
    },
    CounterExhausted,
    InvalidAesGcmParameters,
    InvalidAesGcmLayout,
    AuthenticatedDecryptionFailed,
    InvalidScryptParameters,
    XorKeyTooLong {
        length: usize,
        limit: usize,
    },
    SliceOutOfBounds {
        start: usize,
        length: usize,
        input_length: usize,
    },
    SelectionOutOfBounds {
        index: usize,
        input_length: usize,
    },
    InvalidBitsPerByte {
        bits_per_byte: u8,
    },
    IncompleteBitGroup {
        selected_bits: usize,
        bits_per_byte: u8,
    },
    InvalidBitStride {
        stride_bits: usize,
    },
    InvalidBitPhase {
        phase: usize,
        stride_bits: usize,
    },
    BitRangeOverflow,
    BitRangeOutOfBounds {
        start_bit: usize,
        bit_count: usize,
        input_bits: usize,
    },
    BitSelectionOutOfBounds {
        index: usize,
        input_bits: usize,
    },
    PermutationLengthMismatch {
        length: usize,
        input_length: usize,
    },
    PermutationIndexOutOfBounds {
        index: usize,
        input_length: usize,
    },
    DuplicatePermutationIndex {
        index: usize,
    },
    OutputLimitExceeded {
        limit: usize,
    },
    IntermediateBudgetExceeded {
        limit: usize,
    },
    WorkBudgetExceeded {
        limit: usize,
    },
    AllocationFailed,
    InvalidCompressedStream,
    TrailingCompressedData,
}

/// A bounded explanation for an explicit constraint result
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstraintFailure {
    LengthMismatch { expected: usize, actual: usize },
    PrefixMismatch,
    Sha256Mismatch { actual_hex: String },
    InvalidSha256Expectation,
    PrefixTooLong { length: usize, limit: usize },
    InvalidUtf8,
    InvalidJson,
    InvalidChecksumParameters,
    ChecksumMismatch { expected: u32, actual: u32 },
    InvalidAesGcmParameters,
    AuthenticatedDecryptionFailed,
    OperandRequiresCase,
}

/// Constraints are syntactic or structural checks, never independent credential validation
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConstraintStatus {
    Satisfied,
    Violated { reason: ConstraintFailure },
    Invalid { reason: ConstraintFailure },
    NotEvaluated { after_step: usize },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepReport {
    pub operation: Operation,
    #[serde(default)]
    pub operand_provenance: Vec<OperandProvenance>,
    pub input_length: Option<usize>,
    pub input_sha256: Option<String>,
    pub output_length: Option<usize>,
    pub output_sha256: Option<String>,
    pub status: StepStatus,
}

/// Exact retained bytes used to resolve one operation parameter
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperandProvenance {
    pub slot: OperandSlot,
    pub provider_node: u64,
    pub provider_blob: String,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

/// Name of the operation parameter supplied by a retained byte range
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperandSlot {
    Seed,
    Key,
    Nonce,
    AssociatedData,
    Salt,
}

/// Recipe location that owns one external operand reference
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperandLocation {
    Step { step_index: usize },
    Constraint { constraint_index: usize },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintReport {
    pub constraint: Constraint,
    #[serde(default)]
    pub operand_provenance: Vec<OperandProvenance>,
    pub status: ConstraintStatus,
}

/// Auditable result with the last successful bytes retained when a step fails
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationReport {
    pub status: DerivationStatus,
    pub input_length: usize,
    pub input_sha256: String,
    pub output: Vec<u8>,
    pub output_sha256: String,
    pub steps: Vec<StepReport>,
    pub constraints: Vec<ConstraintReport>,
    pub intermediate_bytes: usize,
    pub work_bytes: usize,
}
