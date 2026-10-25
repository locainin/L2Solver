//! Source identities and output records for static-to-runtime code links

use core::fmt;
use serde::{Deserialize, Serialize};

use crate::{
    endpoint::{TraceMatchStatus, TracePacketRange},
    evidence::SourceRange,
};

use super::super::ArtifactError;

/// Default maximum runtime address ranges retained from one mapping document
pub const MAX_RUNTIME_MODULE_MAPPINGS: usize = 65_536;
/// Default maximum stack-frame links emitted in one report
pub const MAX_CODE_LINKS: usize = 65_536;
pub(super) const LIMITATIONS: [&str; 5] = [
    "Runtime address mapping is conditional on the caller-provided mapping document and its source hash",
    "A mapping-source hash is caller-reported unless the raw mapping source is supplied for verification",
    "Static function ranges are rebound to the analyzed binary only when the binary bytes are supplied",
    "A function mapped in a syscall stack is associated with that syscall context; this does not establish that the function constructed or caused the observed bytes",
    "Packet ranges preserve the input trace correlation status and do not identify a packet constructor",
];

/// One process address range mapped to a byte offset in an analyzed module
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModuleMapping {
    /// First included process virtual address
    pub runtime_start: u64,
    /// First excluded process virtual address
    pub runtime_end: u64,
    /// Binary file offset corresponding to `runtime_start`
    pub file_offset: u64,
}

/// Explicit process-to-module mapping evidence supplied by the analyst
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeModuleMap {
    /// SHA-256 of the exact analyzed executable or shared-library bytes
    pub binary_sha256: String,
    /// SHA-256 of the raw source used to produce the runtime map
    pub mapping_source_sha256: String,
    /// Process that owned the address space, when the source identified one
    #[serde(default)]
    pub process_id: Option<u32>,
    /// Runtime ranges and corresponding file offsets
    pub mappings: Vec<RuntimeModuleMapping>,
}

/// Limits for runtime mappings and link examples
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeLinkLimits {
    /// Maximum mappings accepted from one document
    pub max_mappings: usize,
    /// Maximum trace stack frames linked in one report
    pub max_links: usize,
}

impl Default for CodeLinkLimits {
    fn default() -> Self {
        Self {
            max_mappings: MAX_RUNTIME_MODULE_MAPPINGS,
            max_links: MAX_CODE_LINKS,
        }
    }
}

/// Optional source bytes used to recheck the supplied hashes
#[derive(Clone, Copy, Debug, Default)]
pub struct CodeLinkSourceChecks<'a> {
    /// SHA-256 of the exact runtime mapping JSON bytes
    pub mapping_document_sha256: &'a str,
    /// Exact binary bytes analyzed by the static receipt
    pub binary_bytes: Option<&'a [u8]>,
    /// Exact acquisition file hashed by the runtime mapping document
    pub mapping_source_bytes: Option<&'a [u8]>,
}

/// State for one source-qualified stack frame and syscall observation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeLinkStatus {
    /// The stack-frame record did not expose a process instruction pointer
    MissingInstructionPointer,
    /// No supplied runtime range contained the instruction pointer
    UnmappedRuntimeAddress,
    /// Multiple supplied runtime ranges contained the instruction pointer
    AmbiguousRuntimeMapping,
    /// The mapped process differs from the trace process
    ProcessMismatch,
    /// Mapping and trace evidence do not identify the same process
    ProcessIdentityUnavailable,
    /// The mapped file offset was outside every retained function
    NoFunctionAtMappedOffset,
    /// Multiple retained function ranges covered the mapped file offset
    AmbiguousStaticFunction,
    /// One function matched, but no exact packet range was linked to its syscall
    FunctionMappedWithoutPacketMatch,
    /// One function matched and the syscall has packet ranges without a unique result
    FunctionMappedWithPacketCandidates,
    /// One function matched a unique syscall byte range and packet range set
    FunctionMatchedWithPacketEvidence,
}

/// One trace frame mapped through explicit runtime and static source ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodeLink {
    /// Complete trace line containing the observed syscall
    pub trace_source_range: SourceRange,
    /// Exact trace stack-frame line and source identity
    pub frame_source_range: SourceRange,
    /// Exact buffer text range, when the trace parser retained one
    pub data_source_range: Option<SourceRange>,
    /// Process identifier from the trace line
    pub process_id: Option<u32>,
    /// Syscall name printed in the trace
    pub syscall: String,
    /// Direction relative to the traced process
    pub direction: crate::endpoint::IoDirection,
    /// Module label printed by the unwinder
    pub unwinder_module: Option<String>,
    /// Symbol label printed by the unwinder
    pub unwinder_symbol: Option<String>,
    /// Process virtual address printed by the unwinder
    pub instruction_pointer: Option<u64>,
    /// Index of the explicit runtime mapping used for this link
    pub mapping_index: Option<usize>,
    /// Runtime mapping start address
    pub mapping_runtime_start: Option<u64>,
    /// Runtime mapping end address
    pub mapping_runtime_end: Option<u64>,
    /// File offset corresponding to the mapped instruction pointer
    pub mapped_file_offset: Option<u64>,
    /// Static function name retained by the analysis receipt
    pub function_name: Option<String>,
    /// Static function virtual address retained by the analysis receipt
    pub function_address: Option<u64>,
    /// Static function file offset retained by the analysis receipt
    pub function_file_offset: Option<usize>,
    /// SHA-256 of the exact retained function bytes
    pub function_code_sha256: Option<String>,
    /// SHA-256 of bytes recorded for this syscall
    pub io_bytes_sha256: String,
    /// Number of bytes recorded for this syscall
    pub io_bytes_length: usize,
    /// Existing syscall-to-capture correlation state
    pub trace_match_status: Option<TraceMatchStatus>,
    /// Number of captured byte locations considered by the existing correlation
    pub trace_candidate_count: Option<u64>,
    /// Packet ranges from the existing syscall correlation
    pub captured_ranges: Vec<TracePacketRange>,
    /// Evidence boundary for associating the frame with syscall I/O
    pub association: &'static str,
    /// Link result without a probability score
    pub status: CodeLinkStatus,
}

/// Independent hash checks against exact binary and runtime mapping source bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CodeLinkSourceVerification {
    /// Whether exact binary bytes were supplied and verified
    pub binary_source_verified: bool,
    /// Whether exact runtime mapping source bytes were supplied and verified
    pub mapping_source_verified: bool,
}

/// Runtime-to-static frame links with explicit evidence identities
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodeLinkReport {
    /// SHA-256 from the source-bound static analysis receipt
    pub analysis_source_sha256: String,
    /// Independent checks of source identities against supplied exact bytes
    #[serde(flatten)]
    pub source_verification: CodeLinkSourceVerification,
    /// SHA-256 of the exact runtime mapping JSON bytes
    pub mapping_document_sha256: String,
    /// Caller-reported SHA-256 of the acquisition source for runtime mappings
    pub mapping_source_sha256: String,
    /// Process ID recorded by the runtime mapping document
    pub mapping_process_id: Option<u32>,
    /// Source identity of the parsed strace input
    pub trace_source_sha256: String,
    /// Whether the static receipt and trace input report full coverage
    pub evidence_complete: bool,
    /// Whether examples or source coverage were incomplete
    pub partial: bool,
    /// Number of stack frames omitted after reaching the configured report limit
    pub omitted_links: usize,
    /// Source-qualified stack-frame links
    pub links: Vec<CodeLink>,
    /// Limits on interpreting a mapped stack frame as a network operation
    pub limitations: Vec<&'static str>,
}

/// Invalid hash, source mismatch, or malformed mapping and trace evidence
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodeLinkError {
    /// A required digest is not 64 hexadecimal characters
    InvalidHash { field: &'static str },
    /// Static receipt and mapping document refer to different binary bytes
    BinaryHashMismatch,
    /// Optional exact binary bytes disagree with the static receipt
    BinarySourceHashMismatch,
    /// Optional exact mapping-source bytes disagree with the mapping document
    MappingSourceHashMismatch,
    /// Runtime mapping JSON is malformed
    InvalidMappingDocument,
    /// Runtime mapping document contains no address ranges
    EmptyMappingDocument,
    /// Mapping input or frame count exceeds a configured budget
    LimitExceeded { field: &'static str, maximum: usize },
    /// Resource limits are zero or one mapping range is structurally invalid
    InvalidLimits,
    /// Runtime address or file offset range overflows or is reversed
    InvalidMapping { index: usize },
    /// Retained static function bytes or ranges disagree with their receipt
    InvalidFunction { index: usize },
    /// A source range is outside its declared input file
    InvalidTraceRange,
    /// The trace contains more than one event at the same source range
    DuplicateTraceEvent,
    /// More than one correlation result claims the same trace event
    DuplicateTraceCorrelation,
    /// A trace correlation points to no event in the supplied trace report
    CorrelationWithoutEvent,
    /// A unique trace match lacks one unique candidate or packet ranges
    InvalidTraceCorrelation,
    /// The executable header or one of its mappings could not be validated
    Artifact(ArtifactError),
}

impl fmt::Display for CodeLinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHash { field } => write!(formatter, "invalid SHA-256 in {field}"),
            Self::BinaryHashMismatch => {
                formatter.write_str("runtime mapping binary hash differs from the static receipt")
            }
            Self::BinarySourceHashMismatch => {
                formatter.write_str("supplied binary bytes differ from the static receipt source")
            }
            Self::MappingSourceHashMismatch => formatter
                .write_str("supplied runtime mapping source differs from its recorded hash"),
            Self::InvalidMappingDocument => {
                formatter.write_str("runtime mapping document is malformed")
            }
            Self::EmptyMappingDocument => {
                formatter.write_str("runtime mapping document has no address ranges")
            }
            Self::LimitExceeded { field, maximum } => {
                write!(formatter, "code-link {field} exceeds maximum {maximum}")
            }
            Self::InvalidLimits => formatter.write_str("code-link limits must be positive"),
            Self::InvalidMapping { index } => {
                write!(
                    formatter,
                    "runtime mapping {index} has an invalid address or file range"
                )
            }
            Self::InvalidFunction { index } => write!(
                formatter,
                "static function {index} has invalid bytes, hash, or source range"
            ),
            Self::InvalidTraceRange => {
                formatter.write_str("trace or packet source range is outside its declared input")
            }
            Self::DuplicateTraceEvent => {
                formatter.write_str("trace event source range is duplicated")
            }
            Self::DuplicateTraceCorrelation => {
                formatter.write_str("trace event has duplicate correlation results")
            }
            Self::CorrelationWithoutEvent => {
                formatter.write_str("trace correlation does not identify an event in the trace")
            }
            Self::InvalidTraceCorrelation => {
                formatter.write_str("unique trace correlation has incomplete packet evidence")
            }
            Self::Artifact(error) => write!(formatter, "invalid analyzed binary: {error}"),
        }
    }
}

impl std::error::Error for CodeLinkError {}
