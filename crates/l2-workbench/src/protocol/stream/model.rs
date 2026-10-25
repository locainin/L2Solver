use super::super::{ByteRange, FramingKind, MessageContext, MessageRole, ProtocolLimits};
use super::origin_index::SourceOriginIndex;
use serde::{Deserialize, Serialize};

pub(super) const CANDIDATE_ASSUMPTION: &str = "candidate_framing";
// Version zero is the legacy checkpoint without a retained-byte version field
pub(super) const CURRENT_CHECKPOINT_VERSION: u8 = 1;

/// Source location for one part of a candidate message
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageOrigin {
    /// Original capture record number
    pub packet: u32,
    /// First byte in the original captured frame
    pub frame_offset: usize,
    /// First byte relative to the candidate message
    pub message_offset: usize,
    /// Number of bytes mapped from the captured frame
    pub length: usize,
}

/// Why an incremental parser changed the state of one framing candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransitionState {
    /// A candidate framing rule selected one complete byte range
    MessageBoundary,
    /// A sequence gap prevents further boundaries from being assigned safely
    SequenceGap,
    /// A final partial message remained without a complete boundary
    UnresolvedTail,
    /// A candidate framing rule became structurally impossible
    InvalidCandidate,
    /// A configured retention budget stopped one candidate
    ResourceOmitted,
}

/// One evidence-preserving transition for a candidate framing interpretation
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamTransition {
    /// Capture, network scope, session, and direction for the observed bytes
    pub context: MessageContext,
    /// Position of this candidate in the supplied competing-framing list
    pub framing_index: usize,
    /// Candidate framing rule retained with the transition
    pub framing: FramingKind,
    /// Whether the TCP generation was ambiguous in reconstruction
    pub generation_ambiguous: bool,
    /// Whether sequence interpretation was ambiguous in reconstruction
    pub sequence_ambiguous: bool,
    /// State change derived from exact observed bytes
    pub state: StreamTransitionState,
    /// Half-open byte interval in the reconstructed directional stream
    pub stream_range: ByteRange,
    /// Hash of the exact mapped bytes when this transition has byte evidence
    pub evidence_sha256: Option<String>,
    /// Original packet and frame ranges that supplied the transition bytes
    pub origins: Vec<MessageOrigin>,
    /// Application role remains unknown unless external evidence supplies one
    pub role: Option<MessageRole>,
    /// Assumption required to interpret this state transition
    pub assumption: String,
}

/// One tentative message selected by one framing candidate
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageRecord {
    /// Stable capture, scope, session, and direction context
    pub context: MessageContext,
    /// Position of this candidate in the supplied competing-framing list
    pub framing_index: usize,
    /// Candidate framing rule that selected the range
    pub framing: FramingKind,
    /// Whether the TCP generation was ambiguous in reconstruction
    pub generation_ambiguous: bool,
    /// Whether sequence interpretation was ambiguous in reconstruction
    pub sequence_ambiguous: bool,
    /// Half-open byte interval in the reconstructed directional stream
    pub stream_range: ByteRange,
    /// Exact candidate bytes; no bytes are inferred or padded
    pub bytes: Vec<u8>,
    /// Hash of the exact candidate bytes
    pub sha256: String,
    /// Original packet and frame ranges that supplied every candidate byte
    pub origins: Vec<MessageOrigin>,
    /// Application role remains unknown unless external evidence supplies one
    pub role: Option<MessageRole>,
    /// Assumption required to interpret this candidate as a message
    pub assumption: String,
}

/// Incremental source-mapped candidate message extraction from one TCP direction
///
/// State is serializable so a reader can pause at a file or page boundary and
/// resume with the next contiguous reconstructed chunk
/// Resumed state checks internal consistency but does not authenticate its stored source bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMessageParser {
    pub(super) context: MessageContext,
    pub(super) ambiguity: StreamAmbiguity,
    pub(super) limits: ProtocolLimits,
    pub(super) candidates: Vec<CandidateState>,
    pub(super) source_origins: SourceOriginIndex,
    pub(super) messages: Vec<MessageRecord>,
    pub(super) transitions: Vec<StreamTransition>,
    pub(super) next_offset: usize,
    pub(super) total_input_bytes: usize,
    pub(super) retained_bytes: usize,
    /// Version of the parser checkpoint invariants and retained-storage estimate
    #[serde(default)]
    pub(super) checkpoint_version: u8,
    /// Observed bytes kept after framing stopped at a sequence gap
    #[serde(default)]
    pub(super) pending_unparsed: Option<PendingUnparsedTail>,
    pub(super) omitted_candidates: usize,
    pub(super) finalized: bool,
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "needs_checkpoint_validation"
    )]
    pub(super) needs_validation: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StreamAmbiguity {
    pub(super) generation: bool,
    pub(super) sequence: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CandidateState {
    pub(super) framing: FramingKind,
    pub(super) active: bool,
    pub(super) buffer_start: usize,
    pub(super) buffer: Vec<u8>,
    /// First buffered byte not scanned for a delimiter
    #[serde(default)]
    pub(super) delimiter_scanned_to: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingUnparsedTail {
    pub(super) start: usize,
    pub(super) bytes: Vec<u8>,
}

/// Source-mapped messages and transitions from one directional stream
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamExtractionReport {
    /// Stable capture, scope, session, and direction context
    pub context: MessageContext,
    /// Whether TCP session generation assignment was ambiguous
    pub generation_ambiguous: bool,
    /// Whether sequence interpretation was ambiguous in reconstruction
    pub sequence_ambiguous: bool,
    /// Every candidate-framed message retained, including aliases
    pub messages: Vec<MessageRecord>,
    /// Complete, incomplete, and discontinuity transitions for each candidate
    pub transitions: Vec<StreamTransition>,
    /// Observed directional bytes supplied to this parser
    pub input_bytes: usize,
    /// Number of observed source ranges that were not retained after a budget stop
    pub omitted_candidates: usize,
    /// Whether any candidate or message evidence was omitted
    pub partial: bool,
}

const fn needs_checkpoint_validation() -> bool {
    true
}
