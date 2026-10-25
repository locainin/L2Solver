use core::fmt;

/// A bounded evidence case, source, reference, or encoding failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    /// The case does not use the current evidence schema
    UnsupportedSchema { found: u32, expected: u32 },
    /// A serialized case exceeded its input or output limit
    CaseTooLarge { length: usize, maximum: usize },
    /// Case JSON could not be decoded or encoded
    InvalidJson,
    /// A validated case could not be written to the supplied output
    WriteFailed,
    /// A digest is not a canonical lowercase SHA-256 value
    InvalidDigest,
    /// Retained bytes do not match their declared SHA-256 value
    HashMismatch,
    /// Two different byte strings produced the same supplied digest
    HashCollision,
    /// A label, kind, relationship, reason, or limitation is invalid
    InvalidText { field: &'static str },
    /// The case exceeded a hard record or byte limit
    QuotaExceeded { field: &'static str, maximum: usize },
    /// An evidence resource count could not be represented without overflow
    ArithmeticOverflow { field: &'static str },
    /// A cached aggregate does not match its retained Case records
    InconsistentResourceCount { field: &'static str },
    /// A source with the same hash conflicts with retained source metadata
    SourceMetadataConflict,
    /// A referenced source or blob does not exist
    MissingReference { kind: &'static str },
    /// A byte range is empty, overflows, or exceeds its source length
    InvalidSourceRange,
    /// A node identifier is not the next canonical identifier
    InvalidNodeId,
    /// A blob has no reference from a source or observation node
    OrphanBlob,
    /// One node's serialized details exceed the per-node limit
    NodeDetailsTooLarge { length: usize, maximum: usize },
    /// The serialized details exceed the case-wide limit
    TotalDetailsTooLarge { length: usize, maximum: usize },
    /// A caller-selected resource limit is zero or otherwise invalid
    InvalidResourceLimit { field: &'static str },
    /// A fallible allocation could not reserve the required capacity
    AllocationFailed { field: &'static str },
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { found, expected } => write!(
                formatter,
                "unsupported evidence schema version {found}; expected {expected}"
            ),
            Self::CaseTooLarge { length, maximum } => write!(
                formatter,
                "evidence case has {length} bytes; maximum is {maximum}"
            ),
            Self::InvalidJson => formatter.write_str("invalid evidence case JSON"),
            Self::WriteFailed => formatter.write_str("could not write evidence case JSON"),
            Self::InvalidDigest => formatter.write_str("invalid canonical SHA-256 identifier"),
            Self::HashMismatch => {
                formatter.write_str("evidence bytes do not match their SHA-256 identifier")
            }
            Self::HashCollision => {
                formatter.write_str("different evidence bytes share one SHA-256 identifier")
            }
            Self::InvalidText { field } => write!(formatter, "invalid evidence {field}"),
            Self::QuotaExceeded { field, maximum } => {
                write!(formatter, "evidence {field} exceeds maximum {maximum}")
            }
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "evidence {field} total overflowed")
            }
            Self::InconsistentResourceCount { field } => {
                write!(
                    formatter,
                    "evidence {field} count does not match retained records"
                )
            }
            Self::SourceMetadataConflict => {
                formatter.write_str("source metadata conflicts with an existing content hash")
            }
            Self::MissingReference { kind } => {
                write!(formatter, "missing evidence {kind} reference")
            }
            Self::InvalidSourceRange => formatter.write_str("invalid evidence source byte range"),
            Self::InvalidNodeId => {
                formatter.write_str("evidence node identifiers are not canonical")
            }
            Self::OrphanBlob => formatter.write_str("evidence case contains an unreferenced blob"),
            Self::NodeDetailsTooLarge { length, maximum } => write!(
                formatter,
                "node details have {length} encoded bytes; maximum is {maximum}"
            ),
            Self::TotalDetailsTooLarge { length, maximum } => write!(
                formatter,
                "node details have {length} encoded bytes; case maximum is {maximum}"
            ),
            Self::InvalidResourceLimit { field } => {
                write!(formatter, "evidence {field} resource limit is invalid")
            }
            Self::AllocationFailed { field } => {
                write!(formatter, "could not allocate evidence {field}")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}
