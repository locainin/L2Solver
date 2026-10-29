//! Errors for source construction and state-record resolution

use std::fmt;

/// A state source or record reference failed validation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateSourceError {
    /// The source exceeds the bounded record count
    RecordLimit,
    /// A subject address does not identify an on-link neighbor
    InvalidAddress,
    /// A source is malformed, truncated, or not canonical
    InvalidEncoding,
    /// Record numbers are one based
    ZeroRecord,
    /// The reference names another source
    SourceMismatch,
    /// The record does not exist in the referenced source
    RecordOutOfBounds,
    /// Bounded source storage could not be reserved
    Allocation,
}

impl fmt::Display for StateSourceError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::RecordLimit => "state source record limit exceeded",
            Self::InvalidAddress => "invalid neighbor address in state record",
            Self::InvalidEncoding => "invalid state source encoding",
            Self::ZeroRecord => "state record number must be nonzero",
            Self::SourceMismatch => "state reference names another source",
            Self::RecordOutOfBounds => "state record is outside the source",
            Self::Allocation => "state source allocation failed",
        })
    }
}

impl std::error::Error for StateSourceError {}
