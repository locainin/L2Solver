use super::super::RecordError;
use std::{error::Error, fmt};

/// Invalid search configuration or resource failure during record discovery
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordDiscoveryError {
    /// A required discovery limit is zero
    InvalidLimits,
    /// A required caller-supplied candidate domain is empty
    EmptyDomain { field: &'static str },
    /// Candidate generation requires at least one training message
    NoTrainingMessages { held_out: usize },
    /// At least two training messages are required
    InsufficientMessages { training: usize, held_out: usize },
    /// Total training and held-out messages exceed the discovery ceiling
    TooManyMessages { count: usize, maximum: usize },
    /// Aggregate framed message bytes exceed the configured record input limit
    RecordOperation(RecordError),
}

impl fmt::Display for RecordDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("record discovery limits must be positive"),
            Self::EmptyDomain { field } => {
                write!(
                    formatter,
                    "record discovery domain {field} must not be empty"
                )
            }
            Self::NoTrainingMessages { held_out } => write!(
                formatter,
                "record schema proposal needs a training message; got {held_out} held-out messages"
            ),
            Self::InsufficientMessages { training, held_out } => write!(
                formatter,
                "record discovery needs at least two training messages; got {training} with {held_out} held-out messages"
            ),
            Self::TooManyMessages { count, maximum } => write!(
                formatter,
                "record discovery has {count} messages; maximum is {maximum}"
            ),
            Self::RecordOperation(error) => write!(formatter, "record discovery: {error}"),
        }
    }
}

impl Error for RecordDiscoveryError {}
