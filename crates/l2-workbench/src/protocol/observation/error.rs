use crate::protocol::ByteRange;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Invalid input or resource configuration for one observation pass
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationError {
    /// The configured limits exceed the module's hard safety ceilings
    InvalidLimits,
    /// The request cannot be represented within the module's hard input ceiling
    InvalidPlan,
    /// Two admitted inputs use the same caller-supplied sample identifier
    DuplicateSample { sample: u64 },
    /// A requested interval is empty or has its end before its start
    InvalidRange { range: ByteRange },
    /// A provenance mapping does not describe the complete input coordinate space
    InvalidProvenance { sample: u64 },
    /// A bounded report allocation could not reserve memory
    AllocationFailed { field: &'static str },
}

impl Display for ObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("observation limits exceed hard ceilings"),
            Self::InvalidPlan => formatter.write_str("observation plan exceeds hard ceilings"),
            Self::DuplicateSample { sample } => {
                write!(
                    formatter,
                    "duplicate observation sample identifier {sample}"
                )
            }
            Self::InvalidRange { range } => write!(
                formatter,
                "invalid byte range {}..{}",
                range.start, range.end
            ),
            Self::InvalidProvenance { sample } => {
                write!(
                    formatter,
                    "invalid provenance for observation sample {sample}"
                )
            }
            Self::AllocationFailed { field } => {
                write!(formatter, "could not reserve memory for {field}")
            }
        }
    }
}

impl Error for ObservationError {}
