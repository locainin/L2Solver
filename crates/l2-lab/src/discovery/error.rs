//! Errors for bounded admission and deterministic execution

use core::fmt;
use l2_scenario::{AdmissionError, RunError};

/// Failure to construct or execute the synthetic discovery workload
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The receiver and a stimulus source use the same controlled identity
    SameAgent,
    /// A probe frame is empty or exceeds the modeled Ethernet frame limit
    FrameLimit,
    /// An expected identity is empty or exceeds the modeled identity limit
    IdentityLimit,
    /// The workload exceeds the modeled receiver's fixed event ceiling
    ProbeLimit,
    /// Bounded storage could not be reserved
    Allocation,
    /// The canonical scheduler rejected the workload or its resource budget
    Admission(AdmissionError),
    /// The scheduler could not finish the requested run
    Execution(RunError),
    /// An internal sequence or evidence invariant was violated
    Invariant,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameAgent => formatter.write_str("source and receiver identities must differ"),
            Self::FrameLimit => formatter.write_str("frame exceeds the modeled size limits"),
            Self::IdentityLimit => {
                formatter.write_str("expected identity exceeds the modeled size limits")
            }
            Self::ProbeLimit => formatter.write_str("discovery probe ceiling exceeded"),
            Self::Allocation => formatter.write_str("discovery allocation failed"),
            Self::Admission(error) => write!(formatter, "discovery admission failed: {error}"),
            Self::Execution(error) => write!(formatter, "discovery execution failed: {error}"),
            Self::Invariant => formatter.write_str("discovery execution invariant failed"),
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AdmissionError> for DiscoveryError {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<RunError> for DiscoveryError {
    fn from(error: RunError) -> Self {
        Self::Execution(error)
    }
}
