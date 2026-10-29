//! Errors from admitting or executing the synthetic STP scenario

use std::fmt;

/// A bounded virtual STP experiment could not be prepared or completed
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A bridge identity cannot name a modeled unicast bridge
    InvalidBridge,
    /// Ethernet framing does not describe a supported STP access-link packet
    InvalidFrame,
    /// The test does not contain distinct, ordered control and hostile roots
    InvalidScenario,
    /// Previous fault-injected state has not yet been restored
    DirtyState,
    /// Bounded capture storage could not be reserved
    Allocation,
    /// A checked internal invariant failed
    Invariant,
    /// The shared scheduler rejected the packet workload
    Admission(l2_scenario::AdmissionError),
    /// The shared scheduler did not reach a terminal state
    Scheduler(l2_scenario::RunError),
    /// Ethernet decoding rejected the complete supplied frame
    Ethernet(l2_core::DecodeError),
    /// The canonical BPDU decoder rejected the payload
    Bpdu(l2_codecs::StpError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBridge => f.write_str("invalid modeled bridge identity"),
            Self::InvalidFrame => f.write_str("invalid modeled STP Ethernet frame"),
            Self::InvalidScenario => f.write_str("invalid STP control or superior root"),
            Self::DirtyState => f.write_str("modeled bridge state requires restoration"),
            Self::Allocation => f.write_str("STP capture allocation failed"),
            Self::Invariant => f.write_str("STP model invariant failed"),
            Self::Admission(error) => write!(f, "STP schedule admission failed: {error}"),
            Self::Scheduler(error) => write!(f, "STP scheduler report failed: {error}"),
            Self::Ethernet(error) => write!(f, "Ethernet decode failed: {error}"),
            Self::Bpdu(error) => write!(f, "BPDU decode failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Scheduler(error) => Some(error),
            Self::Ethernet(error) => Some(error),
            Self::Bpdu(error) => Some(error),
            Self::InvalidBridge
            | Self::InvalidFrame
            | Self::InvalidScenario
            | Self::DirtyState
            | Self::Allocation
            | Self::Invariant => None,
        }
    }
}
