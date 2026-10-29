//! Failures from model admission and virtual evidence construction

use std::fmt;

/// A virtual topology or execution could not be constructed
#[derive(Debug)]
#[non_exhaustive]
pub enum LabError {
    /// Access VLANs must use IDs from 1 through 4094
    InvalidVlan,
    /// Endpoint addresses must be nonzero unicast Ethernet addresses
    InvalidMac,
    /// An agent, address, or modeled interface is attached more than once
    DuplicateEndpoint,
    /// Every planned agent must have exactly its declared modeled attachment
    UnboundTopology,
    /// Bounded intermediate storage could not be reserved
    Allocation,
    /// A checked internal invariant did not hold
    Invariant,
    /// The independent scheduler rejected the workload
    Admission(l2_scenario::AdmissionError),
    /// The independent scheduler could not produce a terminal report
    Scheduler(l2_scenario::RunError),
    /// Authenticated canary key construction failed
    Key(l2_canary::KeyError),
    /// Planned canary material was invalid
    Canary(l2_canary::CanaryError),
    /// Ethernet frame encoding failed
    Encode(l2_core::EncodeError),
    /// Ethernet frame decoding failed
    Decode(l2_core::DecodeError),
    /// The exact canary frame did not match its plan
    PlannedFrame(l2_segmentation::PlannedFrameError),
    /// A modeled receipt failed the canonical causal checks
    Receipt(l2_segmentation::ReceiptError),
    /// A delivered canary failed the canonical observation checks
    Evaluation(l2_segmentation::EvaluationError),
}

impl fmt::Display for LabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVlan => f.write_str("VLAN must be between 1 and 4094"),
            Self::InvalidMac => f.write_str("endpoint MAC must be a nonzero unicast address"),
            Self::DuplicateEndpoint => f.write_str("duplicate endpoint, MAC, or interface"),
            Self::UnboundTopology => f.write_str("topology does not bind all planned agents"),
            Self::Allocation => f.write_str("virtual lab allocation failed"),
            Self::Invariant => f.write_str("virtual lab invariant failed"),
            Self::Admission(error) => write!(f, "schedule admission failed: {error}"),
            Self::Scheduler(error) => write!(f, "scheduler report failed: {error}"),
            Self::Key(error) => write!(f, "canary key failed: {error}"),
            Self::Canary(error) => write!(f, "canary failed: {error}"),
            Self::Encode(error) => write!(f, "frame encoding failed: {error}"),
            Self::Decode(error) => write!(f, "frame decoding failed: {error}"),
            Self::PlannedFrame(error) => write!(f, "planned frame failed: {error}"),
            Self::Receipt(error) => write!(f, "modeled receipt failed: {error}"),
            Self::Evaluation(error) => write!(f, "modeled observation failed: {error}"),
        }
    }
}

impl std::error::Error for LabError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Scheduler(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Canary(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::PlannedFrame(error) => Some(error),
            Self::Receipt(error) => Some(error),
            Self::Evaluation(error) => Some(error),
            Self::InvalidVlan
            | Self::InvalidMac
            | Self::DuplicateEndpoint
            | Self::UnboundTopology
            | Self::Allocation
            | Self::Invariant => None,
        }
    }
}

macro_rules! from_error {
    ($type:path, $variant:ident) => {
        impl From<$type> for LabError {
            fn from(error: $type) -> Self {
                Self::$variant(error)
            }
        }
    };
}

from_error!(l2_scenario::AdmissionError, Admission);
from_error!(l2_scenario::RunError, Scheduler);
from_error!(l2_canary::KeyError, Key);
from_error!(l2_canary::CanaryError, Canary);
from_error!(l2_core::EncodeError, Encode);
from_error!(l2_core::DecodeError, Decode);
from_error!(l2_segmentation::PlannedFrameError, PlannedFrame);
from_error!(l2_segmentation::ReceiptError, Receipt);
from_error!(l2_segmentation::EvaluationError, Evaluation);
