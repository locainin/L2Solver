//! Construction and pre-dispatch allocation errors

use std::fmt;

/// An active operation cannot be prepared with the supplied scope or limits
#[derive(Debug)]
#[non_exhaustive]
pub enum PlanError {
    /// An IPv4 address cannot name one on-link host
    InvalidAddress,
    /// The target is the selected source address
    SameAddress,
    /// The deadline is zero, too short, or above the fixed ceiling
    InvalidTimeout,
    /// The packet ceiling is zero or too large
    InvalidPacketLimit,
    /// The captured-byte ceiling is zero or too large
    InvalidByteLimit,
    /// The shared Ethernet encoder rejected the request
    Encode(l2_core::EncodeError),
}

impl fmt::Display for PlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => output.write_str("address does not identify an IPv4 host"),
            Self::SameAddress => output.write_str("target must differ from the source address"),
            Self::InvalidTimeout => output.write_str("timeout is outside the allowed range"),
            Self::InvalidPacketLimit => {
                output.write_str("receive packet limit is outside the allowed range")
            }
            Self::InvalidByteLimit => {
                output.write_str("receive byte limit is outside the allowed range")
            }
            Self::Encode(error) => write!(output, "cannot encode the request: {error}"),
        }
    }
}

impl std::error::Error for PlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// An operation could not be prepared before any network transmission
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunError {
    /// Bounded result storage could not be reserved
    Allocation,
    /// The requested deadline cannot be represented by the platform clock
    DeadlineOverflow,
}

impl fmt::Display for RunError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Allocation => "cannot reserve bounded observation storage",
            Self::DeadlineOverflow => "operation deadline is not representable",
        })
    }
}

impl std::error::Error for RunError {}
