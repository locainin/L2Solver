//! Configuration and bounded execution errors

use std::fmt;

/// A DHCP model could not be admitted or executed
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Clients and server attachment identities must be distinct
    DuplicateAgent,
    /// Server identifiers and offered addresses must be distinct unicast values
    InvalidAddress,
    /// Both transaction identifiers must be nonzero and distinct
    InvalidTransaction,
    /// The expected authorized-server limit must be one or two leases
    InvalidLeaseLimit,
    /// The scheduler rejected the workload before execution
    Admission(l2_scenario::AdmissionError),
    /// The scheduler could not produce a terminal report
    Scheduler(l2_scenario::RunError),
    /// Bounded evidence storage could not be reserved
    Allocation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateAgent => f.write_str("DHCP agents must be distinct"),
            Self::InvalidAddress => f.write_str("DHCP addresses must be distinct unicast values"),
            Self::InvalidTransaction => {
                f.write_str("DHCP transaction IDs must be nonzero and distinct")
            }
            Self::InvalidLeaseLimit => f.write_str("DHCP lease limit must be one or two"),
            Self::Admission(error) => write!(f, "DHCP schedule admission failed: {error}"),
            Self::Scheduler(error) => write!(f, "DHCP scheduler report failed: {error}"),
            Self::Allocation => f.write_str("DHCP evidence allocation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Scheduler(error) => Some(error),
            _ => None,
        }
    }
}

impl From<l2_scenario::AdmissionError> for Error {
    fn from(error: l2_scenario::AdmissionError) -> Self {
        Self::Admission(error)
    }
}

impl From<l2_scenario::RunError> for Error {
    fn from(error: l2_scenario::RunError) -> Self {
        Self::Scheduler(error)
    }
}
