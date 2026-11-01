//! Scoped collection of received MPLS candidates

use std::{error::Error, fmt, sync::atomic::AtomicBool, time::Instant};

use l2_onpath::MacAddress;

use crate::{ActiveLink, Limits, RunError, session::run_listen_until};

use super::{MplsObservation, MplsReport, wire};

const MAX_OBSERVATIONS: usize = 64;
const MAX_LABEL_VALUE: u32 = 0x0f_ffff;

/// Invalid bounds or endpoint for one MPLS observation window
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MplsPlanError {
    /// The destination is not a nonzero unicast MAC address
    Destination,
    /// The expected top label does not fit in the 20-bit field
    ExpectedLabel,
}

impl fmt::Display for MplsPlanError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Destination => output.write_str("destination must be a nonzero unicast MAC"),
            Self::ExpectedLabel => output.write_str("expected label exceeds 20 bits"),
        }
    }
}

impl Error for MplsPlanError {}

/// One receive-only window for MPLS frames addressed to one unicast MAC
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MplsMonitor {
    destination: MacAddress,
    expected_top_label: Option<u32>,
    limits: Limits,
}

impl MplsMonitor {
    /// Select a destination, optional expected top label, and finite limits
    ///
    /// The backend must confirm that the destination is the selected local
    /// interface's own MAC before it admits a native capture
    ///
    /// # Errors
    /// Rejects a non-unicast destination or a label wider than 20 bits
    pub fn new(
        destination: [u8; 6],
        expected_top_label: Option<u32>,
        limits: Limits,
    ) -> Result<Self, MplsPlanError> {
        let destination = MacAddress::new(destination).map_err(|_| MplsPlanError::Destination)?;
        if expected_top_label.is_some_and(|label| label > MAX_LABEL_VALUE) {
            return Err(MplsPlanError::ExpectedLabel);
        }
        Ok(Self {
            destination,
            expected_top_label,
            limits,
        })
    }

    /// Return the selected destination MAC
    #[must_use]
    pub const fn destination(self) -> MacAddress {
        self.destination
    }

    /// Return the optional expected value of the top label
    #[must_use]
    pub const fn expected_top_label(self) -> Option<u32> {
        self.expected_top_label
    }

    /// Return the admitted receive limits
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Collect candidate frames without transmitting
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<MplsReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Collect under an absolute deadline shared with backend setup
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<MplsReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unrelated_packets = 0_u32;
        // The common listener charges all delivered frames before classification
        let summary = run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            wire::classify(frame.bytes(), self.destination).map_or_else(
                || {
                    unrelated_packets += 1;
                    false
                },
                |parsed| {
                    // Repeated and malformed candidates share the same fixed cap
                    observations.push(MplsObservation {
                        frame,
                        evidence: parsed.evidence,
                        label_count: parsed.label_count,
                    });
                    observations.len() == MAX_OBSERVATIONS
                },
            )
        })?;
        Ok(MplsReport {
            observations,
            unrelated_packets,
            expected_top_label: self.expected_top_label,
            summary,
        })
    }
}
