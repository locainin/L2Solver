//! Collect bounded HSRP candidates without transmitting

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, Limits, RunError, session::run_listen_until};

use super::{HsrpObservation, HsrpReport, wire};

// Limit retained captures independently of the shared packet and byte budgets
const MAX_OBSERVATIONS: usize = 64;

/// One receive-only observation window for Ethernet HSRPv1/IPv4 messages
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HsrpMonitor {
    group: Option<u8>,
    limits: Limits,
}

impl HsrpMonitor {
    /// Select one group or all groups, with finite receive limits
    #[must_use]
    pub const fn new(group: Option<u8>, limits: Limits) -> Self {
        Self { group, limits }
    }

    /// Return the selected group, or all groups when absent
    #[must_use]
    pub const fn group(self) -> Option<u8> {
        self.group
    }

    /// Return the admitted time and capture limits
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Collect scoped messages without sending a packet
    ///
    /// A link with a fixed capture filter must admit this monitor's selected
    /// group. Reuse the same monitor supplied when opening such a link
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<HsrpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Collect under an absolute deadline shared with backend setup
    ///
    /// A link with a fixed capture filter must admit this monitor's selected
    /// group. Reuse the same monitor supplied when opening such a link
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<HsrpReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unmatched_packets = 0_u32;
        // The shared listener accounts for each frame before this classification
        let summary = run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            wire::classify(frame.bytes(), self.group).map_or_else(
                || {
                    unmatched_packets += 1;
                    false
                },
                |evidence| {
                    observations.push(HsrpObservation { frame, evidence });
                    observations.len() == MAX_OBSERVATIONS
                },
            )
        })?;
        Ok(HsrpReport {
            observations,
            unmatched_packets,
            summary,
        })
    }
}
