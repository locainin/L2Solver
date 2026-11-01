//! Collect VTP candidates without transmitting

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, Limits, RunError, switching::session::collect};

use super::{VtpObservation, VtpReport, wire};

/// One bounded receive-only VTP observation window
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VtpMonitor {
    limits: Limits,
}

impl VtpMonitor {
    /// Select the finite duration and capture budgets
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }
    /// Return the admitted time and capture budgets
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }
    /// Collect scoped VTP frames without sending a packet
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<VtpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }
    /// Collect under a shared absolute deadline that cannot extend the limit
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<VtpReport, RunError> {
        let collected = collect(
            link,
            self.limits,
            cancelled,
            deadline,
            wire::classify,
            |frame, evidence| VtpObservation { frame, evidence },
        )?;
        Ok(VtpReport {
            observations: collected.observations,
            unmatched_packets: collected.unmatched_packets,
            summary: collected.summary,
        })
    }
}
