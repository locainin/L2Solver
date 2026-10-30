//! Scoped collection of actual inbound spanning-tree candidates

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, Limits, RunError, session};

use super::{StpObservation, StpReport, wire};

const MAX_OBSERVATIONS: usize = 64;

/// A bounded receive-only inventory of standard Ethernet STP traffic
#[derive(Clone, Copy, Debug)]
pub struct StpMonitor {
    limits: Limits,
}

impl StpMonitor {
    /// Set the admitted capture-work and time ceilings
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }

    /// Return the admitted capture limits
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Collect without transmitting and retain distinct candidate frames
    ///
    /// # Errors
    /// Returns an error if bounded result preparation fails
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<StpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Collect under an absolute deadline shared with interface setup
    ///
    /// # Errors
    /// Returns an error if bounded result preparation fails
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<StpReport, RunError> {
        let mut observations: Vec<StpObservation> = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unrelated_packets = 0_u32;
        let summary = session::run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            let Some(evidence) = wire::classify(&frame) else {
                unrelated_packets += 1;
                return false;
            };
            // Identical copies count as work but do not consume another slot
            if observations
                .iter()
                .any(|observation| observation.frame.bytes() == frame.bytes())
            {
                return false;
            }
            observations.push(StpObservation { frame, evidence });
            observations.len() == MAX_OBSERVATIONS
        })?;
        Ok(StpReport {
            observations,
            unrelated_packets,
            summary,
        })
    }
}
