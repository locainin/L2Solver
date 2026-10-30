//! Receive actual discovery advertisements without sending a packet

use std::{sync::atomic::AtomicBool, time::Instant};

use super::decode;
use super::{DiscoveryObservation, DiscoveryReport};
use crate::{ActiveLink, Limits, RunError, session::run_listen_until};

/// Maximum recognized discovery frames retained by one bounded operation
pub const MAX_OBSERVATIONS: usize = 64;

/// One bounded receive-only discovery collection
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryMonitor {
    limits: Limits,
}

impl DiscoveryMonitor {
    /// Select finite duration and receive limits before opening a link
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }
    /// Return the admitted receive limits
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }
    /// Collect real frames on the selected active link without transmitting
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<DiscoveryReport, RunError> {
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
    ) -> Result<DiscoveryReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unmatched_packets = 0;
        let summary = run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            if let Some(decoded) = decode::decode(frame.bytes()) {
                observations.push(DiscoveryObservation::new(frame, decoded));
                return observations.len() == MAX_OBSERVATIONS;
            }
            unmatched_packets += 1;
            false
        })?;
        Ok(DiscoveryReport {
            summary,
            observations,
            unmatched_packets,
        })
    }
}
