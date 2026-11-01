//! Collect scoped ISL candidates without transmitting

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, Limits, RunError, session::run_listen_until};

use super::{IslObservation, IslReport, wire};

// Bound retained raw frames independently of the receive byte budget
const MAX_OBSERVATIONS: usize = 64;

/// One bounded receive-only ISL observation window
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IslMonitor {
    limits: Limits,
}

impl IslMonitor {
    /// Select finite duration and capture budgets
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }
    /// Return the admitted time and receive budgets
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }
    /// Collect scoped ISL candidates without transmitting
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<IslReport, RunError> {
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
    ) -> Result<IslReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unmatched_packets = 0;
        // The shared listener checks scope and charges each received frame
        let summary = run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            wire::classify(frame.bytes()).map_or_else(
                || {
                    unmatched_packets += 1;
                    false
                },
                |evidence| {
                    observations.push(IslObservation { frame, evidence });
                    observations.len() == MAX_OBSERVATIONS
                },
            )
        })?;
        Ok(IslReport {
            observations,
            unmatched_packets,
            summary,
        })
    }
}
