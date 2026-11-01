//! Bounded receive-only collection of VRRP candidates

use std::{num::NonZeroU8, sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, Limits, RunError, session::run_listen_until};

use super::{VrrpObservation, VrrpReport, wire};

const MAX_OBSERVATIONS: usize = 64;

/// One bounded observation window for IPv4 `VRRPv3` advertisements
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VrrpMonitor {
    vrid: Option<NonZeroU8>,
    limits: Limits,
}

impl VrrpMonitor {
    /// Select an optional VRID and finite receive limits before opening a link
    #[must_use]
    pub const fn new(vrid: Option<NonZeroU8>, limits: Limits) -> Self {
        Self { vrid, limits }
    }

    /// Return the optional selected VRID
    #[must_use]
    pub const fn vrid(self) -> Option<NonZeroU8> {
        self.vrid
    }

    /// Return the admitted receive limits
    #[must_use]
    pub const fn limits(self) -> Limits {
        self.limits
    }

    /// Collect scoped advertisements without sending a packet
    ///
    /// A fixed receive filter must admit this monitor's selected scope; use the
    /// same monitor for helper admission and collection
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<VrrpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Collect under an absolute deadline shared with backend setup
    ///
    /// A fixed receive filter must admit this monitor's selected scope; use the
    /// same monitor for helper admission and collection
    ///
    /// # Errors
    /// Returns an allocation or deadline error before collection begins
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<VrrpReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unrelated_packets = 0_u32;
        // All delivered frames consume the common receive budget before parsing
        let summary = run_listen_until(link, self.limits, cancelled, deadline, |frame| {
            wire::classify(frame.bytes(), self.vrid).map_or_else(
                || {
                    unrelated_packets += 1;
                    false
                },
                |evidence| {
                    // Malformed and unsupported candidates share the same fixed cap
                    observations.push(VrrpObservation { frame, evidence });
                    observations.len() == MAX_OBSERVATIONS
                },
            )
        })?;
        Ok(VrrpReport {
            observations,
            unrelated_packets,
            summary,
        })
    }
}
