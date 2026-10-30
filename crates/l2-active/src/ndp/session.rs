//! One bounded solicitation and collection of actual captured replies

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, RunError, session};

use super::{NdpObservation, NdpProbe, NdpReport, wire};

const MAX_OBSERVATIONS: usize = 64;

impl NdpProbe {
    /// Send the prepared frame and retain qualifying actual advertisements
    ///
    /// A completed send records socket acceptance, not physical arrival
    ///
    /// # Errors
    /// Returns an error only for preparation failures before sending
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<NdpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Run under an absolute deadline shared with interface and helper setup
    ///
    /// A later deadline cannot extend the prepared operation's time limit
    ///
    /// # Errors
    /// Returns an error only for preparation failures before sending
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<NdpReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        let mut unmatched_packets = 0_u32;
        // Shared accounting includes unrelated frames before protocol matching
        let summary = session::run_single_until(
            link,
            self.frame(),
            self.limits,
            cancelled,
            deadline,
            |frame| {
                let Some((mac, source_ip)) = wire::advertisement(self, frame.bytes()) else {
                    unmatched_packets += 1;
                    return false;
                };
                if !observations
                    .iter()
                    .any(|item: &NdpObservation| item.mac == mac)
                {
                    observations.push(NdpObservation {
                        mac,
                        source_ip,
                        frame,
                    });
                }
                observations.len() == MAX_OBSERVATIONS
            },
        )?;
        Ok(NdpReport {
            expected: self.expected,
            observations,
            unmatched_packets,
            summary,
        })
    }
}
