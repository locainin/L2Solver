//! Execute one bounded discover and retain only correlated actual offers

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, RunError, session::run_single_until};

use super::{DhcpObservation, DhcpProbe, DhcpReport, decode};

const MAX_OBSERVATIONS: usize = 64;

impl DhcpProbe {
    /// Submit the preauthorized discover and collect scoped offer evidence
    ///
    /// No lease is requested and no local network state is changed. A socket
    /// accepting the send does not prove that a device received the frame
    ///
    /// # Errors
    /// Returns an error when storage or a deadline cannot be prepared before send
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<DhcpReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Run within an absolute deadline shared with helper and interface setup
    ///
    /// The deadline cannot extend the prepared operation's own time limit
    ///
    /// # Errors
    /// Returns an error when storage or a deadline cannot be prepared before send
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<DhcpReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_OBSERVATIONS)
            .map_err(|_| RunError::Allocation)?;
        // Preserve the exact expectation before any external side effect
        let allowed = if let Some(servers) = &self.allowed {
            let mut copy = Vec::new();
            copy.try_reserve_exact(servers.len())
                .map_err(|_| RunError::Allocation)?;
            copy.extend_from_slice(servers);
            Some(copy)
        } else {
            None
        };
        let summary = run_single_until(
            link,
            self.frame(),
            self.limits,
            cancelled,
            deadline,
            |frame| {
                let Some(offer) = decode::offer(frame.bytes(), self.source, self.transaction)
                else {
                    return false;
                };
                if observations
                    .iter()
                    .any(|existing: &DhcpObservation| existing.offer == offer)
                {
                    return false;
                }
                observations.push(DhcpObservation { offer, frame });
                observations.len() == MAX_OBSERVATIONS
            },
        )?;
        Ok(DhcpReport {
            summary,
            allowed,
            observations,
        })
    }
}
