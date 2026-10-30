//! Send once and collect scoped EAPOL evidence through the shared runner

use std::{sync::atomic::AtomicBool, time::Instant};

use crate::{ActiveLink, RunError, session::run_single_until};

use super::{Dot1xMalformed, Dot1xObservation, Dot1xProbe, Dot1xReport, wire};

// A shared cap preserves both valid and malformed evidence within a fixed bound
const MAX_EVIDENCE: usize = 64;

impl Dot1xProbe {
    /// Submit one prepared Start and collect actual scoped requests
    ///
    /// Sending a Start can affect an existing supplicant. A successful send
    /// means socket acceptance, not that a device received the frame
    ///
    /// # Errors
    /// Returns an error when storage or a deadline cannot be prepared before send
    pub fn run(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
    ) -> Result<Dot1xReport, RunError> {
        let deadline = Instant::now()
            .checked_add(self.limits.timeout())
            .ok_or(RunError::DeadlineOverflow)?;
        self.run_until(link, cancelled, deadline)
    }

    /// Run under an absolute deadline shared with backend startup
    ///
    /// A later deadline cannot extend the prepared operation's own limit
    ///
    /// # Errors
    /// Returns an error when storage or a deadline cannot be prepared before send
    pub fn run_until(
        &self,
        link: &mut impl ActiveLink,
        cancelled: &AtomicBool,
        deadline: Instant,
    ) -> Result<Dot1xReport, RunError> {
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(MAX_EVIDENCE)
            .map_err(|_| RunError::Allocation)?;
        let mut malformed = Vec::new();
        malformed
            .try_reserve_exact(MAX_EVIDENCE)
            .map_err(|_| RunError::Allocation)?;
        let mut unrelated_packets = 0_u32;
        // All frames consume the shared receive budget before this classification
        let summary = run_single_until(
            link,
            self.frame(),
            self.limits,
            cancelled,
            deadline,
            |frame| {
                match wire::classify(frame.bytes(), self.source) {
                    wire::Classification::Request(request) => {
                        observations.push(Dot1xObservation { request, frame });
                    }
                    wire::Classification::Malformed(reason) => {
                        malformed.push(Dot1xMalformed { reason, frame });
                    }
                    wire::Classification::Unrelated => unrelated_packets += 1,
                }
                observations.len() + malformed.len() == MAX_EVIDENCE
            },
        )?;
        Ok(Dot1xReport {
            observations,
            malformed,
            unrelated_packets,
            summary,
        })
    }
}
