//! Dispatch and cancellation have one terminal state and bounded accounting

use crate::{Dispatch, RunError, Schedule, Stimulus};

/// Caller control sampled before each virtual dispatch
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Dispatch the next admitted event
    Continue,
    /// Permanently cancel remaining work
    Cancel,
}

/// Why a virtual run stopped dispatching
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// Every admitted stimulus was dispatched
    Exhausted,
    /// Cancellation prevented further dispatch
    Cancelled,
}

/// Lab-owned claim about verified restoration of controlled state
///
/// A caller must compare before and after state before claiming confirmation
/// This value carries no authority over physical interfaces
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cleanup {
    /// Before and after controlled state were observed to agree
    Confirmed,
    /// Restoration was attempted or its result is unknown
    Unconfirmed,
}

/// Execution accounting without any network-control verdict
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunReport {
    stop_reason: StopReason,
    packets: u64,
    bytes: u64,
    elapsed_millis: u64,
    cleanup: Cleanup,
}

impl RunReport {
    /// Return the terminal scheduler outcome
    #[must_use]
    pub const fn stop_reason(self) -> StopReason {
        self.stop_reason
    }
    /// Return the number of virtual packets dispatched
    #[must_use]
    pub const fn packets(self) -> u64 {
        self.packets
    }
    /// Return complete frame bytes charged at dispatch
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
    /// Return the last dispatched virtual time offset
    #[must_use]
    pub const fn elapsed_millis(self) -> u64 {
        self.elapsed_millis
    }
    /// Return the lab's explicit cleanup claim
    #[must_use]
    pub const fn cleanup(self) -> Cleanup {
        self.cleanup
    }
}

/// An admitted schedule advanced solely by explicit caller polling
#[derive(Debug)]
pub struct Runner {
    schedule: Schedule,
    cursor: usize,
    cancelled: bool,
}

impl Runner {
    pub(crate) const fn new(schedule: Schedule) -> Self {
        Self {
            schedule,
            cursor: 0,
            cancelled: false,
        }
    }

    /// Release one event, charging it before returning to the modeled backend
    ///
    /// Cancellation is permanent and cannot rewrite an already exhausted run
    pub fn next(&mut self, control: Control) -> Option<Dispatch> {
        // Completed work wins over a late cancellation request
        let stimulus = self.schedule.stimuli.get(self.cursor).copied()?;
        if matches!(control, Control::Cancel) {
            self.cancelled = true;
        }
        if self.cancelled {
            return None;
        }
        self.cursor += 1;
        Some(Dispatch(stimulus))
    }

    /// Describe stopped execution while preserving the independent cleanup claim
    ///
    /// # Errors
    /// Returns [`RunError::StillRunning`] while undispatched work remains
    pub fn report(&self, cleanup: Cleanup) -> Result<RunReport, RunError> {
        let stop_reason = if self.cancelled {
            StopReason::Cancelled
        } else if self.cursor == self.schedule.stimuli.len() {
            StopReason::Exhausted
        } else {
            return Err(RunError::StillRunning);
        };
        // Derive usage from the admitted prefix rather than keep duplicate counters
        let dispatched = self.schedule.stimuli.iter().take(self.cursor).copied();
        let bytes = dispatched.clone().map(Stimulus::frame_bytes).sum();
        let elapsed_millis = dispatched.last().map_or(0, Stimulus::at_millis);
        Ok(RunReport {
            stop_reason,
            packets: self.cursor as u64,
            bytes,
            elapsed_millis,
            cleanup,
        })
    }
}
