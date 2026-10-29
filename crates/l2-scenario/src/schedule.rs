//! Admission validates all resource costs before allocating or dispatching work

use l2_onpath::Budget;

use crate::{AdmissionError, Runner, Stimulus};

/// Maximum fixed-size schedule entries retained by one virtual run
///
/// Each entry contains three `u64` values; payloads remain owned by the lab
pub const MAX_STIMULI: usize = 4096;

/// A fully admitted workload in virtual time and protocol sequence order
#[derive(Debug)]
pub struct Schedule {
    pub(crate) stimuli: Vec<Stimulus>,
}

impl Schedule {
    /// Admit the whole workload using canonical on-path resource budgets
    ///
    /// # Errors
    /// Rejects empty, oversized, ambiguous, or over-budget workloads before
    /// dispatch; returns an allocation error if bounded storage is unavailable
    pub fn new(stimuli: &[Stimulus], budget: Budget) -> Result<Self, AdmissionError> {
        if stimuli.is_empty() {
            return Err(AdmissionError::Empty);
        }
        if stimuli.len() > MAX_STIMULI {
            return Err(AdmissionError::ScheduleLimit);
        }
        if stimuli.len() as u64 > budget.packets() {
            return Err(AdmissionError::PacketLimit);
        }
        validate_costs(stimuli, budget)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(stimuli.len())
            .map_err(|_| AdmissionError::Allocation)?;
        owned.extend_from_slice(stimuli);
        // Sorting in place avoids an unaccounted set or stable-sort scratch buffer
        owned.sort_unstable_by_key(|s| s.sequence());
        if owned
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a.sequence() == b.sequence()))
        {
            return Err(AdmissionError::DuplicateSequence);
        }
        owned.sort_unstable_by_key(|s| (s.at_millis(), s.sequence()));
        Ok(Self { stimuli: owned })
    }

    /// Start a virtual run without spawning tasks or opening interfaces
    #[must_use]
    pub const fn start(self) -> Runner {
        Runner::new(self)
    }
}

// Cost validation stays pure and completes before schedule storage is allocated
fn validate_costs(stimuli: &[Stimulus], budget: Budget) -> Result<(), AdmissionError> {
    let mut bytes = 0_u64;
    for stimulus in stimuli {
        if stimulus.sequence() == 0 || stimulus.frame_bytes() == 0 {
            return Err(AdmissionError::InvalidStimulus);
        }
        bytes = bytes
            .checked_add(stimulus.frame_bytes())
            .ok_or(AdmissionError::ByteLimit)?;
        if bytes > budget.bytes() {
            return Err(AdmissionError::ByteLimit);
        }
        if stimulus.at_millis() > budget.duration_millis() {
            return Err(AdmissionError::DurationLimit);
        }
    }
    Ok(())
}
