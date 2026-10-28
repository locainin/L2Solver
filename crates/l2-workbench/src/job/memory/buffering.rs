//! Measurements for completed Cases waiting for ordered collection

use super::{MemoryBudget, MemoryError};
use serde::Serialize;
use std::time::Instant;

/// Current and peak retention in the ordered result handoff
///
/// Charged bytes are a subset of the existing memory charges, not an additional reservation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BufferedCaseSnapshot {
    /// Completed Cases not yet taken by the ordered collector
    pub current_cases: u64,
    /// Retained Case charges represented by those results
    pub current_charged_bytes: u64,
    /// Largest number of simultaneously buffered Cases
    pub peak_cases: u64,
    /// Largest simultaneous retained Case charge in the handoff
    pub peak_charged_bytes: u64,
    /// Number of results taken or discarded by the collector
    pub completed_waits: u64,
    /// Longest completed wait, measured with a monotonic clock
    pub longest_wait_ms: u64,
    /// Sum of completed waits, saturating at the largest representable duration
    pub total_wait_ms: u64,
}

/// Live observation of a completed Case waiting for ordered collection
///
/// Dropping this value ends the observation without changing allocation charges
#[derive(Debug)]
pub struct BufferedCase {
    budget: MemoryBudget,
    charged_bytes: u64,
    started: Instant,
}

impl MemoryBudget {
    /// Observe an already charged Case until the ordered collector takes its result
    ///
    /// This records retention only; callers keep the Case's existing leases alive
    ///
    /// # Errors
    /// Returns an error for poisoned state or overflowing telemetry, without changing state
    pub fn observe_buffered_case(&self, charged_bytes: u64) -> Result<BufferedCase, MemoryError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        let buffered = &mut state.buffered_cases;
        let cases = buffered
            .current_cases
            .checked_add(1)
            .ok_or(MemoryError::ObservationOverflow)?;
        let bytes = buffered
            .current_charged_bytes
            .checked_add(charged_bytes)
            .ok_or(MemoryError::ObservationOverflow)?;
        buffered.current_cases = cases;
        buffered.current_charged_bytes = bytes;
        buffered.peak_cases = buffered.peak_cases.max(cases);
        buffered.peak_charged_bytes = buffered.peak_charged_bytes.max(bytes);
        drop(state);
        Ok(BufferedCase {
            budget: self.clone(),
            charged_bytes,
            started: Instant::now(),
        })
    }
}

impl Drop for BufferedCase {
    fn drop(&mut self) {
        // Poisoning has already made the shared budget unusable
        if let Ok(mut state) = self.budget.shared.state.lock() {
            let buffered = &mut state.buffered_cases;
            buffered.current_cases -= 1;
            buffered.current_charged_bytes -= self.charged_bytes;
            let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            buffered.longest_wait_ms = buffered.longest_wait_ms.max(elapsed);
            buffered.total_wait_ms = buffered.total_wait_ms.saturating_add(elapsed);
            buffered.completed_waits = buffered.completed_waits.saturating_add(1);
        }
    }
}
