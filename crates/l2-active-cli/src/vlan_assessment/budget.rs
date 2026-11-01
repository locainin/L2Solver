//! Divide the assessment's time and per-interface capture budgets

use std::time::{Duration, Instant};

use l2_active::Limits;

pub(super) fn phase_deadline(now: Instant, overall: Instant, phases_left: u32) -> Option<Instant> {
    // Leave time for every remaining phase, including helper startup
    let window = overall
        .checked_duration_since(now)?
        .checked_div(phases_left)?;
    if window < Duration::from_millis(1) {
        return None;
    }
    now.checked_add(window)
}

pub(super) fn remaining_limits(
    budget: Limits,
    used_packets: Option<u64>,
    used_bytes: Option<u64>,
    duration: Duration,
) -> Option<Limits> {
    if duration > budget.timeout() {
        return None;
    }
    // An unknown first total cannot authorize more work on that interface
    let packets = budget
        .max_received_packets()
        .checked_sub(u32::try_from(used_packets?).ok()?)?;
    let bytes = budget.max_received_bytes().checked_sub(used_bytes?)?;
    Limits::new(duration, packets, bytes).ok()
}
