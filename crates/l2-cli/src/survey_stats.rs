//! Pure normalization for live capture accounting

/// Widen both kernel counters before adding them to survey quality
#[must_use]
pub fn total_drops(capture_dropped: u32, interface_dropped: u32) -> u64 {
    u64::from(capture_dropped) + u64::from(interface_dropped)
}
