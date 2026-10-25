//! Capture timestamps are rounded down to nanoseconds only for replay scheduling

use l2_capture::CaptureTimestamp;

pub fn nanoseconds(timestamp: CaptureTimestamp) -> i128 {
    let numerator = i128::from(timestamp.ticks()) * 1_000_000_000;
    // A denominator beyond i128 is larger than every possible numerator
    let resolution = timestamp.resolution();
    let denominator = i128::from(resolution.radix()).checked_pow(u32::from(resolution.exponent()));
    let fraction = denominator.map_or(0, |value| numerator / value);
    i128::from(timestamp.offset_seconds()) * 1_000_000_000 + fraction
}
