//! Libpcap timestamps have microsecond units unless configured otherwise

use l2_capture::{CaptureTimestamp, TimestampResolution, TimestampSource};

pub fn timestamp(seconds: i64, microseconds: i64) -> Result<CaptureTimestamp, &'static str> {
    let seconds = u64::try_from(seconds).map_err(|_| "negative capture timestamp")?;
    let fraction = u64::try_from(microseconds).map_err(|_| "negative timestamp fraction")?;
    if fraction >= 1_000_000 {
        return Err("invalid microsecond fraction");
    }
    let ticks = seconds
        .checked_mul(1_000_000)
        .and_then(|base| base.checked_add(fraction))
        .ok_or("capture timestamp overflow")?;
    // The hardware/kernel timestamp source is not exposed by this backend
    Ok(CaptureTimestamp::new(
        ticks,
        TimestampResolution::MICROSECOND,
        0,
        TimestampSource::Unknown,
    ))
}
