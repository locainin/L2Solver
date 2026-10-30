#[cfg(test)]
#[path = "../tests/time/deadline.rs"]
mod tests;

use std::{
    io,
    time::{Duration, Instant},
};

// Both processes use the same Linux monotonic clock and conservative samples
pub fn encode_deadline(deadline: Instant, ceiling: Duration) -> io::Result<u64> {
    let monotonic = monotonic_nanos()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(expired)?
        .min(ceiling);
    let nanos = u64::try_from(remaining.as_nanos()).map_err(io::Error::other)?;
    if nanos == 0 {
        return Err(expired());
    }
    monotonic
        .checked_add(nanos)
        .ok_or_else(|| io::Error::other("monotonic deadline overflow"))
}

pub fn decode_deadline(deadline: u64) -> io::Result<Instant> {
    let sampled = Instant::now();
    let remaining = deadline
        .checked_sub(monotonic_nanos()?)
        .filter(|value| *value > 0)
        .ok_or_else(expired)?;
    let duration = Duration::from_nanos(remaining);
    if duration > l2_active::MAX_TIMEOUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "deadline exceeds the worker ceiling",
        ));
    }
    sampled
        .checked_add(duration)
        .ok_or_else(|| io::Error::other("monotonic deadline overflow"))
}

pub fn admitted_deadline(deadline: u64) -> io::Result<Instant> {
    let bound = decode_deadline(deadline)?;
    let now = Instant::now();
    let remaining = bound
        .checked_duration_since(now)
        .filter(|value| !value.is_zero())
        .ok_or_else(expired)?;
    // A small conservative guard covers independent clock sampling in the worker
    let guard = (remaining / 10).min(Duration::from_millis(1));
    bound
        .checked_sub(guard)
        .filter(|value| *value > now)
        .ok_or_else(expired)
}

pub fn ensure_before(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(expired());
    }
    Ok(())
}

fn monotonic_nanos() -> io::Result<u64> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(value.tv_sec).map_err(io::Error::other)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(io::Error::other)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| io::Error::other("monotonic clock overflow"))
}

fn expired() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "operation deadline elapsed")
}
