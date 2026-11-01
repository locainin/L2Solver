use std::{
    error::Error,
    time::{Duration, Instant},
};

use l2_active::Limits;

use super::budget::{phase_deadline, remaining_limits};

#[test]
fn phase_windows_share_one_deadline_without_extending_it() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let overall = start + Duration::from_millis(90);
    let first = phase_deadline(start, overall, 3).ok_or("missing first window")?;
    let second = phase_deadline(first, overall, 2).ok_or("missing second window")?;
    let third = phase_deadline(second, overall, 1).ok_or("missing third window")?;
    assert_eq!(first.duration_since(start), Duration::from_millis(30));
    assert_eq!(second.duration_since(first), Duration::from_millis(30));
    assert_eq!(third, overall);
    Ok(())
}

#[test]
fn expired_or_submillisecond_phase_never_authorizes_an_attempt() {
    let now = Instant::now();
    assert!(phase_deadline(now, now, 1).is_none());
    assert!(phase_deadline(now, now + Duration::from_millis(2), 3).is_none());
    assert!(phase_deadline(now, now + Duration::from_millis(3), 0).is_none());
}

#[test]
fn second_control_uses_only_the_first_control_remaining_budget() -> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(3), 10, 1_000)?;
    let remaining = remaining_limits(budget, Some(3), Some(240), Duration::from_secs(1))
        .ok_or("remaining control budget is unavailable")?;
    assert_eq!(remaining.max_received_packets(), 7);
    assert_eq!(remaining.max_received_bytes(), 760);
    assert_eq!(remaining.timeout(), Duration::from_secs(1));
    Ok(())
}

#[test]
fn exhausted_unknown_or_overdrawn_control_budget_prevents_another_attempt()
-> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(3), 10, 1_000)?;
    for (packets, bytes) in [
        (None, Some(0)),
        (Some(0), None),
        (Some(10), Some(0)),
        (Some(0), Some(1_000)),
        (Some(11), Some(0)),
        (Some(0), Some(1_001)),
        (Some(u64::MAX), Some(0)),
    ] {
        assert!(remaining_limits(budget, packets, bytes, Duration::from_secs(1)).is_none());
    }
    assert!(remaining_limits(budget, Some(0), Some(0), Duration::from_millis(0)).is_none());
    assert!(remaining_limits(budget, Some(0), Some(0), Duration::from_secs(4)).is_none());
    Ok(())
}
