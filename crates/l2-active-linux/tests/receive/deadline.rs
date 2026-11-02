use std::time::{Duration, Instant};

use l2_active::ReceiveEvent;

#[test]
fn earlier_worker_deadline_remains_final_after_both_deadlines_expire() {
    let base = Instant::now();
    let worker = base + Duration::from_millis(10);
    let request = base + Duration::from_millis(20);
    let now = base + Duration::from_millis(30);
    assert!(matches!(
        super::deadline_status(now, request, worker),
        Some(ReceiveEvent::BackendTimedOut)
    ));
}

#[test]
fn earlier_request_deadline_is_preserved_after_both_deadlines_expire() {
    let base = Instant::now();
    let request = base + Duration::from_millis(10);
    let worker = base + Duration::from_millis(20);
    let now = base + Duration::from_millis(30);
    assert!(matches!(
        super::deadline_status(now, request, worker),
        Some(ReceiveEvent::TimedOut)
    ));
}

#[test]
fn future_and_equal_deadlines_have_consistent_status() {
    let now = Instant::now();
    assert!(matches!(
        super::deadline_status(now, now + Duration::from_millis(1), now),
        Some(ReceiveEvent::BackendTimedOut)
    ));
    assert!(matches!(
        super::deadline_status(now, now, now),
        Some(ReceiveEvent::TimedOut)
    ));
    assert!(
        super::deadline_status(
            now,
            now + Duration::from_millis(1),
            now + Duration::from_millis(2)
        )
        .is_none()
    );
}
