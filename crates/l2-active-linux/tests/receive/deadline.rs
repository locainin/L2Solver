use std::time::{Duration, Instant};

use l2_active::ReceiveEvent;

#[test]
fn earlier_worker_deadline_remains_final_after_both_deadlines_expire() {
    let now = Instant::now();
    let worker = now - Duration::from_millis(20);
    let request = now - Duration::from_millis(10);
    assert!(matches!(
        super::deadline_status(now, request, worker),
        Some(ReceiveEvent::BackendTimedOut)
    ));
}

#[test]
fn earlier_request_deadline_is_preserved_after_both_deadlines_expire() {
    let now = Instant::now();
    let request = now - Duration::from_millis(20);
    let worker = now - Duration::from_millis(10);
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
