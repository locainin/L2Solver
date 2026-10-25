#[path = "../src/budget.rs"]
mod budget;

use budget::{Budget, DEFAULT_CAPTURE_DURATION, MAX_CAPTURE_DURATION, StopReason};
use std::time::{Duration, Instant};

#[test]
fn public_packet_count_bounds() {
    assert!(Budget::validate_packet_count(0).is_err());
    assert!(Budget::validate_packet_count(10_000).is_ok());
    assert!(Budget::validate_packet_count(10_001).is_err());
}

#[test]
fn packet_limit_after_last_packet() {
    let start = Instant::now();
    let mut budget = Budget::new(2, DEFAULT_CAPTURE_DURATION, start);

    assert_eq!(budget.poll(start), None);
    budget.consume_packet();
    assert_eq!(budget.poll(start), None);
    budget.consume_packet();

    assert_eq!(budget.poll(start), Some(StopReason::PacketLimit));
    assert_eq!(budget.poll(start), Some(StopReason::PacketLimit));
    assert_eq!(budget.stop_reason(), Some(StopReason::PacketLimit));
}

#[test]
fn deadline_reports_at_boundary() {
    let start = Instant::now();
    let mut budget = Budget::new(2, DEFAULT_CAPTURE_DURATION, start);
    let boundary = start + DEFAULT_CAPTURE_DURATION;

    assert_eq!(budget.poll(start + Duration::from_secs(29)), None);
    assert_eq!(budget.poll(boundary), Some(StopReason::Deadline));
    assert_eq!(
        budget.poll(boundary + Duration::from_secs(1)),
        Some(StopReason::Deadline)
    );
    assert_eq!(budget.stop_reason(), Some(StopReason::Deadline));
}

#[test]
fn prioritizes_packet_limit() {
    let start = Instant::now();
    let mut budget = Budget::new(1, DEFAULT_CAPTURE_DURATION, start);
    budget.consume_packet();

    assert_eq!(
        budget.poll(start + DEFAULT_CAPTURE_DURATION),
        Some(StopReason::PacketLimit)
    );
}

#[test]
fn accepts_supported_duration_range() {
    assert!(Budget::validate_duration(Duration::ZERO).is_err());
    assert!(Budget::validate_duration(Duration::from_millis(999)).is_err());
    assert!(Budget::validate_duration(Duration::from_secs(1)).is_ok());
    assert!(Budget::validate_duration(MAX_CAPTURE_DURATION).is_ok());
    assert!(Budget::validate_duration(MAX_CAPTURE_DURATION + Duration::from_millis(1)).is_err());
    assert!(Budget::validate_duration(MAX_CAPTURE_DURATION + Duration::from_secs(1)).is_err());
}

#[test]
fn selected_duration_controls_exact_deadline() {
    let start = Instant::now();
    let duration = Duration::from_secs(75);
    let mut budget = Budget::new(2, duration, start);

    assert_eq!(budget.poll(start + Duration::from_secs(74)), None);
    assert_eq!(budget.poll(start + duration), Some(StopReason::Deadline));
}
