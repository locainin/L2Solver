use l2_workbench::measurement::{Clock, IntervalStatus, TimedSample, measure_timing};
use std::error::Error;

fn clock(id: &str, scope: &str) -> Result<Clock, Box<dyn Error>> {
    Ok(Clock::new(id, scope, 10, 6, 0)?)
}

const fn sample(packet: u64, clock: Clock, ticks: Option<u64>) -> TimedSample {
    TimedSample {
        packet,
        clock,
        ticks,
    }
}

#[test]
fn same_clock_deltas_missing_ticks() -> Result<(), Box<dyn Error>> {
    let domain = clock("capture-clock-a", "interface-0")?;
    let report = measure_timing(&[
        sample(1, domain.clone(), Some(100)),
        sample(2, domain.clone(), Some(106)),
        sample(3, domain.clone(), None),
        sample(4, domain, Some(120)),
    ])?;
    assert!(report.comparable);
    assert_eq!(
        report
            .intervals
            .first()
            .and_then(|interval| interval.delta_ticks),
        Some(6)
    );
    assert_eq!(
        report.intervals.get(1).map(|interval| interval.status),
        Some(IntervalStatus::MissingTimestamp)
    );
    assert_eq!(
        report.intervals.get(2).map(|interval| interval.status),
        Some(IntervalStatus::MissingTimestamp)
    );
    assert_eq!(report.missing_samples, 1);
    Ok(())
}

#[test]
fn different_scopes_cross_domain_intervals() -> Result<(), Box<dyn Error>> {
    let same = clock("clock-a", "interface-0")?;
    let different_clock = clock("clock-b", "interface-0")?;
    let report = measure_timing(&[
        sample(1, same.clone(), Some(10)),
        sample(2, different_clock, Some(11)),
    ])?;
    assert!(!report.comparable);
    assert_eq!(
        report.intervals.first().map(|interval| interval.status),
        Some(IntervalStatus::ClockMismatch)
    );
    assert_eq!(report.clock_mismatches, 1);

    let different_scope = clock("clock-a", "interface-1")?;
    let report = measure_timing(&[
        sample(1, same, Some(10)),
        sample(2, different_scope, Some(11)),
    ])?;
    assert!(!report.comparable);
    assert_eq!(report.scope_mismatches, 1);
    Ok(())
}

#[test]
fn backward_ticks_reported_wrapping() -> Result<(), Box<dyn Error>> {
    let domain = clock("clock-a", "capture-0")?;
    let report = measure_timing(&[
        sample(1, domain.clone(), Some(90)),
        sample(2, domain, Some(12)),
    ])?;
    assert!(report.comparable);
    assert_eq!(report.backwards_intervals, 1);
    assert_eq!(
        report.intervals.first().map(|interval| interval.status),
        Some(IntervalStatus::Backwards)
    );
    assert_eq!(
        report
            .intervals
            .first()
            .and_then(|interval| interval.delta_ticks),
        None
    );
    Ok(())
}

#[test]
fn resolution_offset_not_silently_normalized() -> Result<(), Box<dyn Error>> {
    let base = clock("clock-a", "capture-0")?;
    let different_resolution = Clock::new("clock-a", "capture-0", 10, 9, 0)?;
    let report = measure_timing(&[
        sample(1, base.clone(), Some(1)),
        sample(2, different_resolution, Some(2)),
    ])?;
    assert!(!report.comparable);
    assert_eq!(report.clock_mismatches, 1);

    let different_offset = Clock::new("clock-a", "capture-0", 10, 6, 1)?;
    let report = measure_timing(&[
        sample(1, base, Some(1)),
        sample(2, different_offset, Some(2)),
    ])?;
    assert!(!report.comparable);
    assert_eq!(report.clock_mismatches, 1);
    Ok(())
}
