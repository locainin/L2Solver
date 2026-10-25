use l2_engine::{Clock, FakeClock, MonoTime};
use std::{error::Error, time::Duration};

#[test]
fn checks_fake_clock_advances() -> Result<(), Box<dyn Error>> {
    let mut clock = FakeClock::at(MonoTime::from_nanos(u64::MAX - 2));
    assert_eq!(clock.now(), MonoTime::from_nanos(u64::MAX - 2));
    assert_eq!(
        clock.advance(Duration::from_nanos(2))?,
        MonoTime::from_nanos(u64::MAX)
    );
    assert!(clock.advance(Duration::from_nanos(1)).is_err());
    assert_eq!(clock.now(), MonoTime::from_nanos(u64::MAX));
    let before = clock.now();
    assert!(clock.advance(Duration::MAX).is_err());
    assert_eq!(clock.now(), before);
    Ok(())
}

#[test]
fn rejects_invalid_monotonic_intervals() -> Result<(), Box<dyn Error>> {
    let start = MonoTime::from_nanos(10);
    assert_eq!(start.to_string(), "10ns");
    assert_eq!(start.checked_add_nanos(5)?, MonoTime::from_nanos(15));
    assert_eq!(
        start.checked_duration_since(MonoTime::from_nanos(4))?,
        Duration::from_nanos(6)
    );
    assert!(
        start
            .checked_duration_since(MonoTime::from_nanos(11))
            .is_err()
    );
    assert!(MonoTime::from_nanos(u64::MAX).checked_add_nanos(1).is_err());

    let mut clock = FakeClock::new();
    assert_eq!(clock.advance_nanos(4)?, MonoTime::from_nanos(4));
    Ok(())
}
