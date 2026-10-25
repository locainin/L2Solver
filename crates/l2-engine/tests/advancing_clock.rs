use std::{cell::Cell, error::Error, time::Duration};

use l2_engine::{Clock, EngineConfig, EngineError, Event, EventEngine, MonoTime};

// Each read advances time so convenience methods cannot rely on a frozen clock
struct AdvancingClock(Cell<u64>);

impl Clock for AdvancingClock {
    fn now(&self) -> MonoTime {
        let now = self.0.get();
        self.0.set(now + 1);
        MonoTime::from_nanos(now)
    }
}

#[test]
fn immediate_event_clock_snapshot() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(AdvancingClock(Cell::new(0)), EngineConfig::default())?;
    engine.enqueue(Event::SourceClosed)?;
    let event = engine.next_ready()?.ok_or("missing immediate event")?;
    assert_eq!(event.at(), MonoTime::ZERO);
    assert_eq!(event.event(), &Event::SourceClosed);
    Ok(())
}

#[test]
fn zero_delay_clock_snapshot() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(AdvancingClock(Cell::new(0)), EngineConfig::default())?;
    let timer = engine.set_timer(Duration::ZERO)?;
    let event = engine.next_ready()?.ok_or("missing immediate timer")?;
    assert_eq!(event.at(), MonoTime::ZERO);
    assert_eq!(event.event(), &Event::TimerExpired(timer));
    Ok(())
}

#[test]
fn explicit_past_deadlines_remain_rejected() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(AdvancingClock(Cell::new(1)), EngineConfig::default())?;
    assert!(matches!(
        engine.enqueue_at(MonoTime::ZERO, Event::SourceClosed),
        Err(EngineError::DeadlineInPast { .. })
    ));
    assert!(matches!(
        engine.set_timer_at(MonoTime::ZERO),
        Err(EngineError::DeadlineInPast { .. })
    ));
    assert_eq!(engine.pending_events(), 0);
    assert_eq!(engine.pending_timers(), 0);
    Ok(())
}
