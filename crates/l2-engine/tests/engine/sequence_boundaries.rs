use super::*;

// Snapshot internal queues as well as counters so failure cannot discard pending work
fn snapshot(engine: &EventEngine<FakeClock>) -> String {
    format!(
        "{:?}",
        (
            &engine.queue,
            &engine.timers,
            engine.next_sequence,
            engine.next_timer,
            engine.last_delivered_at,
            engine.cancel_requested,
            engine.cancel_at,
            engine.cleaned_up,
        )
    )
}

#[test]
fn event_sequence_never_pending_work() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = EventEngine::with_default_clock(EngineConfig::default())?;
    engine.next_sequence = u64::MAX - 2;
    for _ in 0..3 {
        engine.enqueue(Event::SourceClosed)?;
    }
    for expected in [u64::MAX - 1, u64::MAX] {
        assert_eq!(
            engine
                .next_ready()?
                .ok_or("missing event")?
                .sequence()
                .get(),
            expected
        );
    }
    let before = snapshot(&engine);
    for _ in 0..2 {
        assert!(matches!(
            engine.next_ready(),
            Err(EngineError::EventSequenceExhausted)
        ));
        assert_eq!(snapshot(&engine), before);
    }
    Ok(())
}

#[test]
fn timer_identifier_never_existing_timers() -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = EventEngine::with_default_clock(EngineConfig::default())?;
    engine.next_timer = u64::MAX - 2;
    for expected in [u64::MAX - 1, u64::MAX] {
        assert_eq!(engine.set_timer(Duration::ZERO)?.get(), expected);
    }
    let before = snapshot(&engine);
    for _ in 0..2 {
        assert!(matches!(
            engine.set_timer(Duration::ZERO),
            Err(EngineError::EventSequenceExhausted)
        ));
        assert_eq!(snapshot(&engine), before);
    }
    Ok(())
}

#[test]
fn failed_timer_delivery_terminal_work() -> Result<(), Box<dyn std::error::Error>> {
    for cancel in [false, true] {
        let mut engine = EventEngine::with_default_clock(EngineConfig::default())?;
        engine.set_timer(Duration::ZERO)?;
        if cancel {
            engine.request_cancel()?;
        }
        engine.next_sequence = u64::MAX;
        let before = snapshot(&engine);
        assert!(matches!(
            engine.next_ready(),
            Err(EngineError::EventSequenceExhausted)
        ));
        assert_eq!(snapshot(&engine), before);
    }
    Ok(())
}
