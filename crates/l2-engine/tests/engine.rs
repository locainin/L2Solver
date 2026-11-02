use l2_capture::{CapturedFrame, InterfaceId};
use l2_engine::{Clock, EngineConfig, EngineError, Event, EventEngine, FakeClock, MonoTime};
use l2_io::FakeLink;
use std::{error::Error, fmt::Display, time::Duration};

const fn interface(section: u32, index: u32) -> InterfaceId {
    InterfaceId { section, index }
}

fn frame(bytes: &[u8], original_len: usize) -> Result<CapturedFrame, Box<dyn Error>> {
    let metadata =
        l2_capture::CaptureMetadata::unknown(interface(0, 0), u32::try_from(original_len)?);
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}

#[test]
fn orders_ready_events_by_time() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    let later = MonoTime::from_nanos(10);
    engine.enqueue_at(later, Event::InterfaceDown(interface(0, 2)))?;
    engine.enqueue(Event::InterfaceUp(interface(0, 1)))?;

    let first = engine.next_ready()?.ok_or("missing immediate event")?;
    assert_eq!(first.event(), &Event::InterfaceUp(interface(0, 1)));
    assert_eq!(first.sequence().get(), 1);
    assert_eq!(first.at(), MonoTime::ZERO);
    assert!(engine.next_ready()?.is_none());

    engine.clock_mut().advance(Duration::from_nanos(10))?;
    let second = engine.next_ready()?.ok_or("missing delayed event")?;
    assert_eq!(second.event(), &Event::InterfaceDown(interface(0, 2)));
    assert_eq!(second.sequence().get(), 2);
    assert_eq!(second.at(), later);
    Ok(())
}

#[test]
fn orders_and_cancels_timers() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    let first = engine.set_timer(Duration::from_secs(2))?;
    let second = engine.set_timer(Duration::from_secs(2))?;
    assert!(engine.cancel_timer(first));
    assert!(!engine.cancel_timer(first));

    engine.clock_mut().advance(Duration::from_secs(2))?;
    let event = engine.next_ready()?.ok_or("missing timer event")?;
    assert_eq!(event.event(), &Event::TimerExpired(second));
    assert_eq!(event.sequence().get(), 1);
    assert_eq!(engine.pending_timers(), 0);
    assert!(engine.next_ready()?.is_none());
    Ok(())
}

#[test]
fn rejects_queue_without_dropping_events() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(1, 4, 4)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;
    engine.enqueue(Event::InterfaceUp(interface(0, 0)))?;
    assert_eq!(
        engine.enqueue(Event::InterfaceDown(interface(0, 0))),
        Err(EngineError::EventQueueFull { limit: 1 })
    );
    assert_eq!(engine.pending_events(), 1);
    assert!(engine.next_ready()?.is_some());
    assert_eq!(engine.pending_events(), 0);
    Ok(())
}

#[test]
fn prioritizes_ready_over_due_timer() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(1, 2, 4)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;
    engine.enqueue(Event::InterfaceUp(interface(0, 0)))?;
    let timer = engine.set_timer(Duration::from_nanos(1))?;
    engine.clock_mut().advance(Duration::from_nanos(1))?;

    assert_eq!(
        engine
            .next_ready()?
            .map(l2_engine::EventEnvelope::into_event),
        Some(Event::InterfaceUp(interface(0, 0)))
    );
    assert_eq!(
        engine
            .next_ready()?
            .map(l2_engine::EventEnvelope::into_event),
        Some(Event::TimerExpired(timer))
    );
    Ok(())
}

#[test]
fn rejects_ingest_before_source_consume() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(1, 1, 4)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;
    let mut source = FakeLink::with_capacity(2)?;
    source.push_rx(frame(&[1], 1)?)?;
    source.push_rx(frame(&[2], 2)?)?;

    assert!(engine.ingest_next(&mut source)?.is_queued());
    assert!(matches!(
        engine.ingest_next(&mut source),
        Err(l2_engine::IngestError::Engine(
            EngineError::EventQueueFull { limit: 1 }
        ))
    ));
    assert!(engine.next_ready()?.is_some());
    assert!(engine.ingest_next(&mut source)?.is_queued());
    let second = engine.next_ready()?.ok_or("second source event was lost")?;
    let Event::FrameReceived(second) = second.into_event() else {
        return Err("unexpected event type".into());
    };
    assert_eq!(second.bytes(), [2]);
    Ok(())
}

#[test]
fn event_queue_invalid_gaps() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    assert_eq!(
        engine.enqueue(Event::CaptureGap { dropped: 0 }),
        Err(EngineError::InvalidCaptureGap)
    );
    assert_eq!(engine.pending_events(), 0);
    Ok(())
}

#[test]
fn rejects_limits_above_ceilings() {
    assert!(EngineConfig::new(0, 1, 1).is_err());
    assert!(EngineConfig::new(l2_engine::ABSOLUTE_MAX_QUEUED_EVENTS + 1, 1, 1).is_err());
    assert!(EngineConfig::new(1, l2_engine::ABSOLUTE_MAX_TIMERS + 1, 1).is_err());
    assert!(EngineConfig::new(1, 1, l2_engine::ABSOLUTE_MAX_DRAIN_EVENTS + 1).is_err());
}

#[test]
fn accepts_runtime_limit_boundaries() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(
        l2_engine::ABSOLUTE_MAX_QUEUED_EVENTS,
        l2_engine::ABSOLUTE_MAX_TIMERS,
        l2_engine::ABSOLUTE_MAX_DRAIN_EVENTS,
    )?;
    assert_eq!(
        config.max_queued_events(),
        l2_engine::ABSOLUTE_MAX_QUEUED_EVENTS
    );
    assert_eq!(config.max_timers(), l2_engine::ABSOLUTE_MAX_TIMERS);
    assert_eq!(
        config.max_drain_events(),
        l2_engine::ABSOLUTE_MAX_DRAIN_EVENTS
    );
    assert!(EngineConfig::new(1, 0, 1).is_err());
    assert!(EngineConfig::new(1, 1, 0).is_err());
    Ok(())
}

#[test]
fn time_out_engine_clock() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(2)?;
    link.push_rx(frame(&[7, 7], 2)?)?;
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    assert!(engine.ingest_next(&mut link)?.is_queued());
    let envelope = engine.next_ready()?.ok_or("missing captured frame")?;
    let Event::FrameReceived(received) = envelope.event() else {
        return Err("unexpected event".into());
    };
    assert_eq!(received.bytes(), [7, 7]);
    assert_eq!(received.captured_len(), 2);
    assert_eq!(envelope.at(), MonoTime::ZERO);
    assert_eq!(engine.clock().now(), MonoTime::ZERO);
    Ok(())
}

#[test]
fn maps_control_events_in_order() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(8)?;
    let id = interface(1, 4);
    link.push_gap(5)?;
    link.push_interface_down(id)?;
    link.push_interface_up(id)?;
    link.push_shutdown()?;
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;

    for _ in 0..4 {
        assert!(engine.ingest_next(&mut link)?.is_queued());
    }
    assert!(engine.ingest_next(&mut link)?.is_end_of_stream());
    let delivered = engine.drain_ready()?;
    assert_eq!(delivered.len(), 4);
    let mut events = delivered.iter();
    assert_eq!(
        events.next().map(l2_engine::EventEnvelope::event),
        Some(&Event::CaptureGap { dropped: 5 })
    );
    assert_eq!(
        events.next().map(l2_engine::EventEnvelope::event),
        Some(&Event::InterfaceDown(id))
    );
    assert_eq!(
        events.next().map(l2_engine::EventEnvelope::event),
        Some(&Event::InterfaceUp(id))
    );
    assert_eq!(
        events.next().map(l2_engine::EventEnvelope::event),
        Some(&Event::SourceClosed)
    );
    assert!(delivered.windows(2).all(|pair| {
        let Some(first) = pair.first() else {
            return false;
        };
        let Some(second) = pair.get(1) else {
            return false;
        };
        first.sequence() < second.sequence()
    }));
    Ok(())
}

#[test]
fn cancellation_cleanup_safe_repeat() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    engine.enqueue(Event::InterfaceUp(interface(0, 0)))?;
    engine.set_timer(Duration::from_secs(30))?;
    assert!(engine.request_cancel()?);
    assert!(!engine.request_cancel()?);
    let first = engine.cleanup();
    let second = engine.cleanup();
    assert_eq!(first.discarded_events, 1);
    assert!(first.cancelled_timers >= 1);
    assert_eq!(engine.pending_events(), 0);
    assert_eq!(engine.pending_timers(), 0);
    assert_eq!(second.discarded_events, 0);
    assert_eq!(second.cancelled_timers, 0);
    assert_eq!(
        engine.enqueue(Event::InterfaceUp(interface(0, 0))),
        Err(EngineError::CleanedUp)
    );
    Ok(())
}

#[test]
fn keeps_timer_ids_stable() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    let first = engine.set_timer(Duration::ZERO)?;
    assert!(engine.cancel_timer(first));
    let second = engine.set_timer(Duration::ZERO)?;
    assert_ne!(first, second);
    assert_eq!(first.get(), 1);
    assert_eq!(second.get(), 2);
    Ok(())
}

#[test]
fn orders_same_deadline_events() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    let deadline = MonoTime::from_nanos(4);
    engine.enqueue_at(deadline, Event::InterfaceUp(interface(0, 2)))?;
    let timer = engine.set_timer(Duration::from_nanos(4))?;
    engine.clock_mut().advance_nanos(4)?;

    assert_eq!(
        engine
            .next_ready()?
            .map(l2_engine::EventEnvelope::into_event),
        Some(Event::InterfaceUp(interface(0, 2)))
    );
    assert_eq!(
        engine
            .next_ready()?
            .map(l2_engine::EventEnvelope::into_event),
        Some(Event::TimerExpired(timer))
    );
    Ok(())
}

fn assert_displayed<T: Display>(value: T) {
    assert_ne!(value.to_string(), "");
}

#[test]
fn preserves_engine_error_contracts() {
    assert_displayed(l2_engine::ClockError::DurationTooLarge { nanos: 7 });
    assert_displayed(l2_engine::ConfigError::QueuedEvents { value: 0, max: 1 });
    assert_displayed(EngineError::InvalidCaptureGap);
    assert_displayed(l2_engine::IngestError::<l2_io::QueueError>::Engine(
        EngineError::Cancelled,
    ));
    assert_displayed(l2_engine::IngestError::<l2_io::QueueError>::Source(
        l2_io::QueueError::Closed,
    ));

    let queued = l2_engine::IngestStatus::Queued;
    let end = l2_engine::IngestStatus::EndOfStream;
    assert!(queued.is_queued());
    assert!(!queued.is_end_of_stream());
    assert!(end.is_end_of_stream());
    assert!(!end.is_queued());
}

#[test]
fn nested_clock_errors_available_sources() {
    let clock = l2_engine::ClockError::DurationTooLarge { nanos: 7 };
    let engine_error = EngineError::Clock(clock);
    assert!(std::error::Error::source(&engine_error).is_some());
}

#[test]
fn ingest_source_errors_available_sources() {
    let ingest = l2_engine::IngestError::Source(l2_io::QueueError::Closed);
    assert!(std::error::Error::source(&ingest).is_some());
}

#[test]
fn preserves_work_on_invalid_timer() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(4, 1, 4)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;

    assert_eq!(
        engine.enqueue_at(MonoTime::from_nanos(u64::MAX), Event::Cancelled),
        Ok(())
    );
    engine.clock_mut().advance_nanos(1)?;
    assert_eq!(
        engine.enqueue_at(MonoTime::ZERO, Event::Cancelled),
        Err(EngineError::DeadlineInPast {
            deadline: MonoTime::ZERO,
            now: MonoTime::from_nanos(1),
        })
    );
    let timer = engine.set_timer(Duration::ZERO)?;
    assert_eq!(engine.pending_timers(), 1);
    assert_eq!(
        engine.set_timer(Duration::ZERO),
        Err(EngineError::TimerLimitReached { limit: 1 })
    );
    assert!(engine.cancel_timer(timer));
    assert_eq!(engine.pending_timers(), 0);
    Ok(())
}

#[test]
fn cancellation_preempts_pending_events() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(1, 1, 4)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;
    engine.enqueue(Event::InterfaceUp(interface(0, 0)))?;

    assert!(engine.request_cancel()?);
    assert!(!engine.request_cancel()?);
    assert_eq!(engine.pending_events(), 1);
    let cancelled = engine.next_ready()?.ok_or("missing cancellation event")?;
    assert_eq!(cancelled.event(), &Event::Cancelled);
    assert!(engine.next_ready()?.is_none());

    let cleanup = engine.cleanup();
    assert_eq!(cleanup.discarded_events, 1);
    Ok(())
}

#[test]
fn drain_ready_obeys_operation_bound() -> Result<(), Box<dyn Error>> {
    let config = EngineConfig::new(4, 1, 2)?;
    let mut engine = EventEngine::new(FakeClock::default(), config)?;
    engine.enqueue(Event::InterfaceUp(interface(0, 0)))?;
    engine.enqueue(Event::InterfaceDown(interface(0, 0)))?;
    engine.enqueue(Event::InterfaceUp(interface(0, 1)))?;

    assert_eq!(engine.drain_ready()?.len(), 2);
    assert_eq!(engine.pending_events(), 1);
    assert_eq!(engine.drain_ready()?.len(), 1);
    Ok(())
}

#[test]
fn timer_deadline_overflow_not_timer() -> Result<(), Box<dyn Error>> {
    let mut engine = EventEngine::new(
        FakeClock::at(MonoTime::from_nanos(u64::MAX)),
        EngineConfig::default(),
    )?;
    assert!(matches!(
        engine.set_timer(Duration::from_nanos(1)),
        Err(EngineError::Clock(_))
    ));
    assert_eq!(engine.pending_timers(), 0);
    Ok(())
}
