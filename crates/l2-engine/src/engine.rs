//! Deterministic, bounded receive-event scheduling

use crate::{
    CleanupReport, Clock, ConfigError, EngineConfig, EngineError, Event, EventEnvelope, EventQueue,
    EventSequence, FakeClock, IngestError, IngestStatus, MonoTime, TimerId, TimerQueue,
};
use l2_io::{LinkEvent, LinkIo};
use std::time::Duration;

#[cfg(test)]
#[path = "../tests/engine/sequence_boundaries.rs"]
mod sequence_boundaries;

/// Deterministic receive-only event engine with bounded memory and timers
pub struct EventEngine<C: Clock> {
    clock: C,
    config: EngineConfig,
    queue: EventQueue,
    timers: TimerQueue,
    next_sequence: u64,
    next_timer: u64,
    last_delivered_at: Option<MonoTime>,
    cancel_requested: bool,
    cancel_at: Option<MonoTime>,
    cleaned_up: bool,
}

impl<C: Clock> EventEngine<C> {
    /// Construct an empty engine with validated runtime limits
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a caller supplied invalid limits
    pub fn new(clock: C, config: EngineConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            clock,
            config,
            queue: EventQueue::new(),
            timers: TimerQueue::new(),
            next_sequence: 0,
            next_timer: 0,
            last_delivered_at: None,
            cancel_requested: false,
            cancel_at: None,
            cleaned_up: false,
        })
    }

    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    pub const fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    #[must_use]
    pub const fn config(&self) -> EngineConfig {
        self.config
    }

    #[must_use]
    pub const fn pending_events(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub const fn pending_timers(&self) -> usize {
        self.timers.len()
    }

    /// Queue an event at the current engine instant
    ///
    /// # Errors
    ///
    /// Returns a bounded queue, cancellation, time, or validation error
    pub fn enqueue(&mut self, event: Event) -> Result<(), EngineError> {
        self.ensure_running()?;
        let now = self.clock.now();
        self.enqueue_validated_time(now, event)
    }

    /// Queue an event for a current or future engine instant
    ///
    /// Sequence numbers are assigned on delivery so future work cannot move
    /// ahead of a later event that is ready now
    ///
    /// # Errors
    ///
    /// Returns without mutation when validation or capacity checks fail
    pub fn enqueue_at(&mut self, at: MonoTime, event: Event) -> Result<(), EngineError> {
        self.ensure_running()?;
        let now = self.clock.now();
        if at < now {
            return Err(EngineError::DeadlineInPast { deadline: at, now });
        }
        self.enqueue_validated_time(at, event)
    }

    fn enqueue_validated_time(&mut self, at: MonoTime, event: Event) -> Result<(), EngineError> {
        if self.cancel_requested {
            return Err(EngineError::Cancelled);
        }
        Self::validate_event(&event)?;
        self.queue_pending(at, event)
    }

    /// Schedule one timer after a checked duration
    ///
    /// # Errors
    ///
    /// Returns without mutation when clock or capacity checks fail
    pub fn set_timer(&mut self, delay: Duration) -> Result<TimerId, EngineError> {
        self.ensure_running()?;
        if self.cancel_requested {
            return Err(EngineError::Cancelled);
        }
        // The relative deadline and its validation share one clock snapshot
        let now = self.clock.now();
        let deadline = now.checked_add(delay)?;
        self.insert_timer(deadline)
    }

    /// Schedule one timer at a current or future instant
    ///
    /// # Errors
    ///
    /// Returns without mutation when the deadline or capacity is invalid
    pub fn set_timer_at(&mut self, deadline: MonoTime) -> Result<TimerId, EngineError> {
        self.ensure_running()?;
        let now = self.clock.now();
        if deadline < now {
            return Err(EngineError::DeadlineInPast { deadline, now });
        }
        if self.cancel_requested {
            return Err(EngineError::Cancelled);
        }
        self.insert_timer(deadline)
    }

    fn insert_timer(&mut self, deadline: MonoTime) -> Result<TimerId, EngineError> {
        if self.timers.len() >= self.config.timer_capacity {
            return Err(EngineError::TimerLimitReached {
                limit: self.config.timer_capacity,
            });
        }
        let id_value = self
            .next_timer
            .checked_add(1)
            .ok_or(EngineError::EventSequenceExhausted)?;
        let id = TimerId::new(id_value);
        self.timers.insert(deadline, id);
        self.next_timer = id_value;
        Ok(id)
    }

    #[must_use]
    pub fn cancel_timer(&mut self, timer: TimerId) -> bool {
        self.timers.cancel(timer)
    }

    /// Request cancellation through a path that cannot fill with work events
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CleanedUp`] after cleanup
    pub fn request_cancel(&mut self) -> Result<bool, EngineError> {
        self.ensure_running()?;
        if self.cancel_requested {
            return Ok(false);
        }
        self.cancel_requested = true;
        self.cancel_at = Some(self.clock.now());
        Ok(true)
    }

    /// Discard pending work and make later operations fail closed
    #[must_use]
    pub fn cleanup(&mut self) -> CleanupReport {
        if self.cleaned_up {
            return CleanupReport::default();
        }
        let report = CleanupReport {
            discarded_events: self.queue.len(),
            cancelled_timers: self.timers.len(),
        };
        self.queue.clear();
        self.timers.clear();
        self.cancel_at = None;
        self.cleaned_up = true;
        report
    }

    /// Return the next event whose engine instant has arrived
    ///
    /// # Errors
    ///
    /// Returns a queue or sequence error if an internal invariant is broken
    pub fn next_ready(&mut self) -> Result<Option<EventEnvelope>, EngineError> {
        if let Some(at) = self.cancel_at {
            return self.deliver_cancellation(at).map(Some);
        }
        // Cleanup still accounts for queued work, but cancellation prevents execution
        if self.cancel_requested {
            return Ok(None);
        }

        let now = self.clock.now();
        let event_at = self.queue.first_time();
        let timer_at = self.timers.first_time();
        let due_timer = timer_at.filter(|deadline| {
            *deadline <= now && event_at.is_none_or(|event_time| *deadline < event_time)
        });
        if let Some(deadline) = due_timer {
            return self.deliver_timer(deadline).map(Some);
        }
        let Some(at) = event_at else {
            return Ok(None);
        };
        if at > now {
            return Ok(None);
        }
        let sequence = self.delivery_sequence(at)?;
        let Some(event) = self.queue.pop_at(at) else {
            return Err(EngineError::QueueInvariant);
        };
        Ok(Some(self.envelope(at, event, sequence)))
    }

    /// Drain ready events up to the configured operation bound
    ///
    /// # Errors
    ///
    /// Returns a queue or sequence error from [`Self::next_ready`]
    pub fn drain_ready(&mut self) -> Result<Vec<EventEnvelope>, EngineError> {
        let mut ready = Vec::new();
        for _ in 0..self.config.drain_batch {
            let Some(event) = self.next_ready()? else {
                break;
            };
            ready.push(event);
        }
        Ok(ready)
    }

    /// Ingest one source item and preserve receive-side control events
    ///
    /// # Errors
    ///
    /// Returns the source error or a deterministic scheduling error
    pub fn ingest_next<L>(&mut self, source: &mut L) -> Result<IngestStatus, IngestError<L::Error>>
    where
        L: LinkIo,
    {
        if let Err(error) = self.ensure_running() {
            return Err(IngestError::Engine(error));
        }
        if self.cancel_requested {
            return Err(IngestError::Engine(EngineError::Cancelled));
        }
        if self.queue.len() >= self.config.queue_capacity {
            return Err(IngestError::Engine(EngineError::EventQueueFull {
                limit: self.config.queue_capacity,
            }));
        }
        let Some(input) = source.next_event().map_err(IngestError::Source)? else {
            return Ok(IngestStatus::EndOfStream);
        };
        let event = match input {
            LinkEvent::Frame(frame) => Event::FrameReceived(frame),
            LinkEvent::CaptureGap(gap) => Event::CaptureGap {
                dropped: gap.dropped,
            },
            LinkEvent::InterfaceDown(interface) => Event::InterfaceDown(interface),
            LinkEvent::InterfaceUp(interface) => Event::InterfaceUp(interface),
            LinkEvent::Shutdown => Event::SourceClosed,
        };
        self.enqueue(event).map_err(IngestError::Engine)?;
        Ok(IngestStatus::Queued)
    }

    const fn ensure_running(&self) -> Result<(), EngineError> {
        if self.cleaned_up {
            return Err(EngineError::CleanedUp);
        }
        Ok(())
    }

    const fn validate_event(event: &Event) -> Result<(), EngineError> {
        if let Event::CaptureGap { dropped } = event
            && *dropped == 0
        {
            return Err(EngineError::InvalidCaptureGap);
        }
        Ok(())
    }

    fn delivery_sequence(&self, at: MonoTime) -> Result<u64, EngineError> {
        if let Some(previous) = self.last_delivered_at
            && at < previous
        {
            return Err(EngineError::QueueInvariant);
        }
        self.next_sequence
            .checked_add(1)
            .ok_or(EngineError::EventSequenceExhausted)
    }

    fn queue_pending(&mut self, at: MonoTime, event: Event) -> Result<(), EngineError> {
        if self.queue.len() >= self.config.queue_capacity {
            return Err(EngineError::EventQueueFull {
                limit: self.config.queue_capacity,
            });
        }
        self.queue.push(at, event);
        Ok(())
    }

    fn deliver_cancellation(&mut self, at: MonoTime) -> Result<EventEnvelope, EngineError> {
        let sequence = self.delivery_sequence(at)?;
        let envelope = self.envelope(at, Event::Cancelled, sequence);
        self.cancel_at = None;
        Ok(envelope)
    }

    fn deliver_timer(&mut self, deadline: MonoTime) -> Result<EventEnvelope, EngineError> {
        let sequence = self.delivery_sequence(deadline)?;
        let Some(timer) = self.timers.pop_at(deadline) else {
            return Err(EngineError::QueueInvariant);
        };
        Ok(self.envelope(deadline, Event::TimerExpired(timer), sequence))
    }

    const fn envelope(&mut self, at: MonoTime, event: Event, sequence: u64) -> EventEnvelope {
        self.next_sequence = sequence;
        self.last_delivered_at = Some(at);
        EventEnvelope::new(EventSequence::new(sequence), at, event)
    }
}

impl EventEngine<FakeClock> {
    /// Construct an engine with the default deterministic fake clock
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when custom limits are invalid
    pub fn with_default_clock(config: EngineConfig) -> Result<Self, ConfigError> {
        Self::new(FakeClock::default(), config)
    }
}
