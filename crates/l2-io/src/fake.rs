//! Bounded input queue for tests and deterministic simulations

use crate::{CaptureGap, LinkEvent, LinkIo};
use l2_capture::{CapturedFrame, InterfaceId};
use std::{collections::VecDeque, fmt};

/// Maximum number of pending receive events in the in-memory source
pub const MAX_QUEUE_EVENTS: usize = 256;

/// In-memory receive source with explicit gaps and interface transitions
#[derive(Debug)]
pub struct FakeLink {
    events: VecDeque<LinkEvent>,
    capacity: usize,
    closed: bool,
}

impl Default for FakeLink {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            capacity: MAX_QUEUE_EVENTS,
            closed: false,
        }
    }
}

/// A rejected source operation never changes queued events or state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    /// The queue has reached its configured event limit
    Full,
    /// A zero packet-loss count cannot represent a gap
    InvalidGap,
    /// The source already contains a shutdown marker
    Closed,
    /// A control event requires the explicit event-aware receive method
    ControlEventRequiresEventApi,
    /// A queue with no storage cannot provide a useful source
    InvalidCapacity,
}

impl fmt::Display for QueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full => "receive event queue is full",
            Self::InvalidGap => "capture gap must report at least one dropped packet",
            Self::Closed => "receive source is shut down",
            Self::ControlEventRequiresEventApi => {
                "receive control event requires LinkIo::next_event"
            }
            Self::InvalidCapacity => "receive event queue capacity must be nonzero",
        })
    }
}

impl std::error::Error for QueueError {}

impl FakeLink {
    /// Create an in-memory source with a bounded event queue
    ///
    /// # Errors
    /// Returns [`QueueError::InvalidCapacity`] for an invalid queue size
    pub fn with_capacity(capacity: usize) -> Result<Self, QueueError> {
        if capacity == 0 || capacity > MAX_QUEUE_EVENTS {
            return Err(QueueError::InvalidCapacity);
        }
        Ok(Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            closed: false,
        })
    }

    /// Return the number of pending receive events
    #[must_use]
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    /// Return whether a shutdown marker has been queued
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Queue one already-validated frame without rechecking its metadata
    ///
    /// [`CapturedFrame::new`] owns frame validation. Keeping this method as a
    /// pure queue operation avoids a second, divergent metadata policy
    ///
    /// # Errors
    /// Returns [`QueueError::Closed`] after shutdown or [`QueueError::Full`]
    /// when the bounded queue has no room
    pub fn push_rx(&mut self, frame: CapturedFrame) -> Result<(), QueueError> {
        self.push_event(LinkEvent::Frame(frame))
    }

    /// Queue a packet-loss notification
    ///
    /// # Errors
    /// Returns [`QueueError::InvalidGap`] for zero, or a queue-state error
    pub fn push_gap(&mut self, dropped: u64) -> Result<(), QueueError> {
        if dropped == 0 {
            return Err(QueueError::InvalidGap);
        }
        self.push_event(LinkEvent::CaptureGap(CaptureGap { dropped }))
    }

    /// Queue an interface-down transition
    ///
    /// # Errors
    /// Returns a queue-state error when the event cannot be retained
    pub fn push_interface_down(&mut self, interface: InterfaceId) -> Result<(), QueueError> {
        self.push_event(LinkEvent::InterfaceDown(interface))
    }

    /// Queue an interface-up transition
    ///
    /// # Errors
    /// Returns a queue-state error when the event cannot be retained
    pub fn push_interface_up(&mut self, interface: InterfaceId) -> Result<(), QueueError> {
        self.push_event(LinkEvent::InterfaceUp(interface))
    }

    /// Queue one terminal shutdown marker
    ///
    /// The marker consumes a queue slot. If the queue is full, no shutdown
    /// state is recorded, so a caller can drain it and retry safely
    ///
    /// # Errors
    /// Returns a queue-state error when the marker cannot be retained
    pub fn push_shutdown(&mut self) -> Result<(), QueueError> {
        self.push_event(LinkEvent::Shutdown)?;
        self.closed = true;
        Ok(())
    }

    fn push_event(&mut self, event: LinkEvent) -> Result<(), QueueError> {
        // Check every failure before touching the queue or closed flag
        if self.closed {
            return Err(QueueError::Closed);
        }
        if self.events.len() >= self.capacity {
            return Err(QueueError::Full);
        }
        self.events.push_back(event);
        Ok(())
    }

    fn next_queued_event(&mut self) -> Option<LinkEvent> {
        self.events.pop_front()
    }
}

impl LinkIo for FakeLink {
    type Error = QueueError;

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        // Peek before removing so a frame-only consumer cannot lose evidence
        let Some(next) = self.events.front() else {
            return Ok(None);
        };
        match next {
            LinkEvent::Frame(_) => match self.next_queued_event() {
                Some(LinkEvent::Frame(frame)) => Ok(Some(frame)),
                _ => Err(QueueError::ControlEventRequiresEventApi),
            },
            LinkEvent::Shutdown => {
                self.next_queued_event();
                Ok(None)
            }
            LinkEvent::CaptureGap(_) | LinkEvent::InterfaceDown(_) | LinkEvent::InterfaceUp(_) => {
                Err(QueueError::ControlEventRequiresEventApi)
            }
        }
    }

    fn next_event(&mut self) -> Result<Option<LinkEvent>, Self::Error> {
        Ok(self.next_queued_event())
    }
}
