//! Bounded receive events and ordered event envelopes

use l2_capture::{CapturedFrame, InterfaceId};

/// A stable identifier for a scheduled timer
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimerId(u64);

impl TimerId {
    /// Return the numeric timer identifier
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// A monotonically assigned event sequence number
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventSequence(u64);

impl EventSequence {
    /// Return the numeric event sequence
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// An event delivered by the receive-only observation engine
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// A frame retained with its exact capture metadata
    FrameReceived(CapturedFrame),
    /// A source-reported interval of missing packets
    CaptureGap {
        /// Number of packets reported missing
        dropped: u64,
    },
    /// The selected interface became unavailable
    InterfaceDown(InterfaceId),
    /// The selected interface became available again
    InterfaceUp(InterfaceId),
    /// A scheduled timer reached its deadline
    TimerExpired(TimerId),
    /// Cancellation was requested by the caller
    Cancelled,
    /// The input source supplied its terminal shutdown marker
    SourceClosed,
}

/// One event with deterministic sequence and engine-time provenance
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnvelope {
    sequence: EventSequence,
    at: crate::MonoTime,
    event: Event,
}

impl EventEnvelope {
    pub(crate) const fn new(sequence: EventSequence, at: crate::MonoTime, event: Event) -> Self {
        Self {
            sequence,
            at,
            event,
        }
    }

    /// Return the monotonically increasing delivery sequence
    #[must_use]
    pub const fn sequence(&self) -> EventSequence {
        self.sequence
    }

    /// Return the monotonic engine instant assigned at delivery
    #[must_use]
    pub const fn at(&self) -> crate::MonoTime {
        self.at
    }

    /// Borrow the delivered event
    #[must_use]
    pub const fn event(&self) -> &Event {
        &self.event
    }

    /// Consume the envelope and return its event
    #[must_use]
    pub fn into_event(self) -> Event {
        self.event
    }
}
