//! Engine, ingestion, and cleanup result types

use crate::{ClockError, MonoTime};
use core::fmt;

/// Failures while scheduling or delivering receive events
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineError {
    EventQueueFull { limit: usize },
    TimerLimitReached { limit: usize },
    DeadlineInPast { deadline: MonoTime, now: MonoTime },
    InvalidCaptureGap,
    Clock(ClockError),
    EventSequenceExhausted,
    Cancelled,
    CleanedUp,
    QueueInvariant,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventQueueFull { limit } => {
                write!(formatter, "event queue is full at configured limit {limit}")
            }
            Self::TimerLimitReached { limit } => {
                write!(formatter, "timer set is full at configured limit {limit}")
            }
            Self::DeadlineInPast { deadline, now } => {
                write!(
                    formatter,
                    "deadline {deadline} precedes current engine time {now}"
                )
            }
            Self::InvalidCaptureGap => {
                formatter.write_str("capture gap must report at least one dropped packet")
            }
            Self::Clock(error) => error.fmt(formatter),
            Self::EventSequenceExhausted => {
                formatter.write_str("event sequence counter is exhausted")
            }
            Self::Cancelled => formatter.write_str("event engine cancellation is pending"),
            Self::CleanedUp => formatter.write_str("event engine has been cleaned up"),
            Self::QueueInvariant => formatter.write_str("event queue invariant was violated"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ClockError> for EngineError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

/// Result of asking an input source for one event
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestStatus {
    Queued,
    EndOfStream,
}

impl IngestStatus {
    #[must_use]
    pub const fn is_queued(self) -> bool {
        matches!(self, Self::Queued)
    }

    #[must_use]
    pub const fn is_end_of_stream(self) -> bool {
        matches!(self, Self::EndOfStream)
    }
}

/// A source error or deterministic scheduling error
#[derive(Debug)]
pub enum IngestError<E> {
    Source(E),
    Engine(EngineError),
}

impl<E: fmt::Display> fmt::Display for IngestError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "receive source error: {error}"),
            Self::Engine(error) => write!(formatter, "event engine error: {error}"),
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> std::error::Error for IngestError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Engine(error) => Some(error),
        }
    }
}

/// Counts returned by idempotent engine cleanup
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    pub discarded_events: usize,
    pub cancelled_timers: usize,
}
