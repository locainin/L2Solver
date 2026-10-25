//! Deterministic receive-only event scheduling and passive observation helpers
//!
//! The engine owns no sockets, transmit capability, async runtime, or protocol
//! parser. It accepts canonical capture frames from [`l2_io::LinkIo`] and
//! delivers bounded, ordered events to passive consumers

#![forbid(unsafe_code)]

mod clock;
mod config;
mod engine;
mod error;
mod event;
mod queue;
mod stp;
mod timer;

pub use clock::{Clock, ClockError, FakeClock, MonoTime};
pub use config::{
    ABSOLUTE_MAX_DRAIN_EVENTS, ABSOLUTE_MAX_QUEUED_EVENTS, ABSOLUTE_MAX_TIMERS, ConfigError,
    EngineConfig,
};
pub use engine::EventEngine;
pub use error::{CleanupReport, EngineError, IngestError, IngestStatus};
pub use event::{Event, EventEnvelope, EventSequence, TimerId};
pub(crate) use queue::EventQueue;
pub use stp::{ABSOLUTE_MAX_STP_SAMPLES, StpObserver, StpObserverError, StpUpdate};
pub(crate) use timer::TimerQueue;
