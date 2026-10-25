//! Checked runtime limits for the event engine

use core::fmt;

/// Absolute ceiling for pending event capacity, independent of runtime config
pub const ABSOLUTE_MAX_QUEUED_EVENTS: usize = 4_096;

/// Absolute ceiling for scheduled timer capacity
pub const ABSOLUTE_MAX_TIMERS: usize = 4_096;

/// Absolute ceiling for one bounded drain operation
pub const ABSOLUTE_MAX_DRAIN_EVENTS: usize = 4_096;

/// Runtime queue and operation limits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    pub(super) queue_capacity: usize,
    pub(super) timer_capacity: usize,
    pub(super) drain_batch: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 256,
            timer_capacity: 256,
            drain_batch: 256,
        }
    }
}

impl EngineConfig {
    /// Create limits below the process-wide safety ceilings
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for zero or excessive limits
    pub fn new(
        max_queued_events: usize,
        max_timers: usize,
        max_drain_events: usize,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            queue_capacity: max_queued_events,
            timer_capacity: max_timers,
            drain_batch: max_drain_events,
        };
        config.validate()?;
        Ok(config)
    }

    #[must_use]
    pub const fn max_queued_events(self) -> usize {
        self.queue_capacity
    }

    #[must_use]
    pub const fn max_timers(self) -> usize {
        self.timer_capacity
    }

    #[must_use]
    pub const fn max_drain_events(self) -> usize {
        self.drain_batch
    }

    pub(super) const fn validate(self) -> Result<(), ConfigError> {
        if self.queue_capacity == 0 || self.queue_capacity > ABSOLUTE_MAX_QUEUED_EVENTS {
            return Err(ConfigError::QueuedEvents {
                value: self.queue_capacity,
                max: ABSOLUTE_MAX_QUEUED_EVENTS,
            });
        }
        if self.timer_capacity == 0 || self.timer_capacity > ABSOLUTE_MAX_TIMERS {
            return Err(ConfigError::Timers {
                value: self.timer_capacity,
                max: ABSOLUTE_MAX_TIMERS,
            });
        }
        if self.drain_batch == 0 || self.drain_batch > ABSOLUTE_MAX_DRAIN_EVENTS {
            return Err(ConfigError::DrainEvents {
                value: self.drain_batch,
                max: ABSOLUTE_MAX_DRAIN_EVENTS,
            });
        }
        Ok(())
    }
}

/// Invalid runtime limits rejected before engine allocation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    QueuedEvents { value: usize, max: usize },
    Timers { value: usize, max: usize },
    DrainEvents { value: usize, max: usize },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueuedEvents { value, max } => {
                write!(formatter, "queued-event limit {value} is outside 1..={max}")
            }
            Self::Timers { value, max } => {
                write!(formatter, "timer limit {value} is outside 1..={max}")
            }
            Self::DrainEvents { value, max } => {
                write!(formatter, "drain-event limit {value} is outside 1..={max}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}
