//! Monotonic time primitives used by deterministic engine tests

use std::{fmt, time::Duration};

/// A monotonic nanosecond value used for engine ordering
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonoTime(u64);

impl MonoTime {
    /// The initial monotonic instant
    pub const ZERO: Self = Self(0);

    /// Construct an instant from an exact nanosecond count
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Return the exact nanosecond count
    #[must_use]
    pub const fn nanos(self) -> u64 {
        self.0
    }

    /// Add a checked nanosecond count
    ///
    /// # Errors
    /// Returns [`ClockError::TimeOverflow`] when the instant cannot contain
    /// the requested result
    pub fn checked_add_nanos(self, nanos: u64) -> Result<Self, ClockError> {
        self.0
            .checked_add(nanos)
            .map(Self)
            .ok_or(ClockError::TimeOverflow {
                now: self,
                delta_nanos: nanos,
            })
    }

    /// Add a standard duration without truncating it
    ///
    /// # Errors
    /// Returns [`ClockError::DurationTooLarge`] when the duration does not fit
    /// in the engine's 64-bit nanosecond representation, or
    /// [`ClockError::TimeOverflow`] when the addition overflows
    pub fn checked_add(self, duration: Duration) -> Result<Self, ClockError> {
        let nanos =
            u64::try_from(duration.as_nanos()).map_err(|_| ClockError::DurationTooLarge {
                nanos: duration.as_nanos(),
            })?;
        self.checked_add_nanos(nanos)
    }

    /// Return the elapsed duration from an earlier monotonic instant
    ///
    /// # Errors
    /// Returns [`ClockError::TimeWentBackwards`] when `earlier` is newer than
    /// this instant
    pub fn checked_duration_since(self, earlier: Self) -> Result<Duration, ClockError> {
        self.0
            .checked_sub(earlier.0)
            .map(Duration::from_nanos)
            .ok_or(ClockError::TimeWentBackwards {
                previous: earlier,
                current: self,
            })
    }
}

impl fmt::Display for MonoTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ns", self.0)
    }
}

/// Errors from checked monotonic-time operations
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// A duration was too large to represent as nanoseconds
    DurationTooLarge {
        /// The original duration in nanoseconds
        nanos: u128,
    },
    /// Adding a duration exceeded the maximum monotonic instant
    TimeOverflow {
        /// The instant before addition
        now: MonoTime,
        /// The requested nanosecond increment
        delta_nanos: u64,
    },
    /// An operation supplied a newer instant as its earlier value
    TimeWentBackwards {
        /// The supplied earlier instant
        previous: MonoTime,
        /// The current instant
        current: MonoTime,
    },
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurationTooLarge { nanos } => {
                write!(
                    formatter,
                    "duration of {nanos}ns exceeds monotonic clock range"
                )
            }
            Self::TimeOverflow { now, delta_nanos } => {
                write!(
                    formatter,
                    "adding {delta_nanos}ns to {now} overflows monotonic time"
                )
            }
            Self::TimeWentBackwards { previous, current } => {
                write!(
                    formatter,
                    "monotonic time moved backwards from {previous} to {current}"
                )
            }
        }
    }
}

impl std::error::Error for ClockError {}

/// A manually advanced clock for deterministic state-machine tests
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FakeClock {
    now: MonoTime,
}

impl FakeClock {
    /// Construct a clock at the initial instant
    #[must_use]
    pub const fn new() -> Self {
        Self {
            now: MonoTime::ZERO,
        }
    }

    /// Construct a clock at a chosen instant
    #[must_use]
    pub const fn at(now: MonoTime) -> Self {
        Self { now }
    }

    /// Advance the clock using checked arithmetic
    ///
    /// # Errors
    /// Returns a [`ClockError`] without changing the clock when the duration
    /// cannot be represented or would overflow the current instant
    pub fn advance(&mut self, duration: Duration) -> Result<MonoTime, ClockError> {
        let next = self.now.checked_add(duration)?;
        self.now = next;
        Ok(next)
    }

    /// Advance by an exact nanosecond count
    ///
    /// # Errors
    /// Returns [`ClockError::TimeOverflow`] without changing the clock when
    /// the result cannot be represented
    pub fn advance_nanos(&mut self, nanos: u64) -> Result<MonoTime, ClockError> {
        let next = self.now.checked_add_nanos(nanos)?;
        self.now = next;
        Ok(next)
    }
}

/// A clock source read by the event engine
pub trait Clock {
    /// Return the current monotonic instant
    fn now(&self) -> MonoTime;
}

impl Clock for FakeClock {
    fn now(&self) -> MonoTime {
        self.now
    }
}
