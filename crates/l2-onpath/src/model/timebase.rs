//! Explicit clock scale for session duration accounting

use l2_segmentation::ClockDomainId;

use crate::BudgetError;

/// Clock domain and tick scale used to account for one session's duration
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetTimebase {
    domain: ClockDomainId,
    ticks_per_millisecond: u64,
}

impl BudgetTimebase {
    /// Construct a checked duration timebase
    ///
    /// # Errors
    /// Returns [`BudgetError::ZeroTicksPerMillisecond`] for a zero scale
    pub const fn new(
        domain: ClockDomainId,
        ticks_per_millisecond: u64,
    ) -> Result<Self, BudgetError> {
        if ticks_per_millisecond == 0 {
            return Err(BudgetError::ZeroTicksPerMillisecond);
        }
        Ok(Self {
            domain,
            ticks_per_millisecond,
        })
    }

    /// Return the exact monotonic clock domain
    #[must_use]
    pub const fn domain(self) -> ClockDomainId {
        self.domain
    }

    /// Return the number of monotonic ticks in one millisecond
    #[must_use]
    pub const fn ticks_per_millisecond(self) -> u64 {
        self.ticks_per_millisecond
    }
}
