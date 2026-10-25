use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "../tests/budget/future_start.rs"]
mod tests;

/// Absolute maximum number of frames one helper session may return
pub const MAX_SESSION_FRAMES: u32 = 10_000;

/// Absolute maximum number of frame bytes one helper session may return
pub const MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;

/// Absolute maximum wall-clock lifetime for one helper session
pub const MAX_SESSION_DURATION: Duration = Duration::from_mins(5);

/// Validation failures for helper-owned session budgets
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// A session cannot return zero frames
    ZeroFrameLimit,
    /// A session cannot return zero bytes
    ZeroByteLimit,
    /// The requested frame limit exceeds the helper ceiling
    FrameLimit,
    /// The requested byte limit exceeds the helper ceiling
    ByteLimit,
    /// The requested duration is shorter than one second
    DurationTooShort,
    /// The requested duration exceeds the helper ceiling
    DurationTooLong,
    /// The supplied start instant is ahead of the current monotonic clock
    FutureStart,
    /// A frame would cross the configured byte limit
    FrameWouldExceedBytes,
    /// A frame would cross the configured frame limit
    FrameWouldExceedCount,
    /// The session deadline has elapsed
    Deadline,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroFrameLimit => "frame limit must be nonzero",
            Self::ZeroByteLimit => "byte limit must be nonzero",
            Self::FrameLimit => "frame limit exceeds helper ceiling",
            Self::ByteLimit => "byte limit exceeds helper ceiling",
            Self::DurationTooShort => "session duration must be at least one second",
            Self::DurationTooLong => "session duration exceeds helper ceiling",
            Self::FutureStart => "session start cannot be in the future",
            Self::FrameWouldExceedBytes => "frame would exceed session byte limit",
            Self::FrameWouldExceedCount => "frame would exceed session frame limit",
            Self::Deadline => "session deadline elapsed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BudgetError {}

/// Per-session limits requested by a trusted launcher
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    max_frames: u32,
    max_bytes: u64,
    duration: Duration,
}

impl SessionLimits {
    /// Validate limits against the helper's compiled ceilings
    ///
    /// # Errors
    /// Returns a [`BudgetError`] when any limit is zero, too large, or too short
    pub fn new(max_frames: u32, max_bytes: u64, duration: Duration) -> Result<Self, BudgetError> {
        if max_frames == 0 {
            return Err(BudgetError::ZeroFrameLimit);
        }
        if max_bytes == 0 {
            return Err(BudgetError::ZeroByteLimit);
        }
        if max_frames > MAX_SESSION_FRAMES {
            return Err(BudgetError::FrameLimit);
        }
        if max_bytes > MAX_SESSION_BYTES {
            return Err(BudgetError::ByteLimit);
        }
        if duration < Duration::from_secs(1) {
            return Err(BudgetError::DurationTooShort);
        }
        if duration > MAX_SESSION_DURATION {
            return Err(BudgetError::DurationTooLong);
        }
        Ok(Self {
            max_frames,
            max_bytes,
            duration,
        })
    }

    /// Return the configured frame limit
    #[must_use]
    pub const fn max_frames(self) -> u32 {
        self.max_frames
    }

    /// Return the configured byte limit
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Return the configured wall-clock duration
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.duration
    }
}

/// Mutable helper-owned accounting for one receive session
#[derive(Debug)]
pub struct SessionBudget {
    limits: SessionLimits,
    started: Instant,
    frames: u32,
    bytes: u64,
}

impl SessionBudget {
    /// Start a budget at the current monotonic clock
    #[must_use]
    pub fn start(limits: SessionLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            frames: 0,
            bytes: 0,
        }
    }

    /// Start a server budget from the instant shared with its control deadline
    pub(crate) fn start_at(limits: SessionLimits, started: Instant) -> Result<Self, BudgetError> {
        if started > Instant::now() {
            return Err(BudgetError::FutureStart);
        }
        Ok(Self {
            limits,
            started,
            frames: 0,
            bytes: 0,
        })
    }

    /// Check whether one frame can be accounted for before receiving it
    ///
    /// # Errors
    /// Returns the first exhausted budget dimension
    pub fn reserve(&self, frame_bytes: usize) -> Result<(), BudgetError> {
        if self.started.elapsed() >= self.limits.duration {
            return Err(BudgetError::Deadline);
        }
        if self.frames >= self.limits.max_frames {
            return Err(BudgetError::FrameWouldExceedCount);
        }
        let frame_bytes =
            u64::try_from(frame_bytes).map_err(|_| BudgetError::FrameWouldExceedBytes)?;
        let total = self
            .bytes
            .checked_add(frame_bytes)
            .ok_or(BudgetError::FrameWouldExceedBytes)?;
        if total > self.limits.max_bytes {
            return Err(BudgetError::FrameWouldExceedBytes);
        }
        Ok(())
    }

    /// Commit one frame after backend validation and successful reply encoding
    ///
    /// # Errors
    /// Returns an error if the commit does not match the reserved budget
    pub fn commit(&mut self, frame_bytes: usize) -> Result<(), BudgetError> {
        self.reserve(frame_bytes)?;
        self.commit_reserved(frame_bytes)
    }

    /// Commit a frame after the reserved response has reached the transport
    /// queue
    ///
    /// The caller must run [`Self::reserve`] immediately before attempting the
    /// response enqueue. This method intentionally skips the deadline check so
    /// a response that was accepted by the transport cannot become unaccounted
    /// only because the clock advanced between enqueue and accounting.
    pub(crate) fn commit_reserved(&mut self, frame_bytes: usize) -> Result<(), BudgetError> {
        let frames = self
            .frames
            .checked_add(1)
            .ok_or(BudgetError::FrameWouldExceedCount)?;
        let frame_bytes =
            u64::try_from(frame_bytes).map_err(|_| BudgetError::FrameWouldExceedBytes)?;
        let bytes = self
            .bytes
            .checked_add(frame_bytes)
            .ok_or(BudgetError::FrameWouldExceedBytes)?;
        // reserve() established both ceilings before the response was sent
        self.frames = frames;
        self.bytes = bytes;
        Ok(())
    }

    /// Return the number of frames committed to frontend replies
    #[must_use]
    pub const fn frames(&self) -> u32 {
        self.frames
    }

    /// Return the number of frame bytes committed to frontend replies
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}
