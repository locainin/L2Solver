//! Errors distinguish rejected plans from unfinished executions

use std::fmt;

/// A workload rejected before any virtual dispatch
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AdmissionError {
    /// A scenario must perform at least one bounded stimulus
    Empty,
    /// The fixed schedule memory ceiling would be exceeded
    ScheduleLimit,
    /// Sequence or complete frame size was zero
    InvalidStimulus,
    /// One protocol sequence named more than one event
    DuplicateSequence,
    /// Planned packet count exceeds the selected budget
    PacketLimit,
    /// Planned complete frame sizes exceed the selected budget
    ByteLimit,
    /// A virtual event lies beyond the selected duration
    DurationLimit,
    /// Bounded schedule storage could not be reserved
    Allocation,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "schedule is empty",
            Self::ScheduleLimit => "schedule memory ceiling exceeded",
            Self::InvalidStimulus => "stimulus sequence and byte count must be nonzero",
            Self::DuplicateSequence => "stimulus sequence is duplicated",
            Self::PacketLimit => "packet budget exceeded",
            Self::ByteLimit => "byte budget exceeded",
            Self::DurationLimit => "duration budget exceeded",
            Self::Allocation => "schedule allocation failed",
        })
    }
}

impl std::error::Error for AdmissionError {}

/// An execution cannot yet produce a terminal report
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunError {
    /// Dispatch has neither completed nor been cancelled
    StillRunning,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("execution is still running")
    }
}

impl std::error::Error for RunError {}
