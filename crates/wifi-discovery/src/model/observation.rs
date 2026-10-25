//! Capture framing and per-record observation state

use serde::{Deserialize, Serialize};

/// Explicit framing supplied by the capture interface
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WirelessInput<'a> {
    Ieee80211(&'a [u8]),
    Radiotap(&'a [u8]),
}

/// Evidence identity and monotonic observation time
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationContext {
    sequence: u64,
    monotonic_ns: Option<u64>,
    capture_truncated: bool,
}

impl ObservationContext {
    #[must_use]
    pub const fn new(sequence: u64, monotonic_ns: u64) -> Self {
        Self {
            sequence,
            monotonic_ns: Some(monotonic_ns),
            capture_truncated: false,
        }
    }

    /// Build a context when a capture source has no monotonic timestamp
    #[must_use]
    pub const fn without_time(sequence: u64) -> Self {
        Self {
            sequence,
            monotonic_ns: None,
            capture_truncated: false,
        }
    }

    /// Mark whether the capture source retained fewer bytes than were on wire
    #[must_use]
    pub const fn with_capture_truncated(mut self, value: bool) -> Self {
        self.capture_truncated = value;
        self
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn monotonic_ns(self) -> Option<u64> {
        self.monotonic_ns
    }

    /// Return whether the source reported capture truncation
    #[must_use]
    pub const fn capture_truncated(self) -> bool {
        self.capture_truncated
    }
}

/// Result of examining one capture record
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ObservationStatus {
    Observed,
    Incomplete,
    NonCanonical,
    Protected,
    Unsupported,
    Malformed,
    ResourceLimited,
}
