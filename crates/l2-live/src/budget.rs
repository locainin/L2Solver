//! Bounded live-capture budget with deterministic stop reasons

use std::time::{Duration, Instant};

/// Maximum number of frames one live capture may retain
pub const MAX_PACKET_COUNT: u32 = 10_000;

/// Default wall-clock duration for one live capture
pub const DEFAULT_CAPTURE_DURATION: Duration = Duration::from_secs(30);

/// Absolute wall-clock duration for one live capture
pub const MAX_CAPTURE_DURATION: Duration = Duration::from_mins(5);

/// Normal reason a live capture stopped producing frames
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// The caller's requested frame count has been delivered
    PacketLimit,
    /// The fixed live-capture duration elapsed before the frame count was met
    Deadline,
}

/// Private packet and duration budget shared by the live receive loop
pub struct Budget {
    remaining: u32,
    deadline: Instant,
    stop_reason: Option<StopReason>,
}

impl Budget {
    /// Validate the packet bound before any interface or capture operation
    pub const fn validate_packet_count(packets: u32) -> Result<(), &'static str> {
        if packets == 0 || packets > MAX_PACKET_COUNT {
            Err("packet count must be from 1 to 10000")
        } else {
            Ok(())
        }
    }

    /// Validate the duration before any interface or capture operation
    pub fn validate_duration(duration: Duration) -> Result<(), &'static str> {
        if duration < Duration::from_secs(1) || duration > MAX_CAPTURE_DURATION {
            Err("capture duration must be from 1s to 5m")
        } else {
            Ok(())
        }
    }

    /// Start a budget after the capture handle has been opened
    pub fn new(packets: u32, duration: Duration, started_at: Instant) -> Self {
        // The receive opener validates both limits before opening libpcap
        debug_assert!(Self::validate_packet_count(packets).is_ok());
        debug_assert!(Self::validate_duration(duration).is_ok());
        Self {
            remaining: packets,
            deadline: started_at + duration,
            stop_reason: None,
        }
    }

    /// Account for one frame returned to the caller
    pub const fn consume_packet(&mut self) {
        // A frame is consumed only after the budget check has allowed it
        self.remaining -= 1;
    }

    /// Return and remember the first normal stop reason at the supplied time
    pub fn poll(&mut self, now: Instant) -> Option<StopReason> {
        if let Some(reason) = self.stop_reason {
            return Some(reason);
        }

        let reason = if self.remaining == 0 {
            // Reaching the requested count is the stronger completion signal
            StopReason::PacketLimit
        } else if now >= self.deadline {
            StopReason::Deadline
        } else {
            return None;
        };
        self.stop_reason = Some(reason);
        Some(reason)
    }

    /// Return the normal stop reason after the receive loop reaches EOF
    #[must_use]
    pub const fn stop_reason(&self) -> Option<StopReason> {
        self.stop_reason
    }
}
