//! Fixed resource ceilings for active response collection

use std::time::Duration;

use crate::PlanError;

/// Largest duration of one request and observation period
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest number of captured frames processed by one operation
pub const MAX_RECEIVED_PACKETS: u32 = 4_096;
/// Largest number of captured bytes retained and inspected by one operation
pub const MAX_RECEIVED_BYTES: u64 = 16_777_216;

/// Admitted time and receive-work limits for one active operation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    timeout: Duration,
    max_received_packets: u32,
    max_received_bytes: u64,
}

impl Limits {
    /// Admit explicit finite limits before opening a link
    ///
    /// # Errors
    /// Rejects zero limits or values above the fixed operation ceilings
    pub fn new(
        timeout: Duration,
        max_received_packets: u32,
        max_received_bytes: u64,
    ) -> Result<Self, PlanError> {
        if timeout < Duration::from_millis(1) || timeout > MAX_TIMEOUT {
            return Err(PlanError::InvalidTimeout);
        }
        if max_received_packets == 0 || max_received_packets > MAX_RECEIVED_PACKETS {
            return Err(PlanError::InvalidPacketLimit);
        }
        if max_received_bytes == 0 || max_received_bytes > MAX_RECEIVED_BYTES {
            return Err(PlanError::InvalidByteLimit);
        }
        Ok(Self {
            timeout,
            max_received_packets,
            max_received_bytes,
        })
    }

    /// Return the complete operation deadline
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.timeout
    }

    /// Return the maximum accepted capture records
    #[must_use]
    pub const fn max_received_packets(self) -> u32 {
        self.max_received_packets
    }

    /// Return the total captured-byte ceiling
    #[must_use]
    pub const fn max_received_bytes(self) -> u64 {
        self.max_received_bytes
    }
}
