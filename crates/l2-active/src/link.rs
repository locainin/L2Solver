//! Transport boundary for one explicitly selected, bounded active operation

use std::{io, sync::atomic::AtomicBool, time::Instant};

use l2_capture::{CapturedFrame, LinuxInterfaceIdentity};

/// One packet or terminal event from the selected active capture
#[derive(Debug)]
pub enum ReceiveEvent {
    /// Exact retained bytes and source metadata
    Frame(CapturedFrame),
    /// The caller's absolute observation deadline elapsed
    TimedOut,
    /// A stricter backend deadline ended the observation early
    BackendTimedOut,
    /// The cancellation flag was observed
    Cancelled,
    /// The selected interface became unavailable
    InterfaceDown,
}

/// Captured queue-drain work performed before a send attempt
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreSendUsage {
    packets: u32,
    bytes: u64,
}

impl PreSendUsage {
    /// Record the exact number of drained packets and retained bytes
    #[must_use]
    pub const fn new(packets: u32, bytes: u64) -> Self {
        Self { packets, bytes }
    }

    /// Return the number of drained packets
    #[must_use]
    pub const fn packets(self) -> u32 {
        self.packets
    }

    /// Return the number of retained drained bytes
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Return whether retained bytes fit within the declared number of frames
    #[must_use]
    pub const fn is_consistent(self) -> bool {
        self.bytes <= (self.packets as u64) * (l2_capture::MAX_FRAME_LENGTH as u64)
    }
}

/// Narrow I/O boundary implemented by an explicitly selected active backend
///
/// The backend enforces its own scoped transmit authorization and must not
/// interpret a caller-provided byte sequence as permission to send arbitrary
/// traffic. A completed send confirms socket acceptance, not physical arrival
pub trait ActiveLink {
    /// Return the pinned namespace and interface identity
    fn interface(&self) -> LinuxInterfaceIdentity;

    /// Submit a preauthorized complete frame to the selected socket
    ///
    /// Pre-send queue draining must honor the same deadline and cancellation
    /// If cancellation wins before submission, return `Interrupted`
    /// If the deadline wins before submission, return `TimedOut`
    ///
    /// # Errors
    /// Returns an error if admission or the complete send fails
    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()>;

    /// Return total queue-drain work performed before the attempted send
    ///
    /// This query is required after both successful and unsuccessful sends
    /// `None` means the work could not be established, not that it was zero
    ///
    /// # Errors
    /// Returns an error if bounded work accounting cannot be retrieved
    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>>;

    /// Receive within the deadline while retaining at most `max_bytes` bytes
    ///
    /// A shorter capture must preserve the original length in its metadata
    /// The timeout variant distinguishes the caller's deadline from an
    /// earlier backend-admitted deadline
    /// A receive-only operation may call this without an earlier send; its
    /// backend must not consume unreported frames while preparing the listener
    ///
    /// # Errors
    /// Returns an error if the source cannot continue
    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent>;

    /// Return cumulative packet loss for this operation, or unavailable
    ///
    /// The backend must make this query bounded even after cancellation
    ///
    /// # Errors
    /// Returns an error if the backend cannot query its capture state
    fn capture_loss(&mut self) -> io::Result<Option<u64>>;

    /// Sample whether any captured frame remains queued, without consuming it
    ///
    /// `None` means readiness is unavailable; a false result is only a sample
    /// and does not establish that no earlier loss or later arrivals occurred
    ///
    /// # Errors
    /// Returns an error if the bounded readiness check fails
    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Ok(None)
    }
}
