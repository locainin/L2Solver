//! Canonical accounting and collection quality for one active operation

use std::io;

use crate::PreSendUsage;
use l2_capture::LinuxInterfaceIdentity;

#[derive(Debug)]
pub enum TransportFailure {
    Send(io::Error),
    Receive(io::Error),
}

/// Why the bounded receive loop stopped
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    /// The response window elapsed
    Deadline,
    /// A stricter backend deadline ended the observation window early
    BackendDeadline,
    /// The caller cancelled the operation
    Cancelled,
    /// The selected interface became unavailable
    InterfaceDown,
    /// All admitted capture records were consumed
    PacketLimit,
    /// All admitted captured bytes were consumed
    ByteLimit,
    /// The bounded evidence or observation capacity was filled
    ObservationLimit,
    /// The backend reported an I/O failure
    TransportError,
    /// The backend returned more bytes than its explicit receive allowance
    BackendViolation,
    /// The backend could not account for its pre-send capture work
    AccountingUnavailable,
}

/// Actual resource use and collection quality for a single active operation
#[derive(Debug)]
pub struct RunSummary {
    pub(crate) interface: LinuxInterfaceIdentity,
    pub(crate) stop_reason: StopReason,
    pub(crate) send_attempted: bool,
    pub(crate) pre_send_usage: Option<PreSendUsage>,
    pub(crate) sent_bytes: u64,
    pub(crate) received_packets: u32,
    pub(crate) received_bytes: u64,
    pub(crate) outbound_packets: u32,
    pub(crate) truncated_packets: u32,
    pub(crate) unscoped_packets: u32,
    pub(crate) capture_loss: Option<u64>,
    pub(crate) capture_backlog: Option<bool>,
    pub(crate) transport_error: Option<TransportFailure>,
    pub(crate) loss_error: Option<io::Error>,
    pub(crate) accounting_error: Option<io::Error>,
    pub(crate) backlog_error: Option<io::Error>,
}

impl RunSummary {
    /// Return the pinned source identity
    #[must_use]
    pub const fn interface(&self) -> LinuxInterfaceIdentity {
        self.interface
    }

    /// Return the condition that ended collection
    #[must_use]
    pub const fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    /// Return whether a socket send was attempted
    #[must_use]
    pub const fn send_attempted(&self) -> bool {
        self.send_attempted
    }

    /// Return how many complete frames the socket accepted
    #[must_use]
    pub const fn sent_packets(&self) -> u32 {
        (self.sent_bytes != 0) as u32
    }

    /// Return socket-accepted frame bytes, excluding FCS
    #[must_use]
    pub const fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// Return delivered frame count, including unrelated traffic
    ///
    /// This is a lower bound when a receive fails or a backend deadline
    /// follows frame consumption without delivery
    #[must_use]
    pub const fn received_packets(&self) -> u32 {
        self.received_packets
    }

    /// Return delivered retained bytes, including unrelated traffic
    ///
    /// This is a lower bound when a receive fails or a backend deadline
    /// follows frame consumption without delivery
    #[must_use]
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Return queue-drain work, or unavailable if the backend could not account for it
    #[must_use]
    pub const fn pre_send_usage(&self) -> Option<PreSendUsage> {
        self.pre_send_usage
    }

    /// Return all drained and collected packets, if accounting is complete
    ///
    /// Backend deadlines can occur after a consumed frame without delivering it
    #[must_use]
    pub const fn total_received_packets(&self) -> Option<u64> {
        if matches!(self.stop_reason, StopReason::BackendDeadline)
            || matches!(self.transport_error, Some(TransportFailure::Receive(_)))
        {
            return None;
        }
        match self.pre_send_usage {
            Some(usage) if usage.is_consistent() => {
                Some(usage.packets() as u64 + self.received_packets as u64)
            }
            Some(_) | None => None,
        }
    }

    /// Return all retained drained and collected bytes, if accounting is complete
    ///
    /// Backend deadlines can occur after a consumed frame without delivering it
    #[must_use]
    pub const fn total_received_bytes(&self) -> Option<u64> {
        if matches!(self.stop_reason, StopReason::BackendDeadline)
            || matches!(self.transport_error, Some(TransportFailure::Receive(_)))
        {
            return None;
        }
        match self.pre_send_usage {
            Some(usage) if usage.is_consistent() => usage.bytes().checked_add(self.received_bytes),
            Some(_) | None => None,
        }
    }

    /// Return known local outgoing frames, which still count toward capture limits
    #[must_use]
    pub const fn outbound_packets(&self) -> u32 {
        self.outbound_packets
    }

    /// Return truncated inbound frames that could not support an observation
    #[must_use]
    pub const fn truncated_packets(&self) -> u32 {
        self.truncated_packets
    }

    /// Return frames with unknown or mismatched interface, direction, or VLAN scope
    #[must_use]
    pub const fn unscoped_packets(&self) -> u32 {
        self.unscoped_packets
    }

    /// Return backend-reported packet loss, or unavailable
    #[must_use]
    pub const fn capture_loss(&self) -> Option<u64> {
        self.capture_loss
    }

    /// Return the final queue-readiness sample, or unavailable
    ///
    /// A false sample does not prove that no packets were lost or later arrived
    #[must_use]
    pub const fn capture_backlog(&self) -> Option<bool> {
        self.capture_backlog
    }

    /// Borrow the send or receive error when the operation stopped on I/O
    #[must_use]
    pub const fn transport_error(&self) -> Option<&io::Error> {
        match &self.transport_error {
            Some(TransportFailure::Send(error) | TransportFailure::Receive(error)) => Some(error),
            None => None,
        }
    }

    /// Borrow the loss-query error when collection quality could not be read
    #[must_use]
    pub const fn loss_error(&self) -> Option<&io::Error> {
        self.loss_error.as_ref()
    }

    /// Borrow the pre-send accounting error, when its totals are unavailable
    #[must_use]
    pub const fn accounting_error(&self) -> Option<&io::Error> {
        self.accounting_error.as_ref()
    }

    /// Borrow the final queue-readiness error, when the sample failed
    #[must_use]
    pub const fn backlog_error(&self) -> Option<&io::Error> {
        self.backlog_error.as_ref()
    }
}
