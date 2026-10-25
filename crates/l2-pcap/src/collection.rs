//! Source-reported collection conditions, distinct from packet parse validity

/// Condition that stopped capture collection
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionStopReason {
    Unavailable,
    PacketLimit,
    Deadline,
}

/// Requested collection goal
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionGoal {
    Packets,
    Duration,
}

/// Acquisition conditions asserted by one capture section
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectionReport {
    stop_reason: CollectionStopReason,
    goal: CollectionGoal,
    received: u32,
    capture_dropped: u32,
    interface_dropped: u32,
    loss_counters_authoritative: bool,
}

impl CollectionReport {
    /// Retain reported values without inferring loss authority from zero counters
    #[must_use]
    pub const fn new(
        stop_reason: CollectionStopReason,
        goal: CollectionGoal,
        received: u32,
        capture_dropped: u32,
        interface_dropped: u32,
        loss_counters_authoritative: bool,
    ) -> Self {
        Self {
            stop_reason,
            goal,
            received,
            capture_dropped,
            interface_dropped,
            loss_counters_authoritative,
        }
    }

    /// Require the requested stop condition and authoritative zero-loss counters
    #[must_use]
    pub const fn supports_complete_collection(self) -> bool {
        matches!(
            (self.stop_reason, self.goal),
            (CollectionStopReason::PacketLimit, CollectionGoal::Packets)
                | (CollectionStopReason::Deadline, CollectionGoal::Duration)
        ) && self.loss_counters_authoritative
            && self.capture_dropped == 0
            && self.interface_dropped == 0
    }

    /// Return the reported terminal condition
    #[must_use]
    pub const fn stop_reason(self) -> CollectionStopReason {
        self.stop_reason
    }

    /// Return the requested acquisition goal
    #[must_use]
    pub const fn goal(self) -> CollectionGoal {
        self.goal
    }

    /// Return the backend's received counter, which may count filtered packets
    #[must_use]
    pub const fn received(self) -> u32 {
        self.received
    }

    /// Return reported capture-buffer loss
    #[must_use]
    pub const fn capture_dropped(self) -> u32 {
        self.capture_dropped
    }

    /// Return reported interface loss
    #[must_use]
    pub const fn interface_dropped(self) -> u32 {
        self.interface_dropped
    }

    /// Return whether the producer treated both loss counters as authoritative
    #[must_use]
    pub const fn loss_counters_authoritative(self) -> bool {
        self.loss_counters_authoritative
    }
}

/// Constant-space summary of collection declarations across capture sections
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CollectionSummary {
    pub sections: u64,
    pub reported_sections: u64,
    pub incomplete_sections: u64,
    pub capture_dropped: u64,
    pub interface_dropped: u64,
    /// Known packet losses reported by obsolete Packet Block headers
    pub packet_block_packets_dropped: u64,
    /// Packet Blocks whose legacy drop counter was unavailable
    pub packet_blocks_with_unavailable_drop_count: u64,
}

impl CollectionSummary {
    pub(super) fn observe(&mut self, report: Option<CollectionReport>) {
        // Section numbers and each counter are at most u32, so these u64 sums fit
        self.sections += 1;
        if let Some(report) = report {
            self.reported_sections += 1;
            self.incomplete_sections += u64::from(!report.supports_complete_collection());
            self.capture_dropped += u64::from(report.capture_dropped());
            self.interface_dropped += u64::from(report.interface_dropped());
        }
    }

    pub(super) fn observe_packet_block_drops(&mut self, drops_count: u16) {
        // The reader enforces a u32 record ceiling, so this count cannot overflow
        if drops_count == u16::MAX {
            self.packet_blocks_with_unavailable_drop_count += 1;
        } else {
            // The record ceiling is u32 and each legacy count is at most u16::MAX - 1
            self.packet_block_packets_dropped += u64::from(drops_count);
        }
    }
}
