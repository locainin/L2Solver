//! Inspection completeness requires both valid capture contents and no reported loss

#[cfg(feature = "live")]
use serde::Serialize;

/// Terminal condition reported by a bounded live capture
#[cfg(feature = "live")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStopReason {
    PacketLimit,
    Deadline,
    Unavailable,
}

/// Operator-selected live collection goal
#[cfg(feature = "live")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveGoal {
    Packets,
    Duration,
}

/// Live stop and loss information retained in reports
#[cfg(feature = "live")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LiveCaptureQuality {
    stop_reason: LiveStopReason,
    goal: LiveGoal,
    received: u32,
    capture_dropped: u32,
    interface_dropped: u32,
    loss_counters_authoritative: bool,
}

#[cfg(feature = "live")]
impl LiveCaptureQuality {
    pub const fn from_libpcap(
        reason: Option<l2_live::StopReason>,
        duration_is_goal: bool,
        statistics: l2_live::LiveStatistics,
    ) -> Self {
        Self {
            stop_reason: match reason {
                Some(l2_live::StopReason::PacketLimit) => LiveStopReason::PacketLimit,
                Some(l2_live::StopReason::Deadline) => LiveStopReason::Deadline,
                None => LiveStopReason::Unavailable,
            },
            goal: if duration_is_goal {
                LiveGoal::Duration
            } else {
                LiveGoal::Packets
            },
            received: statistics.received(),
            capture_dropped: statistics.capture_dropped(),
            interface_dropped: statistics.interface_dropped(),
            loss_counters_authoritative: statistics.loss_counters_authoritative(),
        }
    }

    /// Return whether the requested ceiling ended collection with proven zero loss
    #[must_use]
    pub const fn supports_complete_collection(self) -> bool {
        self.collection_report().supports_complete_collection()
    }

    /// Use the capture format's collection rule for both live and saved evidence
    pub const fn collection_report(self) -> l2_pcap::CollectionReport {
        l2_pcap::CollectionReport::new(
            match self.stop_reason {
                LiveStopReason::PacketLimit => l2_pcap::CollectionStopReason::PacketLimit,
                LiveStopReason::Deadline => l2_pcap::CollectionStopReason::Deadline,
                LiveStopReason::Unavailable => l2_pcap::CollectionStopReason::Unavailable,
            },
            match self.goal {
                LiveGoal::Packets => l2_pcap::CollectionGoal::Packets,
                LiveGoal::Duration => l2_pcap::CollectionGoal::Duration,
            },
            self.received,
            self.capture_dropped,
            self.interface_dropped,
            self.loss_counters_authoritative,
        )
    }

    #[must_use]
    pub const fn stop_reason(self) -> LiveStopReason {
        self.stop_reason
    }

    #[must_use]
    pub const fn goal(self) -> LiveGoal {
        self.goal
    }

    #[must_use]
    pub const fn received(self) -> u32 {
        self.received
    }

    #[must_use]
    pub const fn capture_dropped(self) -> u32 {
        self.capture_dropped
    }

    #[must_use]
    pub const fn interface_dropped(self) -> u32 {
        self.interface_dropped
    }

    #[must_use]
    pub const fn loss_counters_authoritative(self) -> bool {
        self.loss_counters_authoritative
    }

    #[cfg(test)]
    pub const fn authoritative_for_test(
        reason: Option<l2_live::StopReason>,
        duration_is_goal: bool,
        received: u32,
        capture_dropped: u32,
        interface_dropped: u32,
    ) -> Self {
        Self {
            stop_reason: match reason {
                Some(l2_live::StopReason::PacketLimit) => LiveStopReason::PacketLimit,
                Some(l2_live::StopReason::Deadline) => LiveStopReason::Deadline,
                None => LiveStopReason::Unavailable,
            },
            goal: if duration_is_goal {
                LiveGoal::Duration
            } else {
                LiveGoal::Packets
            },
            received,
            capture_dropped,
            interface_dropped,
            loss_counters_authoritative: true,
        }
    }

    #[cfg(test)]
    pub const fn reported_for_test(
        stop_reason: LiveStopReason,
        goal: LiveGoal,
        received: u32,
        capture_dropped: u32,
        interface_dropped: u32,
    ) -> Self {
        Self {
            stop_reason,
            goal,
            received,
            capture_dropped,
            interface_dropped,
            loss_counters_authoritative: false,
        }
    }
}

pub const fn complete(
    malformed: u64,
    invalid: u64,
    unsupported: u64,
    truncated: u64,
    drops: [u32; 2],
) -> bool {
    let [kernel, interface] = drops;
    malformed == 0
        && invalid == 0
        && unsupported == 0
        && truncated == 0
        && kernel == 0
        && interface == 0
}

#[cfg(feature = "live")]
pub const fn complete_live(
    malformed: u64,
    invalid: u64,
    unsupported: u64,
    truncated: u64,
    quality: &LiveCaptureQuality,
) -> bool {
    quality.supports_complete_collection()
        && complete(
            malformed,
            invalid,
            unsupported,
            truncated,
            [quality.capture_dropped(), quality.interface_dropped()],
        )
}

#[cfg(test)]
#[path = "../tests/completion/mod.rs"]
mod tests;
