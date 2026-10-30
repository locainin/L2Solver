//! Exact captured neighbor advertisements and bounded run accounting

use std::net::Ipv6Addr;

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::{NeighborStatus, RunSummary, neighbor};

/// One distinct claimed MAC and the exact captured advertisement
#[derive(Debug)]
pub struct NdpObservation {
    pub(super) mac: MacAddress,
    pub(super) source_ip: Ipv6Addr,
    pub(super) frame: CapturedFrame,
}

impl NdpObservation {
    /// Return the untrusted target link-layer address claim
    #[must_use]
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }

    /// Return the IPv6 source of the advertisement
    #[must_use]
    pub const fn source_ip(&self) -> Ipv6Addr {
        self.source_ip
    }

    /// Borrow the actual captured frame and its source metadata
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// Results of one scoped solicitation and bounded capture
///
/// Neighbor advertisements have no nonce or authentication; a matching
/// packet is a claim, not proof of freshness or address ownership
#[derive(Debug)]
pub struct NdpReport {
    pub(super) expected: Option<MacAddress>,
    pub(super) observations: Vec<NdpObservation>,
    pub(super) unmatched_packets: u32,
    pub(super) summary: RunSummary,
}

impl NdpReport {
    /// Classify observed claims without treating absence as proof
    #[must_use]
    pub fn status(&self) -> NeighborStatus {
        neighbor::classify(self.expected, self.observations.iter().map(|item| item.mac))
    }

    /// Borrow distinct MAC claims and their captured frames
    #[must_use]
    pub fn observations(&self) -> &[NdpObservation] {
        &self.observations
    }

    /// Return whether different MAC addresses claimed the same target
    #[must_use]
    pub const fn has_conflicting_identities(&self) -> bool {
        self.observations.len() > 1
    }

    /// Count scoped complete frames that did not match the selected profile
    #[must_use]
    pub const fn unmatched_packets(&self) -> u32 {
        self.unmatched_packets
    }

    /// Borrow shared transport and capture-quality accounting
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
