//! Exact captured neighbor advertisements and bounded run accounting

use std::net::Ipv6Addr;

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

/// What correlated, unauthenticated advertisements establish
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NdpStatus {
    /// At least one matching target MAC claim was observed
    Observed,
    /// At least one claim differed from the selected expected MAC
    UnexpectedIdentity,
    /// No qualifying advertisement was observed
    Inconclusive,
}

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
    pub fn status(&self) -> NdpStatus {
        if self.observations.is_empty() {
            return NdpStatus::Inconclusive;
        }
        if self
            .observations
            .iter()
            .any(|item| self.expected.is_some_and(|expected| expected != item.mac))
        {
            return NdpStatus::UnexpectedIdentity;
        }
        NdpStatus::Observed
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
