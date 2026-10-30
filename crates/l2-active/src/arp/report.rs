//! Source-backed results from a single on-link ARP request

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

/// What the captured matching reply fields establish
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpStatus {
    /// At least one matching reply was observed
    Observed,
    /// A matching reply claimed a MAC other than the configured expectation
    UnexpectedIdentity,
    /// No qualifying reply was observed
    Inconclusive,
}

/// One distinct source MAC claim and the exact captured reply that carried it
#[derive(Debug)]
pub struct ArpObservation {
    pub(super) mac: MacAddress,
    pub(super) frame: CapturedFrame,
}

impl ArpObservation {
    /// Return the untrusted source MAC claimed by the reply
    #[must_use]
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }

    /// Borrow the exact captured frame and source metadata
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// Actual request accounting and bounded, independently captured reply facts
///
/// ARP has no nonce or message authentication. Header correlation does not
/// establish freshness, sender ownership, or a network protection verdict
#[derive(Debug)]
pub struct ArpReport {
    pub(super) summary: RunSummary,
    pub(super) expected: Option<MacAddress>,
    pub(super) observations: Vec<ArpObservation>,
}

impl ArpReport {
    /// Classify retained facts without claiming that ARP is authenticated
    #[must_use]
    pub fn status(&self) -> ArpStatus {
        if self.observations.is_empty() {
            return ArpStatus::Inconclusive;
        }
        if self
            .observations
            .iter()
            .any(|item| self.expected_match(item.mac) == Some(false))
        {
            return ArpStatus::UnexpectedIdentity;
        }
        ArpStatus::Observed
    }

    /// Borrow the canonical resource and collection summary
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }

    /// Borrow distinct source-qualified replies in observation order
    #[must_use]
    pub fn observations(&self) -> &[ArpObservation] {
        &self.observations
    }

    /// Return whether distinct MACs claimed the same target IPv4 address
    #[must_use]
    pub const fn has_conflicting_identities(&self) -> bool {
        self.observations.len() > 1
    }

    /// Compare one observed MAC with the operator's optional expectation
    #[must_use]
    pub fn expected_match(&self, mac: MacAddress) -> Option<bool> {
        self.expected.map(|expected| expected == mac)
    }
}
