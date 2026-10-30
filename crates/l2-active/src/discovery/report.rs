//! Source-backed discovery events and bounded collection accounting

use l2_capture::CapturedFrame;

use super::decode::{Content, Decoded};
use crate::RunSummary;

/// Recognized discovery protocol on the captured frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryProtocol {
    /// LLDP over Ethernet II
    Lldp,
    /// CDP over IEEE 802.3 LLC/SNAP
    Cdp,
}

/// Result of examining one recognized discovery frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryDisposition {
    /// Valid nonzero-hold advertisement
    Advertisement,
    /// Valid zero-hold withdrawal advertisement
    Withdrawal,
    /// A recognizable frame violated the supported semantic or framing rules
    Malformed,
    /// The frame exceeded a local parser budget, so its validity is unknown
    LimitExceeded,
}

/// Borrowed unauthenticated device and port identifiers
///
/// LLDP values include their subtype byte; CDP values are raw TLV bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryIdentity<'a> {
    device: &'a [u8],
    port: &'a [u8],
}

impl<'a> DiscoveryIdentity<'a> {
    /// Return the device or chassis identifier bytes
    #[must_use]
    pub const fn device(self) -> &'a [u8] {
        self.device
    }
    /// Return the port identifier bytes
    #[must_use]
    pub const fn port(self) -> &'a [u8] {
        self.port
    }
}

/// One received frame retained with its interface and capture metadata
#[derive(Debug)]
pub struct DiscoveryObservation {
    pub(super) frame: CapturedFrame,
    pub(super) protocol: DiscoveryProtocol,
    pub(super) source_mac: [u8; 6],
    pub(super) destination_mac: [u8; 6],
    pub(super) content: Content,
}

impl DiscoveryObservation {
    pub(super) const fn new(frame: CapturedFrame, decoded: Decoded) -> Self {
        Self {
            frame,
            protocol: decoded.protocol,
            source_mac: decoded.source_mac,
            destination_mac: decoded.destination_mac,
            content: decoded.content,
        }
    }
    /// Return the recognized protocol
    #[must_use]
    pub const fn protocol(&self) -> DiscoveryProtocol {
        self.protocol
    }
    /// Return the Ethernet source bytes as captured, including malformed values
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source_mac
    }
    /// Return the Ethernet destination scope from the captured frame
    #[must_use]
    pub const fn destination_mac(&self) -> [u8; 6] {
        self.destination_mac
    }
    /// Return the parsed frame disposition
    #[must_use]
    pub const fn disposition(&self) -> DiscoveryDisposition {
        match &self.content {
            Content::Malformed => DiscoveryDisposition::Malformed,
            Content::LimitExceeded => DiscoveryDisposition::LimitExceeded,
            Content::Valid(fields) if fields.hold_seconds == 0 => DiscoveryDisposition::Withdrawal,
            Content::Valid(_) => DiscoveryDisposition::Advertisement,
        }
    }
    /// Return the advertised hold time in seconds, if parsing succeeded
    #[must_use]
    pub const fn hold_seconds(&self) -> Option<u16> {
        match &self.content {
            Content::Valid(fields) => Some(fields.hold_seconds),
            Content::Malformed | Content::LimitExceeded => None,
        }
    }
    /// Borrow identity bytes from the retained evidence frame
    ///
    /// Malformed frames return `None`; ranges are checked against retained bytes
    #[must_use]
    pub fn identity(&self) -> Option<DiscoveryIdentity<'_>> {
        let Content::Valid(fields) = &self.content else {
            return None;
        };
        Some(DiscoveryIdentity {
            device: self.frame.bytes().get(fields.device.clone())?,
            port: self.frame.bytes().get(fields.port.clone())?,
        })
    }
    /// Borrow the exact captured frame and its original metadata
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// Summary of actual recognized frame observations
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryStatus {
    /// At least one valid advertisement or withdrawal was observed
    Observed,
    /// At least one recognizable discovery frame was malformed
    Malformed,
    /// No recognizable frame was retained
    Inconclusive,
}

/// Comparison of observed claims with one operator-supplied identity
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAssessment {
    /// At least one scoped claim matched and none contradicted the expectation
    Matched,
    /// At least one scoped claim carried a different device or port identity
    UnexpectedIdentity,
    /// No decodable claim matched the selected source, scope, and protocol
    Inconclusive,
}

/// Bounded observed discovery events and their actual collection quality
#[derive(Debug)]
pub struct DiscoveryReport {
    pub(super) summary: RunSummary,
    pub(super) observations: Vec<DiscoveryObservation>,
    pub(super) unmatched_packets: u32,
}

impl DiscoveryReport {
    /// Classify retained frames without inferring protection from silence
    #[must_use]
    pub fn status(&self) -> DiscoveryStatus {
        if self
            .observations
            .iter()
            .any(|item| item.disposition() == DiscoveryDisposition::Malformed)
        {
            DiscoveryStatus::Malformed
        } else if self
            .observations
            .iter()
            .any(|item| matches!(item.content, Content::Valid(_)))
        {
            DiscoveryStatus::Observed
        } else {
            DiscoveryStatus::Inconclusive
        }
    }
    /// Borrow retained frames in collection order, including repeated claims
    #[must_use]
    pub fn observations(&self) -> &[DiscoveryObservation] {
        &self.observations
    }

    /// Compare all decoded claims from one source and destination scope
    ///
    /// A withdrawal is still an identity claim, not proof of current presence
    /// An observed contradiction remains visible after cancellation or loss
    /// Matching unauthenticated bytes does not establish sender ownership
    #[must_use]
    pub fn assess_identity(
        &self,
        protocol: DiscoveryProtocol,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
        expected_device: &[u8],
        expected_port: &[u8],
    ) -> IdentityAssessment {
        let mut matched = false;
        for observation in &self.observations {
            if observation.protocol != protocol
                || observation.source_mac != source_mac
                || observation.destination_mac != destination_mac
            {
                continue;
            }
            let Some(identity) = observation.identity() else {
                continue;
            };
            if identity.device() != expected_device || identity.port() != expected_port {
                return IdentityAssessment::UnexpectedIdentity;
            }
            matched = true;
        }
        if matched {
            IdentityAssessment::Matched
        } else {
            IdentityAssessment::Inconclusive
        }
    }
    /// Count complete, scoped frames that did not match the selected protocols
    #[must_use]
    pub const fn unmatched_packets(&self) -> u32 {
        self.unmatched_packets
    }
    /// Borrow the actual interface, limits, termination, loss, and error summary
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
