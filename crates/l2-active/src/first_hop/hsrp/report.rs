//! Bounded HSRP claims and their capture provenance

use std::{fmt, net::Ipv4Addr};

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

/// What the collection window established about HSRP messages
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsrpStatus {
    /// At least one scoped message passed the supported structural checks
    Observed,
    /// No valid scoped message was received
    Inconclusive,
}

/// The layer that prevented a recognizable candidate from becoming a claim
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsrpMalformed {
    /// The Ethernet source was not a nonzero unicast address
    SourceMac,
    /// The IPv4 header, length, checksum, source, fragmentation, or TTL was invalid
    Ipv4,
    /// The UDP envelope, length, or present checksum was invalid
    Udp,
    /// The supported fixed header, opcode, state, reserved field, or timers were invalid
    Protocol,
}

/// The message type claimed by the sender
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsrpOpcode {
    /// The sender claims to be participating in the group
    Hello,
    /// The sender requests the active role
    Coup,
    /// The sender gives up its claim to the active role
    Resign,
}

/// The sender's claimed HSRP state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsrpState {
    /// The protocol is not running according to the sender
    Initial,
    /// The sender is learning the virtual address
    Learn,
    /// The sender is listening for other members
    Listen,
    /// The sender is participating in the election
    Speak,
    /// The sender claims the standby role
    Standby,
    /// The sender claims the active role
    Active,
}

/// One unauthenticated `HSRPv1` message's fixed-header claims
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HsrpAdvertisement {
    pub(super) source_mac: MacAddress,
    pub(super) source_ip: Ipv4Addr,
    pub(super) virtual_ip: Ipv4Addr,
    pub(super) opcode: HsrpOpcode,
    pub(super) state: HsrpState,
    pub(super) group: u8,
    pub(super) priority: u8,
    pub(super) hello_seconds: u8,
    pub(super) hold_seconds: u8,
    pub(super) udp_checksum_present: bool,
}

impl HsrpAdvertisement {
    /// Return the observed Ethernet source, which may itself be a virtual MAC
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source_mac
    }

    /// Return the unauthenticated IPv4 source claim
    #[must_use]
    pub const fn source_ip(&self) -> Ipv4Addr {
        self.source_ip
    }

    /// Return the virtual address as claimed, including an unspecified address
    #[must_use]
    pub const fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }

    /// Return the claimed message type
    #[must_use]
    pub const fn opcode(&self) -> HsrpOpcode {
        self.opcode
    }

    /// Return the claimed sender state, not a verified forwarding role
    #[must_use]
    pub const fn state(&self) -> HsrpState {
        self.state
    }

    /// Return the full one-byte Ethernet group number
    #[must_use]
    pub const fn group(&self) -> u8 {
        self.group
    }

    /// Return the priority claimed in the message
    #[must_use]
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Return the wire hello field in seconds, meaningful for Hello messages
    #[must_use]
    pub const fn hello_seconds(&self) -> u8 {
        self.hello_seconds
    }

    /// Return the wire hold field in seconds, meaningful for Hello messages
    #[must_use]
    pub const fn hold_seconds(&self) -> u8 {
        self.hold_seconds
    }

    /// Return whether the optional IPv4 UDP checksum was present and valid
    #[must_use]
    pub const fn udp_checksum_present(&self) -> bool {
        self.udp_checksum_present
    }
}

/// The supported interpretation of one identifiable HSRP candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HsrpEvidence {
    /// A wire-version-zero fixed header passed the supported checks
    Advertisement(HsrpAdvertisement),
    /// A recognizable candidate failed validation
    Malformed(HsrpMalformed),
    /// The first payload byte did not identify the supported fixed-header version
    ///
    /// This byte is not necessarily the version field in other packet formats
    UnsupportedVersion(u8),
}

/// A scoped candidate with its original capture and safe interpretation
pub struct HsrpObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: HsrpEvidence,
}

impl fmt::Debug for HsrpObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("HsrpObservation")
            .field("evidence", &self.evidence)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl HsrpObservation {
    /// Borrow the captured frame, which can contain cleartext authentication and padding
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }

    /// Borrow the candidate's interpretation without authentication bytes
    #[must_use]
    pub const fn evidence(&self) -> &HsrpEvidence {
        &self.evidence
    }
}

/// Receive-only claims and collection-quality accounting
///
/// A message does not prove the sender's identity, election, or actual forwarding
pub struct HsrpReport {
    pub(super) observations: Vec<HsrpObservation>,
    pub(super) unmatched_packets: u32,
    pub(super) summary: RunSummary,
}

// Backend error messages can contain arbitrary captured bytes
impl fmt::Debug for HsrpReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("HsrpReport")
            .field("status", &self.status())
            .field("observations", &self.observations)
            .field("unmatched_packets", &self.unmatched_packets)
            .field("stop_reason", &self.summary.stop_reason())
            .field("received_packets", &self.summary.received_packets())
            .field("received_bytes", &self.summary.received_bytes())
            .field("capture_loss", &self.summary.capture_loss())
            .finish_non_exhaustive()
    }
}

impl HsrpReport {
    /// Classify the observed claims without treating silence as absence
    #[must_use]
    pub fn status(&self) -> HsrpStatus {
        if self
            .observations
            .iter()
            .any(|item| matches!(item.evidence, HsrpEvidence::Advertisement(_)))
        {
            HsrpStatus::Observed
        } else {
            HsrpStatus::Inconclusive
        }
    }

    /// Borrow scoped candidates in capture order, including repeated packets
    #[must_use]
    pub fn observations(&self) -> &[HsrpObservation] {
        &self.observations
    }

    /// Count complete scoped frames outside the selected HSRP profile
    #[must_use]
    pub const fn unmatched_packets(&self) -> u32 {
        self.unmatched_packets
    }

    /// Borrow capture quality and termination details
    ///
    /// Backend error strings in the returned summary are untrusted and may be sensitive
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
