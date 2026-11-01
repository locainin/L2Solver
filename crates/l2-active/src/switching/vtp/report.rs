//! Source-backed VTP claims and safe diagnostic formatting

use std::{fmt, net::Ipv4Addr};

use l2_capture::CapturedFrame;

use crate::RunSummary;

/// One structurally checked VLAN record advertised in a subset message
pub struct VtpVlan {
    pub(super) id: u16,
    pub(super) status: u8,
    pub(super) vlan_type: u8,
    pub(super) mtu: u16,
    pub(super) said: u32,
    pub(super) name: Vec<u8>,
}

impl fmt::Debug for VtpVlan {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VtpVlan")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("vlan_type", &self.vlan_type)
            .field("mtu", &self.mtu)
            .field("said", &self.said)
            .field("name_len", &self.name.len())
            .finish_non_exhaustive()
    }
}

impl VtpVlan {
    /// Return the advertised ISL VLAN identifier without asserting its use
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }
    /// Return the complete advertised VLAN status byte
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }
    /// Return the advertised media type byte
    #[must_use]
    pub const fn vlan_type(&self) -> u8 {
        self.vlan_type
    }
    /// Return the advertised maximum transmission unit
    #[must_use]
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }
    /// Return the advertised 802.10 security association identifier
    #[must_use]
    pub const fn said(&self) -> u32 {
        self.said
    }
    /// Borrow the exact VLAN name bytes, excluding alignment padding
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
}

/// Supported version 1 and 2 VTP message fields
#[derive(Debug)]
pub enum VtpMessageKind {
    /// Fixed summary fields; extensions and the digest are not validated
    Summary {
        /// Advertised configuration revision
        revision: u32,
        /// Advertised count of following subset messages
        followers: u8,
        /// Claimed address of the updater, which is not sender authentication
        updater: Ipv4Addr,
    },
    /// One subset message, which may be only part of a VLAN database
    Subset {
        /// Advertised configuration revision
        revision: u32,
        /// Claimed sequence number among subset messages
        sequence: u8,
        /// VLAN records present in this one message
        vlans: Vec<VtpVlan>,
    },
    /// An advertisement request, not a database response
    Request {
        /// Advertised requested starting value
        start_value: u16,
    },
}

/// One unauthenticated version 1 or 2 VTP message's supported fields
pub struct VtpMessage {
    pub(super) source: [u8; 6],
    pub(super) version: u8,
    pub(super) domain: Vec<u8>,
    pub(super) kind: VtpMessageKind,
}

impl fmt::Debug for VtpMessage {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VtpMessage")
            .field("source", &self.source)
            .field("version", &self.version)
            .field("domain_len", &self.domain.len())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl VtpMessage {
    /// Return the Ethernet source captured with the message
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source
    }
    /// Return the advertised version supported by this parser
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }
    /// Borrow the declared management domain bytes, excluding fixed-field padding
    #[must_use]
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }
    /// Borrow the supported fields carried by this message
    #[must_use]
    pub const fn kind(&self) -> &VtpMessageKind {
        &self.kind
    }
}

/// The layer that prevented a VTP candidate from becoming a structured claim
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtpMalformed {
    /// The selected 802.3 length did not describe the captured payload
    Ethernet,
    /// The Ethernet source was not a nonzero unicast address
    SourceMac,
    /// A supported header, VLAN record, or nested TLV failed structural checks
    Protocol,
}

/// Supported interpretation of one identifiable VTP candidate
#[derive(Debug)]
pub enum VtpEvidence {
    /// Supported fields passed the documented structural checks
    Message(VtpMessage),
    /// A recognizable candidate failed a structural check
    Malformed(VtpMalformed),
    /// The sender used a version outside the supported profile
    UnsupportedVersion(u8),
    /// The message code is outside the supported profile
    UnsupportedMessage(u8),
    /// The records or nested TLVs exceeded the local parsing budget
    LimitExceeded,
}

/// A scoped VTP candidate with its original frame retained privately
pub struct VtpObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: VtpEvidence,
}

impl fmt::Debug for VtpObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VtpObservation")
            .field("evidence", &self.evidence)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl VtpObservation {
    /// Borrow the captured frame, including domain, digest, and padding bytes
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
    /// Borrow the checked fields or reason they could not be decoded
    #[must_use]
    pub const fn evidence(&self) -> &VtpEvidence {
        &self.evidence
    }
}

/// Receive-only VTP observations with their capture quality
pub struct VtpReport {
    pub(super) observations: Vec<VtpObservation>,
    pub(super) unmatched_packets: u32,
    pub(super) summary: RunSummary,
}

// Backend error strings can contain sensitive or attacker-controlled bytes
impl fmt::Debug for VtpReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VtpReport")
            .field("observations", &self.observations)
            .field("unmatched_packets", &self.unmatched_packets)
            .field("stop_reason", &self.summary.stop_reason())
            .field("received_packets", &self.summary.received_packets())
            .field("received_bytes", &self.summary.received_bytes())
            .field("capture_loss", &self.summary.capture_loss())
            .finish_non_exhaustive()
    }
}

impl VtpReport {
    /// Borrow scoped candidates in capture order
    #[must_use]
    pub fn observations(&self) -> &[VtpObservation] {
        &self.observations
    }
    /// Count complete frames outside the selected VTP profile
    #[must_use]
    pub const fn unmatched_packets(&self) -> u32 {
        self.unmatched_packets
    }
    /// Borrow termination and capture quality, whose backend errors may be sensitive
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
