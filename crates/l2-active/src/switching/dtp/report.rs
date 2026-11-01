//! Source-backed DTP claims and safe diagnostic formatting

use std::fmt;

use l2_capture::CapturedFrame;

use crate::RunSummary;

/// Operating status claimed in one DTP status byte
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DtpOperatingStatus {
    /// The sender claims access operation
    Access,
    /// The sender claims trunk operation
    Trunk,
}

/// Administrative status claimed in one DTP status byte
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DtpAdministrativeStatus {
    /// The sender claims an administratively on setting
    On,
    /// The sender claims an administratively off setting
    Off,
    /// The sender claims a desirable setting
    Desirable,
    /// The sender claims an automatic setting
    Auto,
    /// An unrecognized value remains visible
    Other(u8),
}

/// One advertised trunk status byte, without independently verifying the link
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DtpStatus(pub(super) u8);

impl DtpStatus {
    /// Return the complete advertised status byte, including reserved bits
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Decode the sender's claimed operating status
    #[must_use]
    pub const fn operating(self) -> DtpOperatingStatus {
        if self.0 & 0x80 == 0 {
            DtpOperatingStatus::Access
        } else {
            DtpOperatingStatus::Trunk
        }
    }

    /// Decode the sender's claimed administrative status
    #[must_use]
    pub const fn administrative(self) -> DtpAdministrativeStatus {
        match self.0 & 7 {
            1 => DtpAdministrativeStatus::On,
            2 => DtpAdministrativeStatus::Off,
            3 => DtpAdministrativeStatus::Desirable,
            4 => DtpAdministrativeStatus::Auto,
            value => DtpAdministrativeStatus::Other(value),
        }
    }
}

/// Encapsulation value claimed by the sender
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DtpTrunkEncapsulation {
    /// The sender claims a negotiated administrative type
    Negotiated,
    /// The sender claims native encapsulation
    Native,
    /// The sender claims ISL encapsulation
    Isl,
    /// The sender claims IEEE 802.1Q encapsulation
    Dot1q,
    /// An unrecognized value remains visible
    Other(u8),
}

/// One advertised trunk type byte, including the unrecognized bits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DtpTrunkType(pub(super) u8);

impl DtpTrunkType {
    /// Return the complete advertised type byte
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Decode the sender's claimed operating encapsulation
    #[must_use]
    pub const fn operating(self) -> DtpTrunkEncapsulation {
        match (self.0 & 0xe0) >> 5 {
            1 => DtpTrunkEncapsulation::Native,
            2 => DtpTrunkEncapsulation::Isl,
            5 => DtpTrunkEncapsulation::Dot1q,
            value => DtpTrunkEncapsulation::Other(value),
        }
    }

    /// Decode the sender's claimed administrative encapsulation
    #[must_use]
    pub const fn administrative(self) -> DtpTrunkEncapsulation {
        match self.0 & 7 {
            0 => DtpTrunkEncapsulation::Negotiated,
            1 => DtpTrunkEncapsulation::Native,
            2 => DtpTrunkEncapsulation::Isl,
            5 => DtpTrunkEncapsulation::Dot1q,
            value => DtpTrunkEncapsulation::Other(value),
        }
    }
}

/// Structurally checked version 1 fields advertised by one unauthenticated sender
pub struct DtpAdvertisement {
    pub(super) source: [u8; 6],
    pub(super) domain: Option<Vec<u8>>,
    pub(super) status: Option<DtpStatus>,
    pub(super) trunk_type: Option<DtpTrunkType>,
    pub(super) sender_id: Option<[u8; 6]>,
}

impl fmt::Debug for DtpAdvertisement {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("DtpAdvertisement")
            .field("source", &self.source)
            .field("domain_present", &self.domain.is_some())
            .field("status", &self.status)
            .field("trunk_type", &self.trunk_type)
            .field("sender_id", &self.sender_id)
            .finish_non_exhaustive()
    }
}

impl DtpAdvertisement {
    /// Return the Ethernet source captured with this claim
    #[must_use]
    pub const fn source_mac(&self) -> [u8; 6] {
        self.source
    }
    /// Borrow exact domain TLV bytes, including any terminating zero
    #[must_use]
    pub fn domain(&self) -> Option<&[u8]> {
        self.domain.as_deref()
    }
    /// Return the advertised status, if that TLV was present
    #[must_use]
    pub const fn status(&self) -> Option<DtpStatus> {
        self.status
    }
    /// Return the advertised trunk type, if that TLV was present
    #[must_use]
    pub const fn trunk_type(&self) -> Option<DtpTrunkType> {
        self.trunk_type
    }
    /// Return the advertised sender identifier, if that TLV was present
    #[must_use]
    pub const fn sender_id(&self) -> Option<[u8; 6]> {
        self.sender_id
    }
}

/// The layer that prevented a DTP candidate from becoming a structured claim
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DtpMalformed {
    /// The selected 802.3 length did not describe the captured payload
    Ethernet,
    /// The Ethernet source was not a nonzero unicast address
    SourceMac,
    /// A supported header or TLV violated structural checks
    Protocol,
}

/// Supported interpretation of one identifiable DTP candidate
#[derive(Debug)]
pub enum DtpEvidence {
    /// The version 1 header and present TLVs passed supported structural checks
    Advertisement(DtpAdvertisement),
    /// A recognizable candidate failed a structural check
    Malformed(DtpMalformed),
    /// The sender used a version outside the supported profile
    UnsupportedVersion(u8),
    /// The number of TLVs exceeded the local parsing budget
    LimitExceeded,
}

/// A scoped DTP candidate with its original frame retained privately
pub struct DtpObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: DtpEvidence,
}

impl fmt::Debug for DtpObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("DtpObservation")
            .field("evidence", &self.evidence)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl DtpObservation {
    /// Borrow the captured frame, including possibly sensitive domain and padding bytes
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
    /// Borrow the checked claim or reason it could not be decoded
    #[must_use]
    pub const fn evidence(&self) -> &DtpEvidence {
        &self.evidence
    }
}

/// Receive-only DTP observations with their capture quality
pub struct DtpReport {
    pub(super) observations: Vec<DtpObservation>,
    pub(super) unmatched_packets: u32,
    pub(super) summary: RunSummary,
}

// Transport diagnostics can contain sensitive or attacker-controlled bytes
impl fmt::Debug for DtpReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("DtpReport")
            .field("observations", &self.observations)
            .field("unmatched_packets", &self.unmatched_packets)
            .field("stop_reason", &self.summary.stop_reason())
            .field("received_packets", &self.summary.received_packets())
            .field("received_bytes", &self.summary.received_bytes())
            .field("capture_loss", &self.summary.capture_loss())
            .finish_non_exhaustive()
    }
}

impl DtpReport {
    /// Borrow scoped candidates in capture order
    #[must_use]
    pub fn observations(&self) -> &[DtpObservation] {
        &self.observations
    }
    /// Count complete frames outside the selected DTP profile
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
