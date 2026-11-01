//! ISL header claims and privacy-preserving diagnostics

use std::fmt;

use l2_capture::CapturedFrame;

use crate::RunSummary;

use super::wire::{HSA, LLC, SUFFIX_BYTES};

/// Structurally checked Ethernet ISL header fields from an unauthenticated frame
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IslHeader {
    pub(super) destination: [u8; 6],
    pub(super) source: [u8; 6],
    pub(super) length: u16,
    pub(super) vlan_bpdu: u16,
    pub(super) port_index: u16,
    pub(super) reserved: u16,
}

impl IslHeader {
    /// Return the captured 40-bit ISL destination prefix
    #[must_use]
    pub const fn destination_prefix(self) -> [u8; 5] {
        let [first, second, third, fourth, fifth, _] = self.destination;
        [first, second, third, fourth, fifth]
    }
    /// Return the outer source address as claimed by the sender
    #[must_use]
    pub const fn source_mac(self) -> [u8; 6] {
        self.source
    }
    /// Return the captured media type; this profile interprets Ethernet type zero
    #[must_use]
    pub const fn media_type(self) -> u8 {
        let [_, _, _, _, _, media_user] = self.destination;
        media_user >> 4
    }
    /// Return all four USER bits, including bits outside the priority field
    #[must_use]
    pub const fn user(self) -> u8 {
        let [_, _, _, _, _, media_user] = self.destination;
        media_user & 0x0f
    }
    /// Return the two Ethernet priority bits claimed in USER
    #[must_use]
    pub const fn priority(self) -> u8 {
        self.user() & 3
    }
    /// Return the declared size after the first 14 outer bytes, excluding outer FCS
    #[must_use]
    pub const fn declared_length(self) -> u16 {
        self.length
    }
    /// Return the checked LLC bytes present in the ISL header
    #[must_use]
    pub const fn llc(self) -> [u8; 3] {
        LLC
    }
    /// Return the checked high source address bytes present in the ISL header
    #[must_use]
    pub const fn hsa(self) -> [u8; 3] {
        HSA
    }
    /// Return the advertised 15-bit VLAN value, not a verified VLAN membership
    #[must_use]
    pub const fn vlan_id(self) -> u16 {
        self.vlan_bpdu >> 1
    }
    /// Return the sender's BPDU/CDP/VTP indicator without classifying inner traffic
    #[must_use]
    pub const fn bpdu(self) -> bool {
        self.vlan_bpdu & 1 != 0
    }
    /// Return the advertised switch port index without verifying the sender
    #[must_use]
    pub const fn port_index(self) -> u16 {
        self.port_index
    }
    /// Return the Ethernet reserved field exactly as received
    #[must_use]
    pub const fn reserved(self) -> u16 {
        self.reserved
    }
    /// Return declared inner bytes, including four bytes designated as an unverified FCS
    #[must_use]
    pub const fn inner_frame_length(self) -> usize {
        (self.length - SUFFIX_BYTES) as usize
    }
}

/// The layer that prevented a recognized ISL candidate from becoming a claim
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IslMalformed {
    /// The fixed header was incomplete or had unsupported LLC or HSA bytes
    Header,
    /// The source address was not a nonzero unicast MAC
    SourceMac,
    /// The declared envelope could not contain the supported inner frame
    Length,
    /// The bounded encapsulated Ethernet header or declared 802.3 length was invalid
    InnerEthernet,
}

/// Supported interpretation of one identifiable ISL candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IslEvidence {
    /// A supported Ethernet ISL envelope passed the stated structural checks
    Frame(IslHeader),
    /// The candidate failed a structural check
    Malformed(IslMalformed),
    /// The candidate encapsulates media outside the supported Ethernet profile
    UnsupportedMedia(u8),
    /// A zero length leaves the inner frame boundary unspecified
    UnsupportedLength,
    /// The declared inner frame exceeded the supported local byte budget
    LimitExceeded,
}

/// One scoped ISL candidate with the captured user traffic retained privately
pub struct IslObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: IslEvidence,
}

impl fmt::Debug for IslObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("IslObservation")
            .field("evidence", &self.evidence)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl IslObservation {
    /// Borrow the captured frame, which can contain arbitrary sensitive user traffic
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
    /// Borrow the header claim or the reason it was not interpreted
    #[must_use]
    pub const fn evidence(&self) -> &IslEvidence {
        &self.evidence
    }
}

/// What the collection window established about supported ISL frames
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IslStatus {
    /// At least one frame passed the supported structural checks
    Observed,
    /// No supported, structurally checked frame was observed
    Inconclusive,
}

/// Bounded ISL candidates and their collection quality
pub struct IslReport {
    pub(super) observations: Vec<IslObservation>,
    pub(super) unmatched_packets: u32,
    pub(super) summary: RunSummary,
}

// Transport error text can itself contain sensitive or attacker-controlled data
impl fmt::Debug for IslReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("IslReport")
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

impl IslReport {
    /// Classify observed claims without drawing conclusions from silence
    #[must_use]
    pub fn status(&self) -> IslStatus {
        if self
            .observations
            .iter()
            .any(|item| matches!(item.evidence, IslEvidence::Frame(_)))
        {
            IslStatus::Observed
        } else {
            IslStatus::Inconclusive
        }
    }
    /// Borrow scoped candidates in capture order, including repeated claims
    #[must_use]
    pub fn observations(&self) -> &[IslObservation] {
        &self.observations
    }
    /// Count complete frames outside the selected ISL prefix profile
    #[must_use]
    pub const fn unmatched_packets(&self) -> u32 {
        self.unmatched_packets
    }
    /// Borrow collection accounting, whose backend errors may contain sensitive text
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
