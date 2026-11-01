//! Captured VRRP candidates and their bounded interpretation

use std::{fmt, net::Ipv4Addr, num::NonZeroU8, ops::Range};

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

/// What the receive window established about advertisements
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VrrpStatus {
    /// At least one structurally valid scoped advertisement was received
    Observed,
    /// No valid scoped advertisement was received
    Inconclusive,
}

/// A field group that prevents a candidate from being treated as an advertisement
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VrrpMalformed {
    /// The Ethernet source was not a nonzero unicast address
    SourceMac,
    /// The IPv4 header had invalid fields or length
    Ipv4Header,
    /// The IPv4 header checksum was invalid
    Ipv4Checksum,
    /// The IPv4 packet was fragmented
    Fragmented,
    /// The IPv4 TTL was not 255
    Ttl,
    /// The IPv4 source was not a usable unicast address
    SourceIp,
    /// The VRRP fixed fields or address count were invalid
    Header,
    /// The declared IPv4 packet or VRRP address list was incomplete
    Truncated,
    /// The RFC 9568 IPv4 VRRP checksum was invalid
    Checksum,
}

/// A bounded advertisement's unauthenticated wire claims
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VrrpAdvertisement {
    pub(super) source_ip: Ipv4Addr,
    pub(super) source_mac: MacAddress,
    pub(super) vrid: NonZeroU8,
    pub(super) priority: u8,
    pub(super) interval_centiseconds: u16,
    pub(super) addresses: Range<usize>,
    pub(super) trailing_ip_bytes: usize,
}

impl VrrpAdvertisement {
    /// Return the unauthenticated IPv4 source claim
    #[must_use]
    pub const fn source_ip(&self) -> Ipv4Addr {
        self.source_ip
    }

    /// Return the observed Ethernet source, normally the virtual router MAC
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.source_mac
    }

    /// Return the advertised virtual router identifier
    #[must_use]
    pub const fn vrid(&self) -> NonZeroU8 {
        self.vrid
    }

    /// Return the advertised priority; zero indicates relinquishment
    #[must_use]
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Return the advertised interval in centiseconds
    #[must_use]
    pub const fn interval_centiseconds(&self) -> u16 {
        self.interval_centiseconds
    }

    /// Return whether the sender used the RFC virtual MAC for this VRID
    ///
    /// A matching source can be forged and does not identify a physical router
    #[must_use]
    pub fn source_matches_virtual_mac(&self) -> bool {
        self.source_mac.bytes() == [0, 0, 0x5e, 0, 1, self.vrid.get()]
    }

    /// Return IP payload bytes beyond the checksummed VRRP message
    #[must_use]
    pub const fn trailing_ip_bytes(&self) -> usize {
        self.trailing_ip_bytes
    }
}

/// Protocol interpretation of one recognizable candidate
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VrrpEvidence {
    /// An IPv4 `VRRPv3` advertisement met the supported structural checks
    Advertisement(VrrpAdvertisement),
    /// A recognizable candidate failed validation
    Malformed(VrrpMalformed),
    /// A recognized VRRP version is outside this monitor's supported profile
    UnsupportedVersion(u8),
}

/// One received candidate with original bytes and capture provenance
pub struct VrrpObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: VrrpEvidence,
}

impl fmt::Debug for VrrpObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VrrpObservation")
            .field("evidence", &self.evidence)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl VrrpObservation {
    /// Borrow the actual captured frame, including any unverified padding
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }

    /// Borrow the candidate's interpretation
    #[must_use]
    pub const fn evidence(&self) -> &VrrpEvidence {
        &self.evidence
    }

    /// Iterate over the advertised IPv4 addresses without copying the frame
    #[must_use]
    pub fn addresses(&self) -> Option<impl Iterator<Item = Ipv4Addr> + '_> {
        let VrrpEvidence::Advertisement(advertisement) = &self.evidence else {
            return None;
        };
        let bytes = self.frame.bytes().get(advertisement.addresses.clone())?;
        let (addresses, _) = bytes.as_chunks::<4>();
        Some(addresses.iter().copied().map(Ipv4Addr::from))
    }
}

/// Receive-only evidence and collection-quality accounting
///
/// Advertisements are unauthenticated claims. They cannot prove current
/// forwarding, a failover, or the identity of the sending device
pub struct VrrpReport {
    pub(super) observations: Vec<VrrpObservation>,
    pub(super) unrelated_packets: u32,
    pub(super) summary: RunSummary,
}

// Backend errors may include attacker-controlled or sensitive text
impl fmt::Debug for VrrpReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("VrrpReport")
            .field("status", &self.status())
            .field("observations", &self.observations)
            .field("unrelated_packets", &self.unrelated_packets)
            .field("stop_reason", &self.summary.stop_reason())
            .field("received_packets", &self.summary.received_packets())
            .field("received_bytes", &self.summary.received_bytes())
            .field("capture_loss", &self.summary.capture_loss())
            .field("capture_backlog", &self.summary.capture_backlog())
            .finish_non_exhaustive()
    }
}

impl VrrpReport {
    /// Classify observations without treating silence as evidence of absence
    #[must_use]
    pub fn status(&self) -> VrrpStatus {
        if self
            .observations
            .iter()
            .any(|item| matches!(item.evidence, VrrpEvidence::Advertisement(_)))
        {
            VrrpStatus::Observed
        } else {
            VrrpStatus::Inconclusive
        }
    }

    /// Borrow scoped candidates in capture order, including repeated packets
    #[must_use]
    pub fn observations(&self) -> &[VrrpObservation] {
        &self.observations
    }

    /// Count complete scoped frames that do not match the selected candidate scope
    #[must_use]
    pub const fn unrelated_packets(&self) -> u32 {
        self.unrelated_packets
    }

    /// Borrow capture, transport, and termination accounting
    ///
    /// Backend error strings in the returned summary are untrusted and may be sensitive
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
