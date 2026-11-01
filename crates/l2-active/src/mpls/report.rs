//! Bounded MPLS evidence and capture-quality accounting

use std::fmt;

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

use super::wire::{ETHERNET_HEADER, LABEL_BYTES};

/// What the receive window established about supported label stacks
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MplsStatus {
    /// At least one supported stack was received
    Observed,
    /// No supported stack was received
    Inconclusive,
}

/// A recognizable candidate that failed basic stack checks
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MplsMalformed {
    /// The Ethernet source was not a nonzero unicast MAC
    SourceMac,
    /// The captured bytes ended before a bottom-of-stack entry
    TruncatedStack,
    /// No captured byte follows the bottom-of-stack entry
    MissingPayload,
    /// A supported special-purpose label had an invalid position or value
    SpecialPurposeLabel,
}

/// A recognizable stack outside this monitor's supported profile
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MplsUnsupported {
    /// The stack had no bottom bit within the limit and more bytes were captured
    StackDepthLimit,
    /// A special-purpose label requires semantics not decoded by this profile
    SpecialPurposeLabel(u32),
}

/// The bounded interpretation of one scoped candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MplsEvidence {
    /// A basic stack ended within the supported depth and had trailing bytes
    Stack,
    /// A recognizable candidate failed basic stack checks
    Malformed(MplsMalformed),
    /// A recognizable candidate needs a different or deeper parser
    Unsupported(MplsUnsupported),
}

/// Four wire fields interpreted under the basic MPLS label-stack profile
///
/// Operator-defined indicators can make later words carry other data without
/// a recognizable reserved value, so these fields do not prove their role
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MplsLabel {
    value: u32,
    traffic_class: u8,
    bottom_of_stack: bool,
    ttl: u8,
}

impl MplsLabel {
    pub(super) const fn from_bytes([first, second, third, ttl]: [u8; 4]) -> Self {
        Self {
            value: (first as u32) << 12 | (second as u32) << 4 | (third as u32) >> 4,
            traffic_class: (third >> 1) & 7,
            bottom_of_stack: third & 1 != 0,
            ttl,
        }
    }

    /// Return the 20-bit label value
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Return the three-bit traffic-class field
    #[must_use]
    pub const fn traffic_class(self) -> u8 {
        self.traffic_class
    }

    /// Return whether this entry carries the bottom-of-stack bit
    #[must_use]
    pub const fn bottom_of_stack(self) -> bool {
        self.bottom_of_stack
    }

    /// Return the encoded time-to-live field
    #[must_use]
    pub const fn ttl(self) -> u8 {
        self.ttl
    }
}

/// One scoped frame and its bounded label-stack interpretation
pub struct MplsObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: MplsEvidence,
    pub(super) label_count: usize,
}

impl fmt::Debug for MplsObservation {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("MplsObservation")
            .field("evidence", &self.evidence)
            .field("label_count", &self.label_count)
            .field("captured_len", &self.frame.captured_len())
            .finish_non_exhaustive()
    }
}

impl MplsObservation {
    /// Borrow original capture bytes, including opaque payload and padding
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }

    /// Return the evidence classification
    #[must_use]
    pub const fn evidence(&self) -> MplsEvidence {
        self.evidence
    }

    /// Return a usable Ethernet source, if the captured value was unicast
    #[must_use]
    pub fn source_mac(&self) -> Option<MacAddress> {
        let bytes = self.frame.bytes().get(6..12)?.try_into().ok()?;
        MacAddress::new(bytes).ok()
    }

    /// Iterate over the bounded prefix interpreted as basic entries, in wire order
    ///
    /// An unsupported special-purpose indicator is the final entry returned;
    /// any following words are intentionally not interpreted as labels. Custom
    /// indicators are not recognizable without external configuration
    pub fn labels(&self) -> impl Iterator<Item = MplsLabel> + '_ {
        let payload = self
            .frame
            .bytes()
            .get(ETHERNET_HEADER..)
            .unwrap_or_default();
        let (entries, _) = payload.as_chunks::<LABEL_BYTES>();
        entries
            .iter()
            .take(self.label_count)
            .copied()
            .map(MplsLabel::from_bytes)
    }

    /// Report the captured byte count after a complete supported stack
    ///
    /// This count may include Ethernet padding or an FCS and does not identify
    /// or expose the inner payload
    #[must_use]
    pub fn captured_bytes_after_stack(&self) -> Option<usize> {
        if self.evidence != MplsEvidence::Stack {
            return None;
        }
        self.frame
            .captured_len()
            .checked_sub(ETHERNET_HEADER + self.label_count * LABEL_BYTES)
    }

    /// Return whether the decoded top entry has a zero TTL field
    ///
    /// This is a wire observation, not a forwarding or path verdict
    #[must_use]
    pub fn top_ttl_is_zero(&self) -> bool {
        self.labels().next().is_some_and(|label| label.ttl() == 0)
    }
}

/// Receive-only MPLS evidence and capture-quality accounting
pub struct MplsReport {
    pub(super) observations: Vec<MplsObservation>,
    pub(super) unrelated_packets: u32,
    pub(super) expected_top_label: Option<u32>,
    pub(super) summary: RunSummary,
}

// Backend errors may include attacker-controlled or sensitive text
impl fmt::Debug for MplsReport {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("MplsReport")
            .field("status", &self.status())
            .field("observations", &self.observations)
            .field("unrelated_packets", &self.unrelated_packets)
            .field("expected_top_label", &self.expected_top_label)
            .field("stop_reason", &self.summary.stop_reason())
            .field("received_packets", &self.summary.received_packets())
            .field("received_bytes", &self.summary.received_bytes())
            .field("capture_loss", &self.summary.capture_loss())
            .field("capture_backlog", &self.summary.capture_backlog())
            .finish_non_exhaustive()
    }
}

impl MplsReport {
    /// Classify the window without treating silence as evidence of absence
    #[must_use]
    pub fn status(&self) -> MplsStatus {
        if self
            .observations
            .iter()
            .any(|item| item.evidence == MplsEvidence::Stack)
        {
            MplsStatus::Observed
        } else {
            MplsStatus::Inconclusive
        }
    }

    /// Borrow candidates in capture order, including repeated packets
    #[must_use]
    pub fn observations(&self) -> &[MplsObservation] {
        &self.observations
    }

    /// Count complete scoped frames outside the selected MPLS envelope
    #[must_use]
    pub const fn unrelated_packets(&self) -> u32 {
        self.unrelated_packets
    }

    /// Return the optional expected top-label value
    #[must_use]
    pub const fn expected_top_label(&self) -> Option<u32> {
        self.expected_top_label
    }

    /// Report whether a supported stack had a different top label
    ///
    /// Returns false if no expectation or no supported stack was observed
    #[must_use]
    pub fn has_unexpected_top_label(&self) -> bool {
        let Some(expected) = self.expected_top_label else {
            return false;
        };
        self.observations.iter().any(|item| {
            item.evidence == MplsEvidence::Stack
                && item
                    .labels()
                    .next()
                    .is_some_and(|label| label.value() != expected)
        })
    }

    /// Borrow capture quality, transport, and termination accounting
    ///
    /// Backend error strings in the returned summary are untrusted and may be sensitive
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
