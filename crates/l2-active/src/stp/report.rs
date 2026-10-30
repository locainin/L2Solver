//! Exact observed BPDU candidates and capture quality

use l2_capture::CapturedFrame;
use l2_codecs::{StpError, StpFrame};
use l2_core::DecodeError;

use crate::RunSummary;

use super::wire;

/// Why a candidate could not be interpreted as a supported BPDU
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedStp {
    /// The Ethernet or declared 802.3 envelope was malformed
    Ethernet(DecodeError),
    /// The Ethernet source was not a nonzero unicast address
    SourceAddress,
    /// The STP LLC or BPDU fields were malformed
    Bpdu(StpError),
}

/// The interpretation supported by an observed candidate's exact bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StpEvidence {
    /// The baseline STP or RSTP decoder accepted this candidate
    Decoded,
    /// The candidate contained malformed fields
    Malformed(MalformedStp),
    /// A recognized version, type, or extension lies outside decoder support
    Unsupported(StpError),
}

/// One distinct candidate and its original capture metadata
#[derive(Debug)]
pub struct StpObservation {
    pub(super) frame: CapturedFrame,
    pub(super) evidence: StpEvidence,
}

impl StpObservation {
    /// Borrow the actual received bytes and their capture metadata
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }

    /// Return the parser classification without treating it as authentication
    #[must_use]
    pub const fn evidence(&self) -> StpEvidence {
        self.evidence
    }

    /// Decode the retained supported frame using the canonical STP decoder
    #[must_use]
    pub fn decoded(&self) -> Option<StpFrame<'_>> {
        if self.evidence != StpEvidence::Decoded {
            return None;
        }
        wire::decoded(&self.frame)
    }
}

/// Results of one receive-only, bounded spanning-tree observation window
#[derive(Debug)]
pub struct StpReport {
    pub(super) observations: Vec<StpObservation>,
    pub(super) unrelated_packets: u32,
    pub(super) summary: RunSummary,
}

impl StpReport {
    /// Borrow distinct candidate frames in collection order
    #[must_use]
    pub fn observations(&self) -> &[StpObservation] {
        &self.observations
    }

    /// Count scoped frames outside this STP envelope
    #[must_use]
    pub const fn unrelated_packets(&self) -> u32 {
        self.unrelated_packets
    }

    /// Return whether one sender, bridge, and port advertised different roots
    ///
    /// Frames are unauthenticated, so this compares claims rather than proving
    /// a topology change or identifying the cause
    #[must_use]
    pub fn has_sender_root_changes(&self) -> bool {
        for (index, current) in self.observations.iter().enumerate() {
            let Some(decoded) = current.decoded() else {
                continue;
            };
            let (Some(root), Some(bridge), Some(port)) =
                (decoded.root, decoded.bridge, decoded.port)
            else {
                continue;
            };
            let Some(source) = current.frame.bytes().get(6..12) else {
                continue;
            };
            // Other senders or bridge ports can legitimately advertise another root
            for prior in self.observations.iter().take(index) {
                if prior.frame.bytes().get(6..12) != Some(source) {
                    continue;
                }
                if prior.decoded().is_some_and(|previous| {
                    previous.bridge == Some(bridge)
                        && previous.port == Some(port)
                        && previous.root.is_some_and(|old_root| old_root != root)
                }) {
                    return true;
                }
            }
        }
        false
    }

    /// Borrow the common capture-quality and resource accounting
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
