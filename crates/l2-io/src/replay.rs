//! Streaming replay preserves capture order without sleeping

use crate::{CapturedFrame, LinkIo};
use l2_pcap::{CaptureLimits, CaptureSource, Error};
use std::io::Read;

/// Adapter from a bounded capture source to the receive interface
pub struct ReplayLink<R: Read> {
    source: CaptureSource<R>,
}

impl<R: Read> ReplayLink<R> {
    /// Validate a capture header and prepare its first packet
    ///
    /// The source selects classic PCAP or PCAPNG from the first bytes and
    /// keeps source-specific interface and timestamp metadata on each frame
    ///
    /// # Errors
    /// Returns an error for unsupported or malformed capture headers
    pub fn new(reader: R) -> Result<Self, Error> {
        Ok(Self {
            source: CaptureSource::with_limits(reader, CaptureLimits::STREAMING)?,
        })
    }
}

impl<R: Read> LinkIo for ReplayLink<R> {
    type Error = Error;

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        self.source.next_packet()
    }

    fn collection_summary(&self) -> l2_pcap::CollectionSummary {
        self.source.collection_summary()
    }
}
