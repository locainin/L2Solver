//! Receive-only links for deterministic, unprivileged capture inspection

#![forbid(unsafe_code)]

mod fake;
mod pcapng_recorder;
mod recording;
mod replay;

pub use fake::{FakeLink, MAX_QUEUE_EVENTS, QueueError};
pub use l2_capture::CapturedFrame;
pub use l2_capture::CapturedFrame as Packet;
pub use l2_capture::LinkType;
pub use pcapng_recorder::PcapNgRecorder;
pub use recording::{FrameRecorder, RecordingError, RecordingLink};
pub use replay::ReplayLink;

/// A positive count of packets absent from a capture stream
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureGap {
    /// Number of packets reported missing by the source
    pub dropped: u64,
}

/// An input item from a receive-only link
///
/// Control items are kept separate from frames so a consumer can report
/// capture loss and interface transitions without fabricating packets
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkEvent {
    /// One frame with its original capture metadata
    Frame(CapturedFrame),
    /// A source-reported packet loss interval
    CaptureGap(CaptureGap),
    /// The selected interface became unavailable
    InterfaceDown(l2_capture::InterfaceId),
    /// The selected interface became available again
    InterfaceUp(l2_capture::InterfaceId),
    /// The source was closed before normal end of input
    Shutdown,
}

/// A source of captured frames and optional receive-side events
pub trait LinkIo {
    /// Backend failures remain distinct from malformed packet contents
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read one frame, returning `None` at the end of the source
    ///
    /// # Errors
    /// Returns the backend error when reading or validating a capture fails
    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error>;

    /// Return source collection declarations observed so far
    ///
    /// Read through end of input before using this summary for a full-source result
    fn collection_summary(&self) -> l2_pcap::CollectionSummary {
        l2_pcap::CollectionSummary::default()
    }

    /// Read the next frame or receive-side control event
    ///
    /// Backends that only expose frames inherit this adapter. Event-aware
    /// backends override it so callers can preserve gaps and link transitions
    /// in their evidence stream
    ///
    /// # Errors
    /// Returns the backend error when reading or validating the source
    fn next_event(&mut self) -> Result<Option<LinkEvent>, Self::Error> {
        self.recv().map(|frame| frame.map(LinkEvent::Frame))
    }
}
