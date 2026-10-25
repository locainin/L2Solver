//! Fail-closed evidence recording for any receive-side link

use crate::{CapturedFrame, LinkEvent, LinkIo};
use std::{error::Error, fmt};

/// A sink that commits one validated frame to authoritative evidence storage
pub trait FrameRecorder {
    type Error: Error + Send + Sync + 'static;

    /// Commit one frame before it is released to an observation consumer
    ///
    /// # Errors
    /// Returns the sink failure when the complete frame cannot be retained
    fn record(&mut self, frame: &CapturedFrame) -> Result<(), Self::Error>;
}

/// A source or recorder failure from [`RecordingLink`]
#[derive(Debug)]
pub enum RecordingError<SourceError, RecorderError> {
    Source(SourceError),
    Recorder(RecorderError),
    Terminated,
}

impl<SourceError: fmt::Display, RecorderError: fmt::Display> fmt::Display
    for RecordingError<SourceError, RecorderError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "capture source failed: {error}"),
            Self::Recorder(error) => write!(formatter, "evidence recorder failed: {error}"),
            Self::Terminated => formatter.write_str("recording link is terminal after a failure"),
        }
    }
}

impl<SourceError, RecorderError> Error for RecordingError<SourceError, RecorderError>
where
    SourceError: Error + Send + Sync + 'static,
    RecorderError: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Recorder(error) => Some(error),
            Self::Terminated => None,
        }
    }
}

/// A receive source that never releases a frame before its evidence is committed
pub struct RecordingLink<Link, Recorder> {
    link: Link,
    recorder: Recorder,
    terminated: bool,
}

impl<Link, Recorder> RecordingLink<Link, Recorder> {
    /// Attach a recorder without reading or mutating the source
    pub const fn new(link: Link, recorder: Recorder) -> Self {
        Self {
            link,
            recorder,
            terminated: false,
        }
    }

    /// Return the recorder for counters and finalization
    #[must_use]
    pub const fn recorder(&self) -> &Recorder {
        &self.recorder
    }

    /// Report whether a source or recorder failure has made the wrapper terminal
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Recover both caller-owned components after the receive loop ends
    #[must_use]
    pub fn into_parts(self) -> (Link, Recorder) {
        (self.link, self.recorder)
    }
}

impl<Link, Recorder> RecordingLink<Link, Recorder>
where
    Link: LinkIo,
    Recorder: FrameRecorder,
{
    fn commit_frame(
        &mut self,
        frame: CapturedFrame,
    ) -> Result<CapturedFrame, RecordingError<Link::Error, Recorder::Error>> {
        if let Err(error) = self.recorder.record(&frame) {
            // The source event is already consumed, so retry cannot be lossless
            self.terminated = true;
            return Err(RecordingError::Recorder(error));
        }
        Ok(frame)
    }

    const fn source_failed(
        &mut self,
        error: Link::Error,
    ) -> RecordingError<Link::Error, Recorder::Error> {
        self.terminated = true;
        RecordingError::Source(error)
    }
}

impl<Link, Recorder> LinkIo for RecordingLink<Link, Recorder>
where
    Link: LinkIo,
    Recorder: FrameRecorder,
{
    type Error = RecordingError<Link::Error, Recorder::Error>;

    fn collection_summary(&self) -> l2_pcap::CollectionSummary {
        self.link.collection_summary()
    }

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        if self.terminated {
            return Err(RecordingError::Terminated);
        }
        match self.link.recv() {
            Ok(Some(frame)) => self.commit_frame(frame).map(Some),
            Ok(None) => Ok(None),
            Err(error) => Err(self.source_failed(error)),
        }
    }

    fn next_event(&mut self) -> Result<Option<LinkEvent>, Self::Error> {
        if self.terminated {
            return Err(RecordingError::Terminated);
        }
        match self.link.next_event() {
            Ok(Some(LinkEvent::Frame(frame))) => {
                self.commit_frame(frame).map(LinkEvent::Frame).map(Some)
            }
            Ok(event) => Ok(event),
            Err(error) => Err(self.source_failed(error)),
        }
    }
}
