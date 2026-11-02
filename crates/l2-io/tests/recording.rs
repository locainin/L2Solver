use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_io::{
    CaptureGap, FakeLink, FrameRecorder, LinkEvent, LinkIo, QueueError, RecordingError,
    RecordingLink,
};
use std::{error::Error, fmt};

fn frame(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    Ok(CapturedFrame::new(
        bytes.to_vec(),
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            u32::try_from(bytes.len())?,
        ),
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecorderFailure {
    Rejected,
}

impl fmt::Display for RecorderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test recorder rejected frame")
    }
}

impl Error for RecorderFailure {}

#[derive(Debug, Default)]
struct TestRecorder {
    packets: Vec<Vec<u8>>,
    reject_after: Option<usize>,
}

impl FrameRecorder for TestRecorder {
    type Error = RecorderFailure;

    fn record(&mut self, frame: &CapturedFrame) -> Result<(), Self::Error> {
        if self
            .reject_after
            .is_some_and(|accepted| self.packets.len() >= accepted)
        {
            return Err(RecorderFailure::Rejected);
        }
        self.packets.push(frame.bytes().to_vec());
        Ok(())
    }
}

#[test]
fn records_frames_before_delivery() -> Result<(), Box<dyn Error>> {
    let mut source = FakeLink::with_capacity(4)?;
    source.push_rx(frame(&[1, 2])?)?;
    source.push_gap(3)?;
    source.push_rx(frame(&[4, 5])?)?;
    let mut link = RecordingLink::new(source, TestRecorder::default());

    assert!(matches!(link.next_event()?, Some(LinkEvent::Frame(_))));
    assert_eq!(link.recorder().packets, vec![vec![1, 2]]);
    assert_eq!(
        link.next_event()?,
        Some(LinkEvent::CaptureGap(CaptureGap { dropped: 3 }))
    );
    assert_eq!(link.recorder().packets, vec![vec![1, 2]]);
    assert!(matches!(link.next_event()?, Some(LinkEvent::Frame(_))));
    assert_eq!(link.recorder().packets, vec![vec![1, 2], vec![4, 5]]);
    assert!(link.next_event()?.is_none());
    Ok(())
}

#[test]
fn stops_delivery_after_recording_failure() -> Result<(), Box<dyn Error>> {
    let mut source = FakeLink::with_capacity(2)?;
    source.push_rx(frame(&[1])?)?;
    source.push_rx(frame(&[2])?)?;
    let recorder = TestRecorder {
        packets: Vec::new(),
        reject_after: Some(0),
    };
    let mut link = RecordingLink::new(source, recorder);

    assert!(matches!(
        link.next_event(),
        Err(RecordingError::Recorder(RecorderFailure::Rejected))
    ));
    assert!(matches!(link.next_event(), Err(RecordingError::Terminated)));
    assert!(link.is_terminated());
    assert_eq!(link.recorder().packets, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[derive(Debug)]
struct FailingSource;

impl LinkIo for FailingSource {
    type Error = QueueError;

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        Err(QueueError::Closed)
    }
}

#[test]
fn terminates_recording_on_source_failure() {
    let mut link = RecordingLink::new(FailingSource, TestRecorder::default());

    assert!(matches!(
        link.next_event(),
        Err(RecordingError::Source(QueueError::Closed))
    ));
    assert!(matches!(link.next_event(), Err(RecordingError::Terminated)));
    assert!(link.is_terminated());
}

#[test]
fn records_before_frame_delivery() -> Result<(), Box<dyn Error>> {
    let mut source = FakeLink::with_capacity(1)?;
    source.push_rx(frame(&[9, 8, 7])?)?;
    let mut link = RecordingLink::new(source, TestRecorder::default());

    let received = link.recv()?.ok_or("missing recorded frame")?;
    assert_eq!(received.bytes(), [9, 8, 7]);
    assert_eq!(link.recorder().packets, vec![vec![9, 8, 7]]);
    assert!(link.recv()?.is_none());
    Ok(())
}

#[test]
fn recording_errors_source_context() {
    let source = RecordingError::<QueueError, RecorderFailure>::Source(QueueError::Closed);
    let recorder =
        RecordingError::<QueueError, RecorderFailure>::Recorder(RecorderFailure::Rejected);
    let terminated = RecordingError::<QueueError, RecorderFailure>::Terminated;

    assert_eq!(
        source.to_string(),
        "capture source failed: receive source is shut down"
    );
    assert_eq!(
        recorder.to_string(),
        "evidence recorder failed: test recorder rejected frame"
    );
    assert_eq!(
        terminated.to_string(),
        "recording link is terminal after a failure"
    );
    assert!(std::error::Error::source(&source).is_some());
    assert!(std::error::Error::source(&recorder).is_some());
    assert!(std::error::Error::source(&terminated).is_none());
}

#[test]
fn new_recording_links_start_nonterminal() {
    let link = RecordingLink::new(FakeLink::default(), TestRecorder::default());
    assert!(!link.is_terminated());
}
