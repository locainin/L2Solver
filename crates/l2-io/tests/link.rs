use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};
use l2_io::{FakeLink, LinkEvent, LinkIo, QueueError};
use std::error::Error;

fn frame(bytes: &[u8], original_len: usize) -> Result<CapturedFrame, Box<dyn Error>> {
    Ok(CapturedFrame::new(
        bytes.to_vec(),
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            u32::try_from(original_len)?,
        ),
    )?)
}

#[test]
fn fake_legacy_frame_receive_method() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::default();
    link.push_rx(frame(&[1, 2], 2)?)?;
    link.push_rx(frame(&[3, 4], 4)?)?;

    assert_eq!(
        link.recv()?.map(|frame| frame.bytes().to_vec()),
        Some(vec![1, 2])
    );
    assert_eq!(
        link.recv()?.map(|frame| frame.bytes().to_vec()),
        Some(vec![3, 4])
    );
    assert!(link.recv()?.is_none());
    Ok(())
}

#[test]
fn replay_adapter_source_frames() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("../../../tests/pcaps/lldp.pcap");
    let mut link = l2_io::ReplayLink::new(bytes.as_slice())?;
    let frame = link.recv()?.ok_or("missing frame")?;
    assert_eq!(frame.captured_len(), 41);
    assert_eq!(frame.metadata().original_len(), 41);
    assert!(link.next_event()?.is_none());
    Ok(())
}

#[test]
fn preserves_event_frame_bytes() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(1)?;
    let original = frame(&[0xde, 0xad, 0xbe, 0xef], 4)?;
    link.push_rx(original.clone())?;
    let Some(LinkEvent::Frame(received)) = link.next_event()? else {
        return Err("missing frame event".into());
    };
    assert_eq!(received, original);
    assert_eq!(received.bytes(), [0xde, 0xad, 0xbe, 0xef]);
    Ok(())
}

#[derive(Debug)]
struct FrameOnlyLink {
    frame: Option<CapturedFrame>,
}

impl LinkIo for FrameOnlyLink {
    type Error = QueueError;

    fn recv(&mut self) -> Result<Option<CapturedFrame>, Self::Error> {
        Ok(self.frame.take())
    }
}

#[test]
fn adapts_frame_only_backend() -> Result<(), Box<dyn Error>> {
    let mut link = FrameOnlyLink {
        frame: Some(frame(&[0x11, 0x22], 2)?),
    };
    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(frame)) if frame.bytes() == [0x11, 0x22]
    ));
    assert!(link.next_event()?.is_none());
    Ok(())
}
