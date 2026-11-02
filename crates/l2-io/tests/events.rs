use l2_capture::{CapturedFrame, InterfaceId};
use l2_io::{CaptureGap, FakeLink, LinkEvent, LinkIo, QueueError};
use std::error::Error;

fn frame(bytes: &[u8], original_len: usize) -> Result<CapturedFrame, Box<dyn Error>> {
    let metadata = l2_capture::CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        u32::try_from(original_len)?,
    );
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}

#[test]
fn fake_frames_eof() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(4)?;
    link.push_rx(frame(&[1, 2], 2)?)?;
    link.push_rx(frame(&[3, 4], 4)?)?;

    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(ref received)) if received.bytes() == [1, 2]
    ));
    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(ref received)) if received.bytes() == [3, 4]
    ));
    assert!(link.next_event()?.is_none());
    Ok(())
}

#[test]
fn preserves_control_shutdown_order() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(8)?;
    let interface = InterfaceId {
        section: 3,
        index: 7,
    };
    link.push_rx(frame(&[0xa5], 2)?)?;
    link.push_gap(14)?;
    link.push_interface_down(interface)?;
    link.push_interface_up(interface)?;
    link.push_shutdown()?;

    assert!(matches!(link.next_event()?, Some(LinkEvent::Frame(_))));
    assert_eq!(
        link.next_event()?,
        Some(LinkEvent::CaptureGap(CaptureGap { dropped: 14 }))
    );
    assert_eq!(
        link.next_event()?,
        Some(LinkEvent::InterfaceDown(interface))
    );
    assert_eq!(link.next_event()?, Some(LinkEvent::InterfaceUp(interface)));
    assert_eq!(link.next_event()?, Some(LinkEvent::Shutdown));
    assert!(link.next_event()?.is_none());
    assert_eq!(link.push_gap(1), Err(QueueError::Closed));
    Ok(())
}

#[test]
fn fake_zero_gaps_without_queue() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(1)?;
    assert_eq!(link.push_gap(0), Err(QueueError::InvalidGap));
    link.push_rx(frame(&[1], 1)?)?;
    assert_eq!(link.push_gap(0), Err(QueueError::InvalidGap));
    assert!(matches!(link.next_event()?, Some(LinkEvent::Frame(_))));
    assert!(link.next_event()?.is_none());
    Ok(())
}

#[test]
fn reuses_capacity_after_overflow() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(2)?;
    link.push_rx(frame(&[1], 1)?)?;
    link.push_rx(frame(&[2], 2)?)?;
    assert_eq!(link.pending_events(), 2);
    assert_eq!(link.push_rx(frame(&[3], 3)?), Err(QueueError::Full));

    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(ref received)) if received.bytes() == [1]
    ));
    link.push_rx(frame(&[3], 3)?)?;
    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(ref received)) if received.bytes() == [2]
    ));
    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(ref received)) if received.bytes() == [3]
    ));
    Ok(())
}

#[test]
fn preserves_duplicate_reordered_bytes() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(3)?;
    let duplicate = frame(&[9, 8, 7], 3)?;
    link.push_rx(duplicate.clone())?;
    link.push_rx(frame(&[1, 0], 2)?)?;
    link.push_rx(duplicate)?;

    let first = match link.next_event()? {
        Some(LinkEvent::Frame(frame)) => frame,
        other => return Err(format!("unexpected first event: {other:?}").into()),
    };
    let second = match link.next_event()? {
        Some(LinkEvent::Frame(frame)) => frame,
        other => return Err(format!("unexpected second event: {other:?}").into()),
    };
    let third = match link.next_event()? {
        Some(LinkEvent::Frame(frame)) => frame,
        other => return Err(format!("unexpected third event: {other:?}").into()),
    };
    assert_eq!(first.bytes(), third.bytes());
    assert_eq!(second.bytes(), [1, 0]);
    Ok(())
}

#[test]
fn preserves_out_of_band_events() -> Result<(), Box<dyn Error>> {
    let mut link = FakeLink::with_capacity(4)?;
    link.push_gap(1)?;
    link.push_interface_down(InterfaceId {
        section: 0,
        index: 0,
    })?;
    link.push_rx(frame(&[4, 2], 2)?)?;
    link.push_shutdown()?;

    assert_eq!(link.recv(), Err(QueueError::ControlEventRequiresEventApi));
    assert_eq!(
        link.next_event()?,
        Some(LinkEvent::CaptureGap(CaptureGap { dropped: 1 }))
    );
    assert_eq!(link.recv(), Err(QueueError::ControlEventRequiresEventApi));
    assert_eq!(
        link.next_event()?,
        Some(LinkEvent::InterfaceDown(InterfaceId {
            section: 0,
            index: 0
        }))
    );
    assert_eq!(
        link.recv()?.map(|packet| packet.bytes().to_vec()),
        Some(vec![4, 2])
    );
    assert!(link.recv()?.is_none());
    Ok(())
}

#[test]
fn invalid_capacity_shutdown_overflow_atomic() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        FakeLink::with_capacity(0),
        Err(QueueError::InvalidCapacity)
    ));
    assert!(matches!(
        FakeLink::with_capacity(l2_io::MAX_QUEUE_EVENTS + 1),
        Err(QueueError::InvalidCapacity)
    ));
    assert!(FakeLink::with_capacity(l2_io::MAX_QUEUE_EVENTS).is_ok());

    let mut link = FakeLink::with_capacity(1)?;
    link.push_rx(frame(&[0xaa], 1)?)?;
    assert_eq!(link.push_shutdown(), Err(QueueError::Full));
    assert!(!link.is_closed());
    assert_eq!(link.pending_events(), 1);
    assert!(matches!(
        link.next_event()?,
        Some(LinkEvent::Frame(frame)) if frame.bytes() == [0xaa]
    ));

    link.push_shutdown()?;
    assert!(link.is_closed());
    assert_eq!(link.next_event()?, Some(LinkEvent::Shutdown));
    assert_eq!(link.push_rx(frame(&[0xbb], 1)?), Err(QueueError::Closed));
    Ok(())
}

#[test]
fn queue_errors_include_actionable_text() {
    assert_ne!(QueueError::Full.to_string(), "");
    assert_ne!(QueueError::InvalidGap.to_string(), "");
    assert_ne!(QueueError::Closed.to_string(), "");
    assert_ne!(QueueError::ControlEventRequiresEventApi.to_string(), "");
    assert_ne!(QueueError::InvalidCapacity.to_string(), "");
}
