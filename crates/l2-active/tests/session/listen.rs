use std::{
    error::Error,
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crate::{Limits, ReceiveEvent, StopReason};

mod support {
    use crate as l2_active;
    include!("../support/mod.rs");
}

fn limits(packets: u32, bytes: u64) -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(40), packets, bytes)?)
}

#[test]
fn listening_collects_actual_frames_without_send_or_presend_drain() -> Result<(), Box<dyn Error>> {
    let bytes = vec![7; 60];
    let frame = support::captured(bytes.clone(), Some(support::identity()?), 60)?;
    let mut link = support::Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    link.send_error = Some(io::ErrorKind::PermissionDenied);
    link.pre_send_error = Some(io::ErrorKind::PermissionDenied);
    let mut captured = Vec::new();
    let summary = super::run_listen_until(
        &mut link,
        limits(4, 1024)?,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(1),
        |frame| {
            captured.push(frame.bytes().to_vec());
            false
        },
    )?;
    assert_eq!(captured, vec![bytes]);
    assert!(link.sent_deadline.is_none());
    assert!(!summary.send_attempted());
    assert_eq!(summary.sent_packets(), 0);
    assert_eq!(summary.total_received_packets(), Some(1));
    assert_eq!(summary.total_received_bytes(), Some(60));
    assert_eq!(summary.capture_loss(), Some(0));
    assert_eq!(summary.capture_backlog(), Some(false));
    assert!(summary.accounting_error().is_none());
    assert_eq!(summary.stop_reason(), StopReason::Deadline);
    Ok(())
}

#[test]
fn listen_receive_failure_keeps_totals_unknown_and_preserves_quality_errors()
-> Result<(), Box<dyn Error>> {
    let mut link = support::Link::new(Vec::new(), None)?;
    link.receive_error = Some(io::ErrorKind::BrokenPipe);
    link.loss_error = Some(io::ErrorKind::Unsupported);
    link.backlog_error = Some(io::ErrorKind::PermissionDenied);
    let summary = super::run_listen_until(
        &mut link,
        limits(4, 1024)?,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(1),
        |_| false,
    )?;
    assert_eq!(summary.stop_reason(), StopReason::TransportError);
    assert_eq!(summary.total_received_packets(), None);
    assert_eq!(summary.total_received_bytes(), None);
    assert_eq!(
        summary.transport_error().map(io::Error::kind),
        Some(io::ErrorKind::BrokenPipe)
    );
    assert_eq!(
        summary.loss_error().map(io::Error::kind),
        Some(io::ErrorKind::Unsupported)
    );
    assert_eq!(
        summary.backlog_error().map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
fn expired_or_cancelled_listen_never_starts_collection() -> Result<(), Box<dyn Error>> {
    for (cancelled, expected) in [(false, StopReason::Deadline), (true, StopReason::Cancelled)] {
        let mut link = support::Link::new(Vec::new(), Some(0))?;
        let summary = super::run_listen_until(
            &mut link,
            limits(4, 1024)?,
            &AtomicBool::new(cancelled),
            Instant::now(),
            |_| false,
        )?;
        assert_eq!(summary.stop_reason(), expected);
        assert!(!summary.send_attempted());
        assert_eq!(summary.capture_loss(), None);
        assert_eq!(summary.capture_backlog(), None);
        assert_eq!(summary.total_received_packets(), Some(0));
    }
    Ok(())
}

#[test]
fn listening_charges_unrelated_frames_against_packet_limit() -> Result<(), Box<dyn Error>> {
    let outbound = support::captured_with_direction(
        vec![3; 60],
        Some(support::identity()?),
        60,
        l2_capture::Direction::Outbound,
    )?;
    let frame = support::captured(vec![4; 60], Some(support::identity()?), 60)?;
    let mut link = support::Link::new(
        vec![ReceiveEvent::Frame(outbound), ReceiveEvent::Frame(frame)],
        Some(0),
    )?;
    let mut accepted = 0;
    let summary = super::run_listen_until(
        &mut link,
        limits(1, 1024)?,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(1),
        |_| {
            accepted += 1;
            false
        },
    )?;
    assert_eq!(accepted, 0);
    assert_eq!(summary.outbound_packets(), 1);
    assert_eq!(summary.total_received_packets(), Some(1));
    assert_eq!(summary.stop_reason(), StopReason::PacketLimit);
    Ok(())
}
