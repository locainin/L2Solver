use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::{
    ReceiveEvent, StopReason,
    switching::{dtp::DtpMonitor, vtp::VtpMonitor},
};

use crate::{
    fixture,
    support::{Link, captured},
};

#[test]
fn filters_scope_and_accounts_unrelated_truncated_and_unscoped_frames() -> Result<(), Box<dyn Error>>
{
    let wrong_destination = fixture::change(fixture::DTP, 5, 0xcd)?;
    let wrong_pid = fixture::change(fixture::DTP, 21, 3)?;
    let truncated = captured(
        fixture::DTP.to_vec(),
        Some(crate::support::identity()?),
        u32::try_from(fixture::DTP.len() + 1)?,
    )?;
    let unscoped = captured(
        fixture::DTP.to_vec(),
        None,
        u32::try_from(fixture::DTP.len())?,
    )?;
    let mut link = Link::new(
        vec![
            fixture::event(&wrong_destination)?,
            fixture::event(&wrong_pid)?,
            ReceiveEvent::Frame(truncated),
            ReceiveEvent::Frame(unscoped),
            fixture::event(fixture::DTP)?,
        ],
        Some(0),
    )?;
    let report =
        DtpMonitor::new(fixture::limits(5, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.unmatched_packets(), 2);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.observations().len(), 1);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn cancellation_deadline_and_transport_failure_never_transmit() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![fixture::event(fixture::SUMMARY)?], None)?;
    let monitor = VtpMonitor::new(fixture::limits(8, 4096)?);
    let cancelled = monitor.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(cancelled.summary().stop_reason(), StopReason::Cancelled);
    assert!(cancelled.observations().is_empty());
    let deadline = monitor.run_until(&mut link, &AtomicBool::new(false), Instant::now())?;
    assert_eq!(deadline.summary().stop_reason(), StopReason::Deadline);
    let mut broken = Link::new(vec![], None)?;
    broken.receive_error = Some(std::io::ErrorKind::BrokenPipe);
    let report = monitor.run(&mut broken, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert!(report.observations().is_empty());
    assert!(link.sent.is_empty() && broken.sent.is_empty());
    Ok(())
}

#[test]
fn tagged_and_non_cisco_snap_frames_are_outside_the_selected_profile() -> Result<(), Box<dyn Error>>
{
    let mut tagged = fixture::DTP
        .get(..12)
        .ok_or("missing Ethernet addresses")?
        .to_vec();
    tagged.extend_from_slice(&[0x81, 0x00, 0x00, 0x25]);
    tagged.extend_from_slice(fixture::DTP.get(12..).ok_or("missing Ethernet payload")?);
    let other_oui = fixture::change(fixture::DTP, 19, 1)?;
    let mut link = Link::new(
        vec![fixture::event(&tagged)?, fixture::event(&other_oui)?],
        Some(0),
    )?;
    let report =
        DtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.unmatched_packets(), 2);
    assert!(report.observations().is_empty());
    Ok(())
}

#[test]
fn observation_limit_stops_before_retaining_unbounded_evidence() -> Result<(), Box<dyn Error>> {
    let events = (0..65)
        .map(|_| fixture::event(fixture::SUMMARY))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        VtpMonitor::new(fixture::limits(70, 20_000)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    Ok(())
}

#[test]
fn dtp_observation_limit_stops_before_retaining_unbounded_evidence() -> Result<(), Box<dyn Error>> {
    let events = (0..65)
        .map(|_| fixture::event(fixture::DTP))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        DtpMonitor::new(fixture::limits(70, 20_000)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    Ok(())
}

#[test]
fn observed_message_retains_loss_and_interface_failure_qualification() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(
        vec![
            fixture::event(fixture::SUMMARY)?,
            ReceiveEvent::InterfaceDown,
        ],
        Some(3),
    )?;
    link.backlog = Some(true);
    let report =
        VtpMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().stop_reason(), StopReason::InterfaceDown);
    assert_eq!(report.summary().capture_loss(), Some(3));
    assert_eq!(report.summary().capture_backlog(), Some(true));
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing frame")?
            .frame()
            .metadata()
            .linux_interface(),
        Some(crate::support::identity()?)
    );
    assert!(link.sent.is_empty());
    Ok(())
}
