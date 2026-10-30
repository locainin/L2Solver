use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::discovery::{
    DiscoveryDisposition, DiscoveryMonitor, DiscoveryProtocol, DiscoveryStatus, MAX_OBSERVATIONS,
};
use l2_active::{ReceiveEvent, StopReason};

use crate::fixture::{CDP, DEVICE, PORT, event, limits, lldp};
use crate::support::{Link, captured, identity};

#[test]
fn observes_actual_lldp_and_cdp_claims_without_any_send() -> Result<(), Box<dyn Error>> {
    let bytes = lldp(120, 0x0e)?;
    let mut link = Link::new(vec![event(bytes.clone())?, event(CDP.to_vec())?], Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Observed);
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(link.sent.is_empty());
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().capture_loss(), Some(0));
    assert_eq!(report.summary().capture_backlog(), Some(false));
    let lldp = report
        .observations()
        .first()
        .ok_or("missing LLDP observation")?;
    assert_eq!(lldp.protocol(), DiscoveryProtocol::Lldp);
    assert_eq!(lldp.disposition(), DiscoveryDisposition::Advertisement);
    assert_eq!(lldp.hold_seconds(), Some(120));
    let id = lldp.identity().ok_or("missing LLDP identity")?;
    assert_eq!((id.device(), id.port()), (DEVICE, PORT));
    assert_eq!(lldp.frame().bytes(), bytes);
    assert_eq!(lldp.frame().metadata().linux_interface(), Some(identity()?));
    let cdp = report
        .observations()
        .get(1)
        .ok_or("missing CDP observation")?;
    assert_eq!(cdp.protocol(), DiscoveryProtocol::Cdp);
    assert_eq!(
        cdp.identity()
            .map(l2_active::discovery::DiscoveryIdentity::device),
        Some(b"switch-a".as_slice())
    );
    assert_eq!(
        cdp.identity()
            .map(l2_active::discovery::DiscoveryIdentity::port),
        Some(b"Gi1/0/1".as_slice())
    );
    assert_eq!(cdp.frame().bytes(), CDP);
    Ok(())
}

#[test]
fn records_shutdown_and_all_three_lldp_multicast_scopes() -> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for scope in [0, 3, 14] {
        events.push(event(lldp(120, scope)?)?);
    }
    events.push(event(lldp(0, 14)?)?);
    let mut link = Link::new(events, Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Observed);
    assert_eq!(report.observations().len(), 4);
    let shutdown = report.observations().last().ok_or("missing shutdown")?;
    assert_eq!(shutdown.disposition(), DiscoveryDisposition::Withdrawal);
    assert_eq!(shutdown.hold_seconds(), Some(0));
    assert_eq!(
        shutdown
            .identity()
            .map(l2_active::discovery::DiscoveryIdentity::device),
        Some(DEVICE)
    );
    Ok(())
}

#[test]
fn retains_malformed_recognized_frames_as_evidence() -> Result<(), Box<dyn Error>> {
    let mut invalid_cdp = CDP.to_vec();
    *invalid_cdp.last_mut().ok_or("missing final byte")? ^= 1;
    let mut invalid_lldp = lldp(120, 14)?;
    invalid_lldp.pop();
    let mut link = Link::new(
        vec![event(invalid_cdp.clone())?, event(invalid_lldp.clone())?],
        Some(0),
    )?;
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Malformed);
    assert_eq!(report.observations().len(), 2);
    for (item, bytes) in report
        .observations()
        .iter()
        .zip([invalid_cdp, invalid_lldp])
    {
        assert_eq!(item.disposition(), DiscoveryDisposition::Malformed);
        assert_eq!(item.identity(), None);
        assert_eq!(item.hold_seconds(), None);
        assert_eq!(item.frame().bytes(), bytes);
    }
    Ok(())
}

#[test]
fn missing_capture_loss_and_transport_faults_never_create_positive_observations()
-> Result<(), Box<dyn Error>> {
    let monitor = DiscoveryMonitor::new(limits(10, 4096)?);
    let mut link = Link::new(vec![], None)?;
    let report = monitor.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Inconclusive);
    assert_eq!(report.summary().capture_loss(), None);
    assert!(report.observations().is_empty());
    let mut broken = Link::new(vec![], Some(0))?;
    broken.receive_error = Some(std::io::ErrorKind::BrokenPipe);
    broken.loss_error = Some(std::io::ErrorKind::Unsupported);
    broken.backlog_error = Some(std::io::ErrorKind::PermissionDenied);
    let report = monitor.run(&mut broken, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert_eq!(report.summary().total_received_packets(), None);
    assert_eq!(report.summary().total_received_bytes(), None);
    assert!(report.summary().loss_error().is_some());
    assert!(report.summary().backlog_error().is_some());
    assert!(broken.sent.is_empty());
    Ok(())
}

#[test]
fn cancellation_limit_and_unscoped_or_truncated_frames_are_accounted() -> Result<(), Box<dyn Error>>
{
    let good = lldp(120, 14)?;
    let mut link = Link::new(vec![event(good.clone())?], Some(0))?;
    let cancelled = AtomicBool::new(true);
    let report = DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &cancelled)?;
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert!(report.observations().is_empty());
    assert!(link.sent.is_empty());
    let mut link = Link::new(vec![event(good.clone())?], Some(0))?;
    let report = DiscoveryMonitor::new(limits(10, 4096)?).run_until(
        &mut link,
        &AtomicBool::new(false),
        Instant::now(),
    )?;
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(report.observations().is_empty());
    let wrong_scope = captured(good.clone(), None, u32::try_from(good.len())?)?;
    let truncated = captured(
        good.clone(),
        Some(identity()?),
        u32::try_from(good.len() + 1)?,
    )?;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(wrong_scope),
            ReceiveEvent::Frame(truncated),
            event(good)?,
        ],
        Some(0),
    )?;
    let report = DiscoveryMonitor::new(limits(3, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.observations().len(), 1);
    Ok(())
}

#[test]
fn observation_storage_limit_retains_complete_captured_frames() -> Result<(), Box<dyn Error>> {
    let wire = lldp(120, 14)?;
    let mut events = Vec::new();
    for _ in 0..=MAX_OBSERVATIONS {
        events.push(event(wire.clone())?);
    }
    let packets = u32::try_from(MAX_OBSERVATIONS + 1)?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(packets, 100_000)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.observations().len(), MAX_OBSERVATIONS);
    assert_eq!(
        report.summary().received_packets(),
        u32::try_from(MAX_OBSERVATIONS)?
    );
    assert!(
        report
            .observations()
            .iter()
            .all(|item| item.frame().bytes() == wire)
    );
    Ok(())
}

#[test]
fn lldp_parser_limit_is_reported_as_inconclusive_not_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = lldp(120, 14)?;
    bytes.truncate(bytes.len() - 2);
    for _ in 0..126 {
        bytes.extend_from_slice(&[0xfe, 0]);
    }
    bytes.extend_from_slice(&[0, 0]);
    let mut link = Link::new(vec![event(bytes.clone())?], Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Inconclusive);
    let observation = report
        .observations()
        .first()
        .ok_or("missing limited frame")?;
    assert_eq!(
        observation.disposition(),
        DiscoveryDisposition::LimitExceeded
    );
    assert_eq!(observation.frame().bytes(), bytes);
    assert_eq!(observation.identity(), None);
    Ok(())
}

#[test]
fn identity_assessment_uses_source_and_scope_and_preserves_conflicting_claims()
-> Result<(), Box<dyn Error>> {
    use l2_active::discovery::IdentityAssessment;
    const SOURCE: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const SCOPE: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 14];
    let expected = lldp(120, 14)?;
    let mut conflict = expected.clone();
    let pos = conflict
        .windows(7)
        .position(|value| value == b"Gi1/0/1")
        .ok_or("missing port")?;
    *conflict.get_mut(pos).ok_or("missing port byte")? = b'T';
    let mut other_sender = conflict.clone();
    *other_sender.get_mut(11).ok_or("missing source")? = 2;
    let mut other_scope = conflict.clone();
    *other_scope.get_mut(5).ok_or("missing scope")? = 3;
    let monitor = DiscoveryMonitor::new(limits(10, 4096)?);
    let mut link = Link::new(
        vec![
            event(expected.clone())?,
            event(other_sender)?,
            event(other_scope)?,
        ],
        Some(0),
    )?;
    let report = monitor.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.assess_identity(DiscoveryProtocol::Lldp, SOURCE, SCOPE, DEVICE, PORT),
        IdentityAssessment::Matched
    );
    assert_eq!(
        report.assess_identity(DiscoveryProtocol::Cdp, SOURCE, SCOPE, DEVICE, PORT),
        IdentityAssessment::Inconclusive
    );
    let mut link = Link::new(
        vec![
            event(expected)?,
            event(conflict)?,
            ReceiveEvent::InterfaceDown,
        ],
        Some(3),
    )?;
    let report = monitor.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.assess_identity(DiscoveryProtocol::Lldp, SOURCE, SCOPE, DEVICE, PORT),
        IdentityAssessment::UnexpectedIdentity
    );
    assert_eq!(report.summary().stop_reason(), StopReason::InterfaceDown);
    assert_eq!(report.summary().capture_loss(), Some(3));
    Ok(())
}

#[test]
fn observed_claim_survives_loss_and_interface_failure_with_quality_visible()
-> Result<(), Box<dyn Error>> {
    let wire = lldp(120, 14)?;
    let mut link = Link::new(vec![event(wire)?, ReceiveEvent::InterfaceDown], Some(3))?;
    link.backlog = Some(true);
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DiscoveryStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().stop_reason(), StopReason::InterfaceDown);
    assert_eq!(report.summary().capture_loss(), Some(3));
    assert_eq!(report.summary().capture_backlog(), Some(true));
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn exact_byte_budget_stops_collection_after_the_retained_frame() -> Result<(), Box<dyn Error>> {
    let wire = lldp(120, 14)?;
    let maximum = u64::try_from(wire.len())?;
    let mut link = Link::new(vec![event(wire.clone())?, event(wire)?], Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(10, maximum)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(report.summary().received_bytes(), maximum);
    assert_eq!(report.observations().len(), 1);
    Ok(())
}

#[test]
fn cdp_zero_hold_is_retained_as_a_withdrawal_with_identity() -> Result<(), Box<dyn Error>> {
    let wire = [
        1, 0, 0x0c, 0xcc, 0xcc, 0xcc, 2, 0, 0, 0, 0, 1, 0, 0x23, 0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20,
        0, 2, 0, 0xe7, 0x36, 0, 1, 0, 0x0c, b's', b'w', b'i', b't', b'c', b'h', b'-', b'a', 0, 3,
        0, 0x0b, b'G', b'i', b'1', b'/', b'0', b'/', b'1',
    ];
    let mut link = Link::new(vec![event(wire.to_vec())?], Some(0))?;
    let report =
        DiscoveryMonitor::new(limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let observation = report
        .observations()
        .first()
        .ok_or("missing CDP withdrawal")?;
    assert_eq!(observation.protocol(), DiscoveryProtocol::Cdp);
    assert_eq!(observation.disposition(), DiscoveryDisposition::Withdrawal);
    assert_eq!(observation.hold_seconds(), Some(0));
    assert_eq!(
        observation
            .identity()
            .map(l2_active::discovery::DiscoveryIdentity::device),
        Some(b"switch-a".as_slice())
    );
    assert_eq!(observation.frame().bytes(), wire);
    assert_eq!(
        report.assess_identity(
            DiscoveryProtocol::Cdp,
            [2, 0, 0, 0, 0, 1],
            [1, 0, 0x0c, 0xcc, 0xcc, 0xcc],
            b"switch-a",
            b"Gi1/0/1",
        ),
        l2_active::discovery::IdentityAssessment::Matched
    );
    Ok(())
}
