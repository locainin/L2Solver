use std::{error::Error, net::Ipv4Addr, sync::atomic::AtomicBool};

use l2_active::{NeighborStatus, ReceiveEvent, StopReason};

use super::fixture::{
    LOCAL_IP, Link, OTHER_MAC, REMOTE_MAC, TARGET_IP, captured, identity, probe, reply,
};

#[test]
fn exact_correlated_reply_is_retained_as_an_observation() -> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    let probe = probe(Some(REMOTE_MAC), 10, 1024)?;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing observation")?
            .mac()
            .bytes(),
        REMOTE_MAC
    );
    assert_eq!(
        report.expected_match(
            report
                .observations()
                .first()
                .ok_or("missing observation")?
                .mac()
        ),
        Some(true)
    );
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(report.summary().sent_bytes(), 60);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.summary().received_bytes(), 60);
    assert_eq!(
        link.sent.first().ok_or("missing send")?.as_slice(),
        probe.frame()
    );
    Ok(())
}

#[test]
fn mismatched_identity_is_reported_as_a_scoped_observation() -> Result<(), Box<dyn Error>> {
    let frame = captured(reply(OTHER_MAC, TARGET_IP, LOCAL_IP), Some(identity()?), 60)?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    let report = probe(Some(REMOTE_MAC), 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::UnexpectedIdentity);
    assert_eq!(
        report.expected_match(
            report
                .observations()
                .first()
                .ok_or("missing observation")?
                .mac()
        ),
        Some(false)
    );
    Ok(())
}

#[test]
fn silence_loss_and_cancellation_never_establish_a_success() -> Result<(), Box<dyn Error>> {
    for loss in [None, Some(1), Some(0)] {
        let mut link = Link::new(vec![], loss)?;
        let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), NeighborStatus::Inconclusive);
        assert_eq!(report.summary().capture_loss(), loss);
    }
    let mut link = Link::new(vec![], None)?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[test]
fn cancellation_during_send_keeps_the_attempt_and_does_not_claim_transmission()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], None)?;
    link.cancel_during_send = true;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert!(report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[test]
fn deadline_during_send_does_not_claim_transmission() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], None)?;
    link.timeout_during_send = true;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    Ok(())
}

#[test]
fn unrelated_truncated_or_wrong_interface_frames_are_not_attributed() -> Result<(), Box<dyn Error>>
{
    let wrong_target = captured(
        reply(REMOTE_MAC, Ipv4Addr::new(192, 0, 2, 99), LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let truncated = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        80,
    )?;
    let wrong_source = captured(reply(REMOTE_MAC, TARGET_IP, LOCAL_IP), None, 60)?;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(wrong_target),
            ReceiveEvent::Frame(truncated),
            ReceiveEvent::Frame(wrong_source),
        ],
        None,
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.summary().received_packets(), 3);
    assert_eq!(report.summary().received_bytes(), 180);
    Ok(())
}

#[test]
fn repeated_reply_is_deduplicated_without_fabricating_freshness() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(captured(
                reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
                Some(identity()?),
                60,
            )?),
            ReceiveEvent::Frame(captured(
                reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
                Some(identity()?),
                60,
            )?),
        ],
        Some(0),
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 1);
    assert!(!report.has_conflicting_identities());
    assert_eq!(report.summary().received_packets(), 2);
    Ok(())
}

#[test]
fn two_distinct_mac_claims_are_reported_even_without_an_expected_identity()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(captured(
                reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
                Some(identity()?),
                60,
            )?),
            ReceiveEvent::Frame(captured(
                reply(OTHER_MAC, TARGET_IP, LOCAL_IP),
                Some(identity()?),
                60,
            )?),
        ],
        Some(0),
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 2);
    assert!(report.has_conflicting_identities());
    assert_eq!(report.status(), NeighborStatus::Observed);
    Ok(())
}

#[test]
fn unexpected_arp_identity_takes_precedence_in_either_observation_order()
-> Result<(), Box<dyn Error>> {
    for claims in [[REMOTE_MAC, OTHER_MAC], [OTHER_MAC, REMOTE_MAC]] {
        let events = claims
            .into_iter()
            .map(|mac| {
                captured(reply(mac, TARGET_IP, LOCAL_IP), Some(identity()?), 60)
                    .map(ReceiveEvent::Frame)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut link = Link::new(events, Some(0))?;
        let report = probe(Some(REMOTE_MAC), 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), NeighborStatus::UnexpectedIdentity);
        assert!(report.has_conflicting_identities());
    }
    Ok(())
}

#[test]
fn packet_and_byte_limits_charge_unrelated_frames() -> Result<(), Box<dyn Error>> {
    let unrelated = || {
        captured(
            reply(REMOTE_MAC, Ipv4Addr::new(192, 0, 2, 99), LOCAL_IP),
            Some(identity()?),
            60,
        )
    };
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(unrelated()?),
            ReceiveEvent::Frame(unrelated()?),
        ],
        None,
    )?;
    let report = probe(None, 1, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().received_packets(), 1);
    let mut link = Link::new(vec![ReceiveEvent::Frame(unrelated()?)], None)?;
    let report = probe(None, 10, 60)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(report.summary().received_bytes(), 60);
    Ok(())
}

#[test]
fn broadcast_reply_is_supported_when_arp_target_fields_match() -> Result<(), Box<dyn Error>> {
    let mut bytes = reply(REMOTE_MAC, TARGET_IP, LOCAL_IP);
    bytes
        .get_mut(..6)
        .ok_or("missing destination")?
        .copy_from_slice(&[0xff; 6]);
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(captured(bytes, Some(identity()?), 60)?)],
        Some(0),
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    Ok(())
}

#[test]
fn malformed_wrong_operation_and_mismatched_hardware_are_ignored() -> Result<(), Box<dyn Error>> {
    let mut bad_operation = reply(REMOTE_MAC, TARGET_IP, LOCAL_IP);
    *bad_operation.get_mut(21).ok_or("missing operation")? = 1;
    let mut bad_source = reply(REMOTE_MAC, TARGET_IP, LOCAL_IP);
    *bad_source.get_mut(11).ok_or("missing source")? ^= 1;
    let mut bad_target = reply(REMOTE_MAC, TARGET_IP, LOCAL_IP);
    *bad_target.get_mut(37).ok_or("missing target hardware")? ^= 1;
    let events = [vec![0; 13], bad_operation, bad_source, bad_target]
        .into_iter()
        .map(|bytes| {
            let len = u32::try_from(bytes.len())?;
            Ok(ReceiveEvent::Frame(captured(
                bytes,
                Some(identity()?),
                len,
            )?))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), 4);
    Ok(())
}

#[test]
fn backend_that_exceeds_the_byte_allowance_is_reported_with_actual_accounting()
-> Result<(), Box<dyn Error>> {
    let bytes = vec![0; 100];
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(captured(
            bytes,
            Some(identity()?),
            100,
        )?)],
        None,
    )?;
    link.ignore_receive_capacity = true;
    let report = probe(None, 10, 60)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::BackendViolation);
    assert_eq!(report.summary().received_bytes(), 100);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    Ok(())
}

#[test]
fn transport_and_loss_failures_preserve_actual_attempt_and_capture_accounting()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], None)?;
    link.send_error = Some(std::io::ErrorKind::PermissionDenied);
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert!(report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(
        report
            .summary()
            .transport_error()
            .ok_or("missing error")?
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );

    let mut link = Link::new(vec![], None)?;
    link.receive_error = Some(std::io::ErrorKind::BrokenPipe);
    link.loss_error = Some(std::io::ErrorKind::Unsupported);
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(
        report
            .summary()
            .transport_error()
            .ok_or("missing error")?
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        report
            .summary()
            .loss_error()
            .ok_or("missing loss error")?
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(report.summary().capture_loss(), None);
    assert_eq!(report.summary().total_received_packets(), None);
    assert_eq!(report.summary().total_received_bytes(), None);
    Ok(())
}

#[test]
fn interface_down_stops_collection_without_discarding_prior_evidence() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(captured(
                reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
                Some(identity()?),
                60,
            )?),
            ReceiveEvent::InterfaceDown,
        ],
        None,
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::InterfaceDown);
    assert_eq!(report.observations().len(), 1);
    Ok(())
}

#[test]
fn known_outbound_frames_are_charged_without_marking_inbound_capture_incomplete()
-> Result<(), Box<dyn Error>> {
    let probe = probe(None, 10, 1024)?;
    let outbound = crate::support::captured_with_direction(
        probe.frame().to_vec(),
        Some(identity()?),
        80,
        l2_capture::Direction::Outbound,
    )?;
    let reply = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(outbound), ReceiveEvent::Frame(reply)],
        Some(0),
    )?;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().received_bytes(), 120);
    assert_eq!(report.summary().outbound_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 0);
    assert_eq!(report.summary().truncated_packets(), 0);
    assert_eq!(report.status(), NeighborStatus::Observed);
    Ok(())
}

#[test]
fn pre_send_drain_counts_against_the_same_packet_and_byte_budget() -> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    link.pre_send = Some(l2_active::PreSendUsage::new(1, 60));
    let report = probe(None, 2, 120)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.summary().received_bytes(), 60);
    assert_eq!(report.summary().total_received_packets(), Some(2));
    assert_eq!(report.summary().total_received_bytes(), Some(120));
    Ok(())
}

#[test]
fn unknown_pre_send_usage_stops_capture_without_inventing_a_total() -> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], None)?;
    link.pre_send = None;
    let report = probe(None, 2, 120)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::AccountingUnavailable
    );
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(report.summary().total_received_packets(), None);
    assert_eq!(report.summary().total_received_bytes(), None);
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    Ok(())
}

#[test]
fn impossible_pre_send_usage_is_rejected_without_claiming_valid_accounting()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], None)?;
    link.pre_send = Some(l2_active::PreSendUsage::new(0, 1));
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::BackendViolation);
    assert_eq!(report.summary().total_received_bytes(), None);
    assert_eq!(
        report
            .summary()
            .pre_send_usage()
            .ok_or("missing raw count")?
            .bytes(),
        1
    );
    assert_eq!(report.status(), NeighborStatus::Inconclusive);
    Ok(())
}

#[test]
fn pre_send_work_survives_send_failure_and_accounting_query_failure_is_visible()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], None)?;
    link.send_error = Some(std::io::ErrorKind::PermissionDenied);
    link.pre_send = Some(l2_active::PreSendUsage::new(2, 120));
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.summary().total_received_packets(), Some(2));
    assert_eq!(report.summary().total_received_bytes(), Some(120));

    let mut link = Link::new(vec![], None)?;
    link.pre_send_error = Some(std::io::ErrorKind::BrokenPipe);
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().stop_reason(),
        StopReason::AccountingUnavailable
    );
    assert_eq!(
        report
            .summary()
            .accounting_error()
            .ok_or("missing accounting error")?
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert_eq!(report.summary().total_received_packets(), None);
    Ok(())
}

#[test]
fn exhausted_capture_limit_is_not_hidden_by_a_concurrent_deadline() -> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    link.receive_delay = std::time::Duration::from_millis(30);
    let report = probe(None, 1, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().received_packets(), 1);
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    link.receive_delay = std::time::Duration::from_millis(30);
    let report = probe(None, 10, 60)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(report.summary().received_bytes(), 60);
    Ok(())
}

#[test]
fn early_backend_deadline_does_not_claim_the_requested_window_completed()
-> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(frame), ReceiveEvent::BackendTimedOut],
        Some(0),
    )?;
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::BackendDeadline);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.summary().received_bytes(), 60);
    assert_eq!(report.summary().total_received_packets(), None);
    assert_eq!(report.summary().total_received_bytes(), None);
    Ok(())
}

#[test]
fn expired_shared_deadline_prevents_any_send() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], Some(0))?;
    let report = probe(None, 10, 1024)?.run_until(
        &mut link,
        &AtomicBool::new(false),
        std::time::Instant::now(),
    )?;
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[test]
fn caller_cannot_extend_the_admitted_timeout() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], Some(0))?;
    let long_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let report =
        probe(None, 10, 1024)?.run_until(&mut link, &AtomicBool::new(false), long_deadline)?;
    assert_eq!(report.summary().sent_packets(), 1);
    let deadline = link.sent_deadline.ok_or("missing sent deadline")?;
    let sent_at = link.sent_at.ok_or("missing send instant")?;
    assert!(deadline.saturating_duration_since(sent_at) <= std::time::Duration::from_millis(20));
    Ok(())
}

#[test]
fn final_backlog_and_query_failure_remain_visible_beside_observed_replies()
-> Result<(), Box<dyn Error>> {
    let frame = captured(
        reply(REMOTE_MAC, TARGET_IP, LOCAL_IP),
        Some(identity()?),
        60,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    link.backlog = Some(true);
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NeighborStatus::Observed);
    assert_eq!(report.summary().capture_backlog(), Some(true));

    let mut link = Link::new(vec![], None)?;
    link.backlog_error = Some(std::io::ErrorKind::BrokenPipe);
    let report = probe(None, 10, 1024)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().capture_backlog(), None);
    assert_eq!(
        report
            .summary()
            .backlog_error()
            .ok_or("missing backlog error")?
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );
    Ok(())
}
