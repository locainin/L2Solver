use std::{error::Error, sync::atomic::AtomicBool};

use l2_active::{ReceiveEvent, StopReason, dhcp::DhcpStatus};

use super::fixture::{
    BAD_COOKIE, BAD_HARDWARE_LENGTH, BAD_HARDWARE_TYPE, BAD_OPCODE, BAD_OVERLOAD, DISCOVER,
    DUPLICATE_SERVER, DUPLICATE_TYPE, EXTRA_OPTIONS, FILE_OVERLOAD, FRAGMENT, INVALID_OFFERED_IP,
    MISSING_END, MISSING_LEASE, MISSING_SERVER, OFFER, OFFERED, OVERLOAD_DUPLICATE,
    OVERLOADED_OPTIONS, RELAY_OFFER, SERVER, SERVER_MAC, TRUNCATED_OPTION, UNEXPECTED_SERVER,
    UNICAST_OFFER, WRONG_CLIENT, WRONG_PORT, WRONG_XID, ZERO_OVERLOAD, ZERO_UDP_CHECKSUM, capture,
    probe,
};
use crate::support::{Link, captured, identity};

#[test]
fn correlated_scapy_offer_is_preserved_with_source_and_request_accounting()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(OFFER)?)], Some(0))?;
    let report = probe(Some(&[SERVER]), 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Observed);
    let offer = report
        .observations()
        .first()
        .ok_or("missing observed offer")?;
    assert_eq!(offer.server_identifier(), SERVER);
    assert_eq!(offer.offered_address(), OFFERED);
    assert_eq!(offer.source_mac().bytes(), SERVER_MAC);
    assert_eq!(offer.frame().bytes(), OFFER);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(
        report.summary().sent_bytes(),
        u64::try_from(DISCOVER.len())?
    );
    assert_eq!(link.sent.first().ok_or("missing actual send")?, DISCOVER);
    Ok(())
}

#[test]
fn offer_from_server_outside_allowlist_is_observed_as_unexpected() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(capture(UNEXPECTED_SERVER)?)],
        Some(0),
    )?;
    let report = probe(Some(&[SERVER]), 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::UnexpectedServer);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(
        report.expected_match(
            report
                .observations()
                .first()
                .ok_or("missing offer")?
                .server_identifier()
        ),
        Some(false)
    );
    Ok(())
}

#[test]
fn unrelated_and_malformed_responses_consume_budget_without_becoming_offers()
-> Result<(), Box<dyn Error>> {
    let fixtures = [
        WRONG_XID,
        WRONG_CLIENT,
        WRONG_PORT,
        FRAGMENT,
        DUPLICATE_SERVER,
        MISSING_END,
        TRUNCATED_OPTION,
    ];
    let events = fixtures
        .into_iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(capture(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 7, 8_192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.summary().received_packets(), 7);
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    Ok(())
}

#[test]
fn bad_checksums_lengths_and_every_truncated_prefix_are_never_attributed()
-> Result<(), Box<dyn Error>> {
    let mut bad_ip = OFFER.to_vec();
    *bad_ip.get_mut(24).ok_or("missing IPv4 checksum")? ^= 1;
    let mut bad_udp = OFFER.to_vec();
    *bad_udp.get_mut(40).ok_or("missing UDP checksum")? ^= 1;
    let mut bad_udp_length = OFFER.to_vec();
    bad_udp_length
        .get_mut(38..40)
        .ok_or("missing UDP length")?
        .copy_from_slice(&7_u16.to_be_bytes());
    let mut bad_ip_length = OFFER.to_vec();
    bad_ip_length
        .get_mut(16..18)
        .ok_or("missing IPv4 length")?
        .copy_from_slice(&u16::MAX.to_be_bytes());
    let mut fixtures = vec![bad_ip, bad_udp, bad_udp_length, bad_ip_length];
    for end in 0..OFFER.len() {
        fixtures.push(OFFER.get(..end).ok_or("invalid fixture prefix")?.to_vec());
    }
    let events = fixtures
        .into_iter()
        .map(|bytes| {
            let size = u32::try_from(bytes.len())?;
            Ok(ReceiveEvent::Frame(captured(
                bytes,
                Some(identity()?),
                size,
            )?))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let count = u32::try_from(events.len())?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, count, 200_000)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), count);
    assert!(report.observations().is_empty());
    Ok(())
}

#[test]
fn silence_loss_and_presend_cancellation_are_inconclusive() -> Result<(), Box<dyn Error>> {
    for loss in [None, Some(0), Some(2)] {
        let mut link = Link::new(vec![], loss)?;
        let report = probe(Some(&[SERVER]), 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), DhcpStatus::Inconclusive);
        assert_eq!(report.summary().capture_loss(), loss);
    }
    let mut link = Link::new(vec![], Some(0))?;
    let report = probe(None, 8, 4_096)?.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn truncated_and_wrong_interface_evidence_cannot_count_as_offers() -> Result<(), Box<dyn Error>> {
    let truncated = captured(
        OFFER.to_vec(),
        Some(identity()?),
        u32::try_from(OFFER.len() + 1)?,
    )?;
    let unknown = captured(OFFER.to_vec(), None, u32::try_from(OFFER.len())?)?;
    let mut link = Link::new(
        vec![ReceiveEvent::Frame(truncated), ReceiveEvent::Frame(unknown)],
        Some(0),
    )?;
    let report = probe(None, 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    Ok(())
}

#[test]
fn valid_unicast_overloaded_and_unchecksummed_offers_are_supported() -> Result<(), Box<dyn Error>> {
    for (bytes, checksum_present) in [
        (UNICAST_OFFER, true),
        (OVERLOADED_OPTIONS, true),
        (FILE_OVERLOAD, true),
        (EXTRA_OPTIONS, true),
        (ZERO_UDP_CHECKSUM, false),
    ] {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(bytes)?)], Some(0))?;
        let report = probe(None, 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), DhcpStatus::Observed);
        let offer = report.observations().first().ok_or("missing valid offer")?;
        assert_eq!(offer.server_identifier(), SERVER);
        assert_eq!(offer.lease_seconds(), 3_600);
        assert_eq!(offer.udp_checksum_present(), checksum_present);
        assert_eq!(report.expected_match(SERVER), None);
    }
    Ok(())
}

#[test]
fn invalid_hardware_address_and_required_offer_fields_are_rejected() -> Result<(), Box<dyn Error>> {
    let fixtures = [
        BAD_HARDWARE_LENGTH,
        BAD_HARDWARE_TYPE,
        INVALID_OFFERED_IP,
        MISSING_SERVER,
        MISSING_LEASE,
    ];
    let events = fixtures
        .into_iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(capture(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 5, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), 5);
    Ok(())
}

#[test]
fn unexpected_server_is_not_hidden_by_an_expected_offer_or_capture_loss()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(OFFER)?),
            ReceiveEvent::Frame(capture(UNEXPECTED_SERVER)?),
        ],
        Some(2),
    )?;
    let report = probe(Some(&[SERVER]), 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::UnexpectedServer);
    assert_eq!(report.observations().len(), 2);
    assert_eq!(report.summary().capture_loss(), Some(2));
    Ok(())
}

#[test]
fn repeated_identical_offers_are_bounded_without_losing_packet_accounting()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(OFFER)?),
            ReceiveEvent::Frame(capture(OFFER)?),
        ],
        Some(0),
    )?;
    let report = probe(None, 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    Ok(())
}

#[test]
fn unrelated_traffic_spends_receive_byte_budget() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(WRONG_XID)?)], Some(0))?;
    let report =
        probe(None, 8, u64::try_from(WRONG_XID.len())?)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(
        report.summary().received_bytes(),
        u64::try_from(WRONG_XID.len())?
    );
    Ok(())
}

#[test]
fn cancellation_or_timeout_during_send_does_not_claim_a_transmission() -> Result<(), Box<dyn Error>>
{
    let mut cancelled_link = Link::new(vec![], None)?;
    cancelled_link.cancel_during_send = true;
    let cancelled = probe(None, 8, 4_096)?.run(&mut cancelled_link, &AtomicBool::new(false))?;
    assert_eq!(cancelled.summary().stop_reason(), StopReason::Cancelled);
    assert!(cancelled.summary().send_attempted());
    assert_eq!(cancelled.summary().sent_packets(), 0);
    let mut timeout_link = Link::new(vec![], None)?;
    timeout_link.timeout_during_send = true;
    let timeout = probe(None, 8, 4_096)?.run(&mut timeout_link, &AtomicBool::new(false))?;
    assert_eq!(timeout.summary().stop_reason(), StopReason::Deadline);
    assert_eq!(timeout.summary().sent_packets(), 0);
    Ok(())
}

#[test]
fn relayed_offer_keeps_sender_separate_from_advertised_server_id() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(RELAY_OFFER)?)], Some(0))?;
    let report = probe(Some(&[SERVER]), 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    let offer = report.observations().first().ok_or("missing relay offer")?;
    assert_eq!(offer.server_identifier(), SERVER);
    assert_eq!(offer.source_ip(), std::net::Ipv4Addr::new(192, 0, 2, 99));
    assert_eq!(offer.relay_ip(), std::net::Ipv4Addr::new(192, 0, 2, 254));
    assert_eq!(report.status(), DhcpStatus::Observed);
    Ok(())
}

#[test]
fn invalid_cookie_opcode_and_ambiguous_overloaded_fields_are_not_offers()
-> Result<(), Box<dyn Error>> {
    let fixtures = [
        BAD_COOKIE,
        BAD_OPCODE,
        DUPLICATE_TYPE,
        OVERLOAD_DUPLICATE,
        BAD_OVERLOAD,
        ZERO_OVERLOAD,
    ];
    let events = fixtures
        .into_iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(capture(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 6, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), 6);
    Ok(())
}

#[test]
fn distinct_offers_stop_at_the_fixed_observation_cap() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("fixtures/many-offers.bin");
    let frames = bytes
        .chunks_exact(OFFER.len())
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert_eq!(frames.len(), 65);
    let mut link = Link::new(frames, Some(0))?;
    let report = probe(None, 100, 30_000)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    Ok(())
}

#[test]
fn ipv4_reserved_flag_is_rejected_but_dont_fragment_is_valid() -> Result<(), Box<dyn Error>> {
    let invalid = include_bytes!("fixtures/reserved-ip-flag.bin");
    let valid = include_bytes!("fixtures/dont-fragment.bin");
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(invalid)?)], Some(0))?;
    let rejected = probe(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(rejected.status(), DhcpStatus::Inconclusive);
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(valid)?)], Some(0))?;
    let accepted = probe(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(accepted.status(), DhcpStatus::Observed);
    Ok(())
}

#[test]
fn option_count_boundary_accepts_128_and_rejects_129() -> Result<(), Box<dyn Error>> {
    let allowed = include_bytes!("fixtures/option-limit.bin");
    let excessive = include_bytes!("fixtures/option-over-limit.bin");
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(allowed)?)], Some(0))?;
    let accepted = probe(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(accepted.status(), DhcpStatus::Observed);
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(excessive)?)], Some(0))?;
    let rejected = probe(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(rejected.status(), DhcpStatus::Inconclusive);
    Ok(())
}

#[test]
fn wrong_link_or_internet_endpoints_and_fragment_offsets_are_rejected() -> Result<(), Box<dyn Error>>
{
    let fixtures: &[&[u8]] = &[
        include_bytes!("fixtures/wrong-destination-port.bin"),
        include_bytes!("fixtures/wrong-destination-mac.bin"),
        include_bytes!("fixtures/wrong-destination-ip.bin"),
        include_bytes!("fixtures/invalid-source-ip.bin"),
        include_bytes!("fixtures/invalid-source-mac.bin"),
        include_bytes!("fixtures/nonzero-fragment-offset.bin"),
    ];
    let events = fixtures
        .iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(capture(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 6, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.summary().received_packets(), 6);
    Ok(())
}

#[test]
fn backend_shorter_receive_window_is_not_a_complete_observation() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::BackendTimedOut], Some(0))?;
    let report = probe(None, 8, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::BackendDeadline);
    Ok(())
}

#[test]
fn expired_operation_deadline_prevents_dhcp_send() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], Some(0))?;
    let report = probe(None, 8, 4_096)?.run_until(
        &mut link,
        &AtomicBool::new(false),
        std::time::Instant::now(),
    )?;
    assert_eq!(report.status(), DhcpStatus::Inconclusive);
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(link.sent.is_empty());
    Ok(())
}
