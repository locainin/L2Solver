use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::{NdpStatus, PreSendUsage, ReceiveEvent, StopReason};
use l2_capture::Direction;
use l2_onpath::MacAddress;

use crate::{
    fixture::{OTHER_MAC, REMOTE_MAC, RESPONSE, event, fix_checksum, probe, with_mac},
    support::{Link, captured, captured_with_direction, identity},
};

#[test]
fn observed_advertisement_retains_actual_frame_and_distinct_mac_claims()
-> Result<(), Box<dyn Error>> {
    let first = RESPONSE.to_vec();
    let second = with_mac(OTHER_MAC)?;
    let mut link = Link::new(vec![event(first.clone())?, event(second)?], Some(0))?;
    let report = probe(Some(REMOTE_MAC), 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::UnexpectedIdentity);
    assert!(report.has_conflicting_identities());
    assert_eq!(report.observations().len(), 2);
    let observation = report.observations().first().ok_or("missing observation")?;
    assert_eq!(observation.mac(), MacAddress::new(REMOTE_MAC)?);
    assert_eq!(observation.frame().bytes(), first);
    assert_eq!(report.summary().received_packets(), 2);
    assert_eq!(report.summary().sent_packets(), 1);
    Ok(())
}

#[test]
fn malformed_unrelated_or_unsupported_advertisements_are_counted_but_not_accepted()
-> Result<(), Box<dyn Error>> {
    let mut cases = Vec::new();
    for (offset, value, checksum) in [
        (14, 0x40, false), // wrong IP version
        (20, 44, false),   // fragment header
        (20, 0, false),    // unsupported extension header
        (21, 254, false),  // off-link hop limit
        (55, 1, true),     // ICMP code
        (56, 0, false),    // checksum
        (58, 0, true),     // unsolicited advertisement
        (77, 3, true),     // different target address
        (79, 0, true),     // zero-length option
        (11, 7, false),    // Ethernet source differs from option
    ] {
        let mut frame = RESPONSE.to_vec();
        *frame.get_mut(offset).ok_or("missing fixture field")? = value;
        if checksum {
            fix_checksum(&mut frame)?;
        }
        cases.push(event(frame)?);
    }
    let count = u32::try_from(cases.len())?;
    let mut link = Link::new(cases, Some(0))?;
    let report = probe(None, 32, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.summary().received_packets(), count);
    assert_eq!(report.unmatched_packets(), count);
    Ok(())
}

#[test]
fn truncated_capture_and_wrong_interface_do_not_become_observations() -> Result<(), Box<dyn Error>>
{
    let truncated = ReceiveEvent::Frame(captured(
        RESPONSE.get(..60).ok_or("missing bytes")?.to_vec(),
        Some(identity()?),
        86,
    )?);
    let unscoped = ReceiveEvent::Frame(captured(RESPONSE.to_vec(), None, 86)?);
    let mut link = Link::new(vec![truncated, unscoped], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    Ok(())
}

#[test]
fn in_band_vlan_tag_is_not_accepted_as_an_untagged_reply() -> Result<(), Box<dyn Error>> {
    let mut tagged = Vec::new();
    tagged.extend_from_slice(RESPONSE.get(..12).ok_or("missing Ethernet addresses")?);
    tagged.extend_from_slice(&[0x81, 0, 0, 10]);
    tagged.extend_from_slice(RESPONSE.get(12..).ok_or("missing IPv6 payload")?);
    let mut link = Link::new(vec![event(tagged)?], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.unmatched_packets(), 1);
    Ok(())
}

#[test]
fn advertisement_to_another_ethernet_destination_is_unmatched() -> Result<(), Box<dyn Error>> {
    let mut frame = RESPONSE.to_vec();
    *frame.get_mut(5).ok_or("missing destination")? = 7;
    let mut link = Link::new(vec![event(frame)?], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.unmatched_packets(), 1);
    Ok(())
}

#[test]
fn outbound_and_unknown_direction_frames_are_not_receiver_observations()
-> Result<(), Box<dyn Error>> {
    let outgoing = ReceiveEvent::Frame(captured_with_direction(
        RESPONSE.to_vec(),
        Some(identity()?),
        86,
        Direction::Outbound,
    )?);
    let unknown = ReceiveEvent::Frame(captured_with_direction(
        RESPONSE.to_vec(),
        Some(identity()?),
        86,
        Direction::Unknown,
    )?);
    let mut link = Link::new(vec![outgoing, unknown], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.summary().outbound_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.unmatched_packets(), 0);
    Ok(())
}

#[test]
fn cancellation_and_packet_budget_stop_actual_dispatch_or_collection() -> Result<(), Box<dyn Error>>
{
    let mut cancelled_link = Link::new(Vec::new(), None)?;
    let report = probe(None, 1, 4096)?.run(&mut cancelled_link, &AtomicBool::new(true))?;
    assert!(cancelled_link.sent.is_empty());
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert_eq!(report.status(), NdpStatus::Inconclusive);

    let mut limited = Link::new(
        vec![event(vec![0; 60])?, event(RESPONSE.to_vec())?],
        Some(3),
    )?;
    let report = probe(None, 1, 4096)?.run(&mut limited, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.summary().capture_loss(), Some(3));
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    Ok(())
}

#[test]
fn expired_shared_deadline_prevents_ndp_send() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(Vec::new(), None)?;
    let report =
        probe(None, 10, 4096)?.run_until(&mut link, &AtomicBool::new(false), Instant::now())?;
    assert!(link.sent.is_empty());
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    Ok(())
}

#[test]
fn every_truncated_packet_prefix_is_ignored_without_panicking() -> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for end in 0..RESPONSE.len() {
        let bytes = RESPONSE
            .get(..end)
            .ok_or("invalid fixture prefix")?
            .to_vec();
        events.push(event(bytes)?);
    }
    let count = u32::try_from(events.len())?;
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 100, 8192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), count);
    assert_eq!(report.unmatched_packets(), count);
    Ok(())
}

#[test]
fn duplicate_or_invalid_target_options_do_not_create_a_claim() -> Result<(), Box<dyn Error>> {
    let mut duplicate = RESPONSE.to_vec();
    duplicate.extend_from_slice(RESPONSE.get(78..86).ok_or("missing option")?);
    duplicate
        .get_mut(18..20)
        .ok_or("missing IPv6 length")?
        .copy_from_slice(&40_u16.to_be_bytes());
    fix_checksum(&mut duplicate)?;

    let mut oversized = RESPONSE.to_vec();
    *oversized.get_mut(79).ok_or("missing option length")? = 2;
    oversized.extend_from_slice(&[0; 8]);
    oversized
        .get_mut(18..20)
        .ok_or("missing IPv6 length")?
        .copy_from_slice(&40_u16.to_be_bytes());
    fix_checksum(&mut oversized)?;

    let mut absent = RESPONSE.get(..78).ok_or("missing header")?.to_vec();
    absent
        .get_mut(18..20)
        .ok_or("missing IPv6 length")?
        .copy_from_slice(&24_u16.to_be_bytes());
    fix_checksum(&mut absent)?;

    let mut link = Link::new(
        vec![event(duplicate)?, event(oversized)?, event(absent)?],
        Some(0),
    )?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.unmatched_packets(), 3);
    Ok(())
}

#[test]
fn valid_unknown_option_and_repeated_reply_preserve_one_claim() -> Result<(), Box<dyn Error>> {
    let mut extra = RESPONSE.to_vec();
    extra.extend_from_slice(&[99, 1, 0, 0, 0, 0, 0, 0]);
    extra
        .get_mut(18..20)
        .ok_or("missing IPv6 length")?
        .copy_from_slice(&40_u16.to_be_bytes());
    fix_checksum(&mut extra)?;
    let mut link = Link::new(vec![event(extra)?, event(RESPONSE.to_vec())?], Some(0))?;
    let report = probe(Some(REMOTE_MAC), 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert!(!report.has_conflicting_identities());
    assert_eq!(report.unmatched_packets(), 0);
    Ok(())
}

#[test]
fn wrong_ipv6_source_or_destination_is_not_accepted() -> Result<(), Box<dyn Error>> {
    let mut unspecified = RESPONSE.to_vec();
    unspecified.get_mut(22..38).ok_or("missing source")?.fill(0);
    fix_checksum(&mut unspecified)?;
    let mut destination = RESPONSE.to_vec();
    *destination.get_mut(53).ok_or("missing destination")? = 3;
    fix_checksum(&mut destination)?;
    let mut link = Link::new(vec![event(unspecified)?, event(destination)?], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    assert_eq!(report.unmatched_packets(), 2);
    Ok(())
}

#[test]
fn proxy_advertisement_retains_its_actual_ipv6_source() -> Result<(), Box<dyn Error>> {
    let mut proxy = RESPONSE.to_vec();
    *proxy.get_mut(37).ok_or("missing source address")? = 3;
    fix_checksum(&mut proxy)?;
    let mut link = Link::new(vec![event(proxy)?], Some(0))?;
    let report = probe(None, 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Observed);
    let observation = report.observations().first().ok_or("missing observation")?;
    assert_eq!(
        observation.source_ip(),
        "fe80::3".parse::<std::net::Ipv6Addr>()?
    );
    Ok(())
}

#[test]
fn capture_byte_ceiling_stops_before_later_replies() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![event(vec![0; 60])?, event(RESPONSE.to_vec())?],
        Some(0),
    )?;
    let report = probe(None, 10, 60)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(report.summary().received_bytes(), 60);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    Ok(())
}

#[test]
fn queue_drain_usage_shares_the_receive_packet_budget() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![event(vec![0; 60])?, event(RESPONSE.to_vec())?],
        Some(0),
    )?;
    link.pre_send = Some(PreSendUsage::new(1, 60));
    let report = probe(None, 2, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::PacketLimit);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(
        report.summary().pre_send_usage(),
        Some(PreSendUsage::new(1, 60))
    );
    assert_eq!(report.status(), NdpStatus::Inconclusive);
    Ok(())
}

#[test]
fn observed_reply_is_retained_when_capture_loss_is_reported() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![event(RESPONSE.to_vec())?], Some(4))?;
    let report = probe(Some(REMOTE_MAC), 10, 4096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), NdpStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().capture_loss(), Some(4));
    Ok(())
}

#[test]
fn distinct_claims_stop_at_the_bounded_observation_capacity() -> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for host in 2_u8..=65 {
        events.push(event(with_mac([2, 0, 0, 0, 0, host])?)?);
    }
    let mut link = Link::new(events, Some(0))?;
    let report = probe(None, 128, 8192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(report.summary().received_packets(), 64);
    assert_eq!(report.observations().len(), 64);
    assert!(report.has_conflicting_identities());
    Ok(())
}
