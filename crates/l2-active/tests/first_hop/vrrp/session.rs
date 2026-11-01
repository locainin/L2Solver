use std::{error::Error, net::Ipv4Addr, sync::atomic::AtomicBool, time::Instant};

use l2_active::{
    ReceiveEvent, StopReason,
    first_hop::vrrp::{VrrpEvidence, VrrpMalformed, VrrpStatus},
};

use super::fixture::{
    ANOMALY, BAD_SOURCE, BAD_TTL, BAD_TYPE, EXTRA_IP, FRAGMENT, MAXIMUM, OPTIONS, OTHER_VRID,
    PSEUDO, RELINQUISH, RESERVED, SHORT_IP, V2_AUTH, VALID, ZERO_COUNT, ZERO_VRID, capture,
    monitor,
};
use crate::support::{Link, captured, captured_with_direction, identity};

#[test]
fn scoped_advertisement_preserves_claims_addresses_and_receive_only_accounting()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(VALID)?)], Some(0))?;
    let report = monitor(Some(42), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    let item = report
        .observations()
        .first()
        .ok_or("missing advertisement")?;
    let VrrpEvidence::Advertisement(advert) = item.evidence() else {
        return Err("missing claim".into());
    };
    assert_eq!(advert.source_ip(), Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(advert.source_mac().bytes(), [0, 0, 0x5e, 0, 1, 42]);
    assert!(advert.source_matches_virtual_mac());
    assert_eq!(advert.vrid().get(), 42);
    assert_eq!(advert.priority(), 110);
    assert_eq!(advert.interval_centiseconds(), 100);
    assert_eq!(
        item.addresses()
            .ok_or("missing addresses")?
            .collect::<Vec<_>>(),
        vec![
            Ipv4Addr::new(192, 0, 2, 254),
            Ipv4Addr::new(198, 51, 100, 254)
        ]
    );
    assert_eq!(item.frame().bytes(), VALID);
    assert_eq!(report.summary().received_packets(), 1);
    assert_eq!(report.summary().sent_packets(), 0);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn selected_vrid_excludes_other_groups_from_observations() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(OTHER_VRID)?),
            ReceiveEvent::Frame(capture(VALID)?),
        ],
        Some(0),
    )?;
    let report = monitor(Some(42), 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.unrelated_packets(), 1);
    Ok(())
}

#[test]
fn unrelated_frames_consume_the_selected_packet_or_byte_budget() -> Result<(), Box<dyn Error>> {
    for (packets, bytes, expected_stop) in [
        (1, 4_096, StopReason::PacketLimit),
        (2, u64::try_from(OTHER_VRID.len())?, StopReason::ByteLimit),
    ] {
        let mut link = Link::new(
            vec![
                ReceiveEvent::Frame(capture(OTHER_VRID)?),
                ReceiveEvent::Frame(capture(VALID)?),
            ],
            Some(0),
        )?;
        let report = monitor(Some(42), packets, bytes)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), VrrpStatus::Inconclusive);
        assert_eq!(report.unrelated_packets(), 1);
        assert_eq!(report.summary().received_packets(), 1);
        assert_eq!(report.summary().stop_reason(), expected_stop);
        assert_eq!(link.events.len(), 1);
        assert!(link.sent.is_empty());
    }
    Ok(())
}

#[test]
fn selected_vrid_is_never_read_from_bytes_outside_the_declared_ip_packet()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(SHORT_IP)?)], Some(0))?;
    let report = monitor(Some(42), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unrelated_packets(), 1);
    Ok(())
}

#[test]
fn ipv4_options_keep_vrrp_offsets_and_addresses_correct() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(OPTIONS)?)], Some(0))?;
    let report = monitor(Some(42), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    let item = report
        .observations()
        .first()
        .ok_or("missing advertisement")?;
    assert_eq!(
        item.addresses()
            .ok_or("missing addresses")?
            .collect::<Vec<_>>(),
        vec![
            Ipv4Addr::new(192, 0, 2, 254),
            Ipv4Addr::new(198, 51, 100, 254)
        ]
    );
    Ok(())
}

#[test]
fn maximum_ipv4_options_and_address_count_remain_within_the_declared_packet()
-> Result<(), Box<dyn Error>> {
    let truncated = MAXIMUM
        .get(..MAXIMUM.len() - 1)
        .ok_or("missing final address byte")?;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(MAXIMUM)?),
            ReceiveEvent::Frame(capture(truncated)?),
        ],
        Some(0),
    )?;
    let report = monitor(Some(255), 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    let [complete, incomplete] = report.observations() else {
        return Err("missing maximum-size candidates".into());
    };
    let VrrpEvidence::Advertisement(advert) = complete.evidence() else {
        return Err("complete maximum-size candidate was rejected".into());
    };
    assert_eq!(advert.vrid().get(), 255);
    assert!(advert.source_matches_virtual_mac());
    let addresses = complete
        .addresses()
        .ok_or("missing maximum-size address list")?
        .collect::<Vec<_>>();
    assert_eq!(addresses.len(), 255);
    assert_eq!(addresses.first(), Some(&Ipv4Addr::new(198, 18, 0, 1)));
    assert_eq!(addresses.last(), Some(&Ipv4Addr::new(198, 18, 1, 1)));
    assert_eq!(
        incomplete.evidence(),
        &VrrpEvidence::Malformed(VrrpMalformed::Truncated)
    );
    Ok(())
}

#[test]
fn invalid_source_macs_are_preserved_as_malformed_candidates() -> Result<(), Box<dyn Error>> {
    for source in [[0; 6], [0xff; 6], [1, 0, 0x5e, 0, 0, 1]] {
        let mut bytes = VALID.to_vec();
        bytes
            .get_mut(6..12)
            .ok_or("missing Ethernet source")?
            .copy_from_slice(&source);
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(&bytes)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), VrrpStatus::Inconclusive);
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing candidate")?
                .evidence(),
            &VrrpEvidence::Malformed(VrrpMalformed::SourceMac)
        );
    }
    Ok(())
}

#[test]
fn sender_mac_mismatch_is_retained_as_an_unauthenticated_anomaly() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(ANOMALY)?)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    let item = report
        .observations()
        .first()
        .ok_or("missing advertisement")?;
    let VrrpEvidence::Advertisement(advert) = item.evidence() else {
        return Err("missing claim".into());
    };
    assert_eq!(advert.source_mac().bytes(), [2, 0, 0, 0, 0, 2]);
    assert!(!advert.source_matches_virtual_mac());
    Ok(())
}

#[test]
fn reserved_bits_are_ignored_and_priority_zero_is_a_relinquishment_claim()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(RESERVED)?),
            ReceiveEvent::Frame(capture(RELINQUISH)?),
        ],
        Some(0),
    )?;
    let report = monitor(None, 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    let [reserved, relinquish] = report.observations() else {
        return Err("missing advertisements".into());
    };
    let VrrpEvidence::Advertisement(first) = reserved.evidence() else {
        return Err("reserved bits rejected".into());
    };
    let VrrpEvidence::Advertisement(second) = relinquish.evidence() else {
        return Err("priority zero rejected".into());
    };
    assert_eq!(first.interval_centiseconds(), 100);
    assert_eq!(second.priority(), 0);
    Ok(())
}

#[test]
fn invalid_checksums_ttl_fragment_and_protocol_fields_are_retained_as_failures()
-> Result<(), Box<dyn Error>> {
    let mut ip_checksum = VALID.to_vec();
    *ip_checksum.get_mut(24).ok_or("missing IP checksum")? ^= 1;
    let mut vrrp_checksum = VALID.to_vec();
    *vrrp_checksum.get_mut(40).ok_or("missing VRRP checksum")? ^= 1;
    let frames = [
        (PSEUDO, VrrpMalformed::Checksum),
        (&ip_checksum, VrrpMalformed::Ipv4Checksum),
        (&vrrp_checksum, VrrpMalformed::Checksum),
        (BAD_TTL, VrrpMalformed::Ttl),
        (FRAGMENT, VrrpMalformed::Fragmented),
        (BAD_SOURCE, VrrpMalformed::SourceIp),
        (ZERO_VRID, VrrpMalformed::Header),
        (ZERO_COUNT, VrrpMalformed::Header),
        (BAD_TYPE, VrrpMalformed::Header),
    ];
    for (frame, expected) in frames {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), VrrpStatus::Inconclusive);
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing failure")?
                .evidence(),
            &VrrpEvidence::Malformed(expected)
        );
    }
    Ok(())
}

#[test]
fn extra_ip_bytes_are_not_part_of_the_advertised_addresses() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(EXTRA_IP)?)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    let item = report
        .observations()
        .first()
        .ok_or("missing advertisement")?;
    let VrrpEvidence::Advertisement(advert) = item.evidence() else {
        return Err("missing claim".into());
    };
    assert_eq!(advert.trailing_ip_bytes(), 5);
    assert_eq!(item.addresses().ok_or("missing addresses")?.count(), 2);
    Ok(())
}

#[test]
fn debug_output_does_not_dump_untrusted_frame_padding() -> Result<(), Box<dyn Error>> {
    let mut with_padding = VALID.to_vec();
    with_padding
        .get_mut(50..58)
        .ok_or("missing Ethernet padding")?
        .copy_from_slice(b"Qx7!pA2?");
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(&with_padding)?)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    assert!(
        report
            .observations()
            .first()
            .ok_or("missing observation")?
            .frame()
            .bytes()
            .ends_with(with_padding.get(50..).ok_or("missing padding")?)
    );
    let debug = format!("{report:?}");
    for marker in [
        "Qx7!pA2?",
        "517837217041323f",
        "81, 120, 55, 33, 112, 65, 50, 63",
    ] {
        assert!(!debug.contains(marker));
    }
    Ok(())
}

#[test]
fn unsupported_version_and_truncated_address_body_are_not_valid_claims()
-> Result<(), Box<dyn Error>> {
    let mut unsupported = VALID.to_vec();
    *unsupported.get_mut(34).ok_or("missing version")? = 0x21;
    let mut short = VALID.to_vec();
    *short.get_mut(37).ok_or("missing address count")? = 3;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(&unsupported)?),
            ReceiveEvent::Frame(capture(&short)?),
        ],
        Some(0),
    )?;
    let report = monitor(None, 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    let [first, second] = report.observations() else {
        return Err("missing failures".into());
    };
    assert_eq!(first.evidence(), &VrrpEvidence::UnsupportedVersion(2));
    assert_eq!(
        second.evidence(),
        &VrrpEvidence::Malformed(VrrpMalformed::Truncated)
    );
    Ok(())
}

#[test]
fn generic_link_keeps_v2_unsupported_and_debug_hides_its_authentication_bytes()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(V2_AUTH)?)], Some(0))?;
    let report = monitor(Some(42), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    let item = report
        .observations()
        .first()
        .ok_or("missing VRRPv2 record")?;
    assert_eq!(item.evidence(), &VrrpEvidence::UnsupportedVersion(2));
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert!(
        item.frame()
            .bytes()
            .windows(8)
            .any(|bytes| bytes == b"VRRPauth")
    );
    let debug = format!("{report:?}");
    for marker in [
        "VRRPauth",
        "5652525061757468",
        "86, 82, 82, 80, 97, 117, 116, 104",
    ] {
        assert!(!debug.contains(marker));
    }
    Ok(())
}

#[test]
fn foreign_vlan_and_capture_provenance_do_not_count_as_claims() -> Result<(), Box<dyn Error>> {
    let mut vlan = VALID.to_vec();
    vlan.splice(12..14, [0x81, 0, 0, 1, 0x08, 0]);
    let mut foreign = VALID.to_vec();
    *foreign.get_mut(5).ok_or("missing destination")? = 0x13;
    let truncated = captured(
        VALID.to_vec(),
        Some(identity()?),
        u32::try_from(VALID.len() + 1)?,
    )?;
    let unknown = captured(VALID.to_vec(), None, u32::try_from(VALID.len())?)?;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(&vlan)?),
            ReceiveEvent::Frame(capture(&foreign)?),
            ReceiveEvent::Frame(truncated),
            ReceiveEvent::Frame(unknown),
        ],
        Some(0),
    )?;
    let report = monitor(None, 4, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unrelated_packets(), 2);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    Ok(())
}

#[test]
fn foreign_ip_destination_or_protocol_never_becomes_vrrp_evidence() -> Result<(), Box<dyn Error>> {
    let mut wrong_destination = VALID.to_vec();
    *wrong_destination
        .get_mut(33)
        .ok_or("missing IPv4 destination")? = 19;
    let mut wrong_protocol = VALID.to_vec();
    *wrong_protocol.get_mut(23).ok_or("missing IPv4 protocol")? = 17;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(&wrong_destination)?),
            ReceiveEvent::Frame(capture(&wrong_protocol)?),
        ],
        Some(0),
    )?;
    let report = monitor(None, 2, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unrelated_packets(), 2);
    Ok(())
}

#[test]
fn malformed_ipv4_headers_and_every_incomplete_message_prefix_are_not_claims()
-> Result<(), Box<dyn Error>> {
    let mut bad_reserved_flag = VALID.to_vec();
    *bad_reserved_flag.get_mut(20).ok_or("missing IP flags")? |= 0x80;
    let mut declared_too_long = VALID.to_vec();
    declared_too_long
        .get_mut(16..18)
        .ok_or("missing IP length")?
        .copy_from_slice(&u16::MAX.to_be_bytes());
    let mut frames = vec![bad_reserved_flag, declared_too_long];
    // The complete IP packet ends at byte 50; later bytes are link padding
    for end in 0..50 {
        frames.push(VALID.get(..end).ok_or("invalid prefix")?.to_vec());
    }
    let count = u32::try_from(frames.len())?;
    let events = frames
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report = monitor(None, count, 8_192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), count);
    assert!(
        report
            .observations()
            .iter()
            .all(|item| !matches!(item.evidence(), VrrpEvidence::Advertisement(_)))
    );
    Ok(())
}

#[test]
fn outbound_candidates_are_counted_but_never_interpreted_as_peer_evidence()
-> Result<(), Box<dyn Error>> {
    let outgoing = captured_with_direction(
        VALID.to_vec(),
        Some(identity()?),
        u32::try_from(VALID.len())?,
        l2_capture::Direction::Outbound,
    )?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(outgoing)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Inconclusive);
    assert_eq!(report.summary().outbound_packets(), 1);
    assert!(report.observations().is_empty());
    Ok(())
}

#[test]
fn an_observed_claim_and_capture_loss_are_both_preserved() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(VALID)?)], Some(2))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), VrrpStatus::Observed);
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().capture_loss(), Some(2));
    Ok(())
}

#[test]
fn silence_cancellation_loss_and_expired_deadlines_never_claim_a_router()
-> Result<(), Box<dyn Error>> {
    for loss in [None, Some(0), Some(2)] {
        let mut link = Link::new(vec![], loss)?;
        let report = monitor(None, 4, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), VrrpStatus::Inconclusive);
        assert_eq!(report.summary().capture_loss(), loss);
        assert_eq!(report.summary().sent_packets(), 0);
    }
    let mut link = Link::new(vec![], Some(0))?;
    let cancelled = monitor(None, 4, 4_096)?.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(cancelled.summary().stop_reason(), StopReason::Cancelled);
    let expired =
        monitor(None, 4, 4_096)?.run_until(&mut link, &AtomicBool::new(false), Instant::now())?;
    assert_eq!(expired.summary().stop_reason(), StopReason::Deadline);
    assert!(link.sent.is_empty());
    Ok(())
}

#[test]
fn report_debug_hides_untrusted_backend_error_text() -> Result<(), Box<dyn Error>> {
    let mut link = crate::sensitive_error::SensitiveErrorLink::new()?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert_eq!(
        report.summary().transport_error().map(ToString::to_string),
        Some(crate::sensitive_error::MARKER.to_owned())
    );
    assert!(!format!("{report:?}").contains(crate::sensitive_error::MARKER));
    Ok(())
}

#[test]
fn repeated_candidates_stop_at_the_bounded_observation_limit() -> Result<(), Box<dyn Error>> {
    let frames = (0..80)
        .map(|_| Ok(ReceiveEvent::Frame(capture(VALID)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(frames, Some(0))?;
    let report = monitor(None, 80, 8_192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    Ok(())
}
