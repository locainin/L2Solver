use std::{
    error::Error,
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    ActiveLink, Limits, PreSendUsage, ReceiveEvent, StopReason,
    first_hop::hsrp::{
        HsrpEvidence, HsrpMalformed, HsrpMonitor, HsrpOpcode, HsrpState, HsrpStatus,
    },
};

use l2_capture::LinuxInterfaceIdentity;

use crate::{
    fixture,
    support::{Link, captured, captured_with_direction, identity},
};

#[test]
fn independently_encoded_hsrp_claim_is_observed_without_sending() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![fixture::event(fixture::ADVERTISEMENT.to_vec())?],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(Some(0), fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert!(link.sent.is_empty());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(report.status(), HsrpStatus::Observed);
    let observation = report.observations().first().ok_or("missing HSRP claim")?;
    let HsrpEvidence::Advertisement(claim) = observation.evidence() else {
        return Err("expected a decoded HSRP claim".into());
    };
    assert_eq!(claim.group(), 0);
    assert_eq!(claim.source_mac().bytes(), [2, 0, 0, 0, 0, 2]);
    assert_eq!(claim.source_ip(), std::net::Ipv4Addr::new(192, 0, 2, 2));
    assert_eq!(claim.virtual_ip(), fixture::target());
    assert_eq!(claim.opcode(), HsrpOpcode::Hello);
    assert_eq!(claim.state(), HsrpState::Active);
    assert_eq!(
        (
            claim.priority(),
            claim.hello_seconds(),
            claim.hold_seconds()
        ),
        (120, 3, 10)
    );
    assert_eq!(observation.frame().bytes(), fixture::ADVERTISEMENT);
    assert_eq!(report.summary().received_packets(), 1);
    Ok(())
}

#[test]
fn report_and_observation_debug_never_show_authentication_or_padding() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(
        vec![
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
            fixture::event(fixture::EXTENSION.to_vec())?,
            fixture::event(fixture::mutate(44, 3, true)?)?,
        ],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    let mut outputs = vec![format!("{report:?}")];
    for observation in report.observations() {
        outputs.push(format!("{observation:?}"));
        outputs.push(format!("{:?}", observation.evidence()));
    }
    for output in outputs {
        for secret in [
            fixture::AUTH_MARKER,
            fixture::PAD_MARKER,
            "4175746850407373",
            "5041442d534543524554",
            "5041442D534543524554",
            "65, 117, 116, 104, 80, 64, 115, 115",
            "80, 65, 68, 45, 83, 69, 67, 82, 69, 84",
            "TRAILER-SECRET",
            "545241494c45522d534543524554",
        ] {
            assert!(
                !output.contains(secret),
                "sensitive bytes leaked into Debug"
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_headers_and_unknown_versions_never_create_claims() -> Result<(), Box<dyn Error>> {
    for (offset, value, fix, expected) in [
        (21, 64, true, HsrpEvidence::Malformed(HsrpMalformed::Ipv4)),
        (40, 0, false, HsrpEvidence::Malformed(HsrpMalformed::Udp)),
        (
            43,
            9,
            true,
            HsrpEvidence::Malformed(HsrpMalformed::Protocol),
        ),
        (
            44,
            3,
            true,
            HsrpEvidence::Malformed(HsrpMalformed::Protocol),
        ),
        (
            49,
            1,
            true,
            HsrpEvidence::Malformed(HsrpMalformed::Protocol),
        ),
        (
            46,
            2,
            true,
            HsrpEvidence::Malformed(HsrpMalformed::Protocol),
        ),
        (42, 2, true, HsrpEvidence::UnsupportedVersion(2)),
    ] {
        let mut link = Link::new(
            vec![fixture::event(fixture::mutate(offset, value, fix)?)?],
            Some(0),
        )?;
        let report =
            HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
        let observation = report
            .observations()
            .first()
            .ok_or("missing recognized candidate")?;
        assert_eq!(observation.evidence(), &expected, "offset {offset}");
        assert_ne!(report.status(), HsrpStatus::Observed);
    }
    Ok(())
}

#[test]
fn selected_group_excludes_other_groups_without_inferring_absence() -> Result<(), Box<dyn Error>> {
    let frame = fixture::mutate(48, 255, true)?;
    let mut selected = Link::new(vec![fixture::event(frame.clone())?], Some(0))?;
    let report = HsrpMonitor::new(Some(0), fixture::limits()?)
        .run(&mut selected, &AtomicBool::new(false))?;
    assert_eq!(report.status(), HsrpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unmatched_packets(), 1);
    let mut explicit = Link::new(vec![fixture::event(frame.clone())?], Some(0))?;
    let selected = HsrpMonitor::new(Some(255), fixture::limits()?)
        .run(&mut explicit, &AtomicBool::new(false))?;
    assert_eq!(selected.status(), HsrpStatus::Observed);
    let mut wildcard = Link::new(vec![fixture::event(frame)?], Some(0))?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut wildcard, &AtomicBool::new(false))?;
    let HsrpEvidence::Advertisement(claim) = report
        .observations()
        .first()
        .ok_or("missing group 255")?
        .evidence()
    else {
        return Err("expected a decoded HSRP claim".into());
    };
    assert_eq!(claim.group(), 255);
    Ok(())
}

#[test]
fn repeated_frames_preserve_each_capture_and_are_charged_individually() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(
        vec![
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
        ],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 2);
    assert_eq!(report.summary().received_packets(), 2);
    Ok(())
}

#[test]
fn candidate_count_is_bounded_even_when_all_frames_repeat() -> Result<(), Box<dyn Error>> {
    let events = (0..80)
        .map(|_| fixture::event(fixture::ADVERTISEMENT.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    Ok(())
}

#[test]
fn udp_checksum_is_checked_when_present_and_optional_for_ipv4() -> Result<(), Box<dyn Error>> {
    let mut absent = fixture::ADVERTISEMENT.to_vec();
    absent
        .get_mut(40..42)
        .ok_or("missing UDP checksum")?
        .fill(0);
    let mut invalid = fixture::ADVERTISEMENT.to_vec();
    *invalid.get_mut(40).ok_or("missing UDP checksum")? ^= 1;
    let mut link = Link::new(
        vec![fixture::event(absent)?, fixture::event(invalid)?],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    let [valid, invalid] = report.observations() else {
        return Err("missing checksum evidence".into());
    };
    let HsrpEvidence::Advertisement(claim) = valid.evidence() else {
        return Err("zero UDP checksum must be accepted for IPv4".into());
    };
    assert!(!claim.udp_checksum_present());
    assert_eq!(
        invalid.evidence(),
        &HsrpEvidence::Malformed(HsrpMalformed::Udp)
    );
    Ok(())
}

#[test]
fn independent_ipv4_options_and_opaque_extensions_preserve_v1_claims() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(
        vec![
            fixture::event(fixture::IP_OPTIONS.to_vec())?,
            fixture::event(fixture::MAX_IP_OPTIONS.to_vec())?,
            fixture::event(fixture::EXTENSION.to_vec())?,
        ],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(Some(0), fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 3);
    for item in report.observations() {
        let HsrpEvidence::Advertisement(claim) = item.evidence() else {
            return Err("valid independent fixture was rejected".into());
        };
        assert_eq!(claim.group(), 0);
        assert_eq!(claim.virtual_ip(), fixture::target());
        assert!(claim.udp_checksum_present());
    }
    assert_eq!(
        report
            .observations()
            .get(2)
            .ok_or("missing extension")?
            .frame()
            .bytes(),
        fixture::EXTENSION
    );
    Ok(())
}

#[test]
fn v2_multicast_profile_is_not_misinterpreted_as_v1() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![fixture::event(fixture::VERSION_TWO.to_vec())?],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), HsrpStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unmatched_packets(), 1);
    Ok(())
}

#[test]
fn selected_group_preserves_bad_udp_length_as_malformed_when_group_is_bounded()
-> Result<(), Box<dyn Error>> {
    for length in [27_u16, 29] {
        let mut bytes = fixture::ADVERTISEMENT.to_vec();
        bytes
            .get_mut(38..40)
            .ok_or("missing UDP length")?
            .copy_from_slice(&length.to_be_bytes());
        let mut link = Link::new(vec![fixture::event(bytes)?], Some(0))?;
        let report = HsrpMonitor::new(Some(0), fixture::limits()?)
            .run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing malformed length")?
                .evidence(),
            &HsrpEvidence::Malformed(HsrpMalformed::Udp),
            "UDP length {length}"
        );
    }
    Ok(())
}

#[test]
fn invalid_network_headers_never_create_claims() -> Result<(), Box<dyn Error>> {
    let mut bad_ip_checksum = fixture::ADVERTISEMENT.to_vec();
    *bad_ip_checksum.get_mut(24).ok_or("missing IP checksum")? ^= 1;
    let mut fragment = fixture::ADVERTISEMENT.to_vec();
    *fragment.get_mut(20).ok_or("missing IP flags")? |= 0x20;
    fixture::fix_checksums(&mut fragment)?;
    let mut reserved_flag = fixture::ADVERTISEMENT.to_vec();
    *reserved_flag.get_mut(20).ok_or("missing IP flags")? |= 0x80;
    fixture::fix_checksums(&mut reserved_flag)?;
    let mut source = fixture::ADVERTISEMENT.to_vec();
    source
        .get_mut(26..30)
        .ok_or("missing source address")?
        .fill(0);
    fixture::fix_checksums(&mut source)?;
    let mut source_mac = fixture::ADVERTISEMENT.to_vec();
    *source_mac.get_mut(6).ok_or("missing source MAC")? |= 1;
    for (bytes, reason) in [
        (bad_ip_checksum, HsrpMalformed::Ipv4),
        (fragment, HsrpMalformed::Ipv4),
        (reserved_flag, HsrpMalformed::Ipv4),
        (source, HsrpMalformed::Ipv4),
        (source_mac, HsrpMalformed::SourceMac),
    ] {
        let mut link = Link::new(vec![fixture::event(bytes)?], Some(0))?;
        let report =
            HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing malformed evidence")?
                .evidence(),
            &HsrpEvidence::Malformed(reason)
        );
        assert_eq!(report.status(), HsrpStatus::Inconclusive);
    }
    Ok(())
}

#[test]
fn selected_group_is_never_read_from_ip_or_udp_padding() -> Result<(), Box<dyn Error>> {
    for (start, length) in [(16, 20_u16), (38, 14_u16)] {
        let mut bytes = fixture::ADVERTISEMENT.to_vec();
        bytes
            .get_mut(start..start + 2)
            .ok_or("missing length")?
            .copy_from_slice(&length.to_be_bytes());
        let mut link = Link::new(vec![fixture::event(bytes)?], Some(0))?;
        let report = HsrpMonitor::new(Some(0), fixture::limits()?)
            .run(&mut link, &AtomicBool::new(false))?;
        assert!(report.observations().is_empty(), "length field at {start}");
        assert_eq!(report.unmatched_packets(), 1);
    }
    Ok(())
}

#[test]
fn hello_timers_follow_rfc_rules_but_other_opcodes_keep_opaque_values() -> Result<(), Box<dyn Error>>
{
    for (opcode, expected) in [
        (0, HsrpOpcode::Hello),
        (1, HsrpOpcode::Coup),
        (2, HsrpOpcode::Resign),
    ] {
        let mut bytes = fixture::mutate(43, opcode, false)?;
        if opcode != 0 {
            bytes.get_mut(45..47).ok_or("missing timers")?.fill(0);
        }
        fixture::fix_checksums(&mut bytes)?;
        let mut link = Link::new(vec![fixture::event(bytes)?], Some(0))?;
        let report =
            HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
        let HsrpEvidence::Advertisement(claim) = report
            .observations()
            .first()
            .ok_or("missing claim")?
            .evidence()
        else {
            return Err("known opcode was rejected".into());
        };
        assert_eq!(claim.opcode(), expected);
    }
    Ok(())
}

#[test]
fn known_states_and_unassigned_virtual_ip_are_preserved_as_claims() -> Result<(), Box<dyn Error>> {
    for (state, expected) in [
        (0, HsrpState::Initial),
        (1, HsrpState::Learn),
        (2, HsrpState::Listen),
        (4, HsrpState::Speak),
        (8, HsrpState::Standby),
        (16, HsrpState::Active),
    ] {
        let mut bytes = fixture::mutate(44, state, false)?;
        *bytes.get_mut(47).ok_or("missing priority")? = 0;
        bytes
            .get_mut(58..62)
            .ok_or("missing virtual address")?
            .fill(0);
        fixture::fix_checksums(&mut bytes)?;
        let mut link = Link::new(vec![fixture::event(bytes)?], Some(0))?;
        let report =
            HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
        let HsrpEvidence::Advertisement(claim) = report
            .observations()
            .first()
            .ok_or("missing claim")?
            .evidence()
        else {
            return Err("known state was rejected".into());
        };
        assert_eq!(claim.state(), expected);
        assert_eq!(claim.priority(), 0);
        assert!(claim.virtual_ip().is_unspecified());
    }
    Ok(())
}

#[test]
fn capture_provenance_vlan_and_direction_are_not_peer_evidence() -> Result<(), Box<dyn Error>> {
    let mut vlan = fixture::ADVERTISEMENT.to_vec();
    vlan.splice(12..14, [0x81, 0, 0, 1, 0x08, 0]);
    let mut foreign = fixture::ADVERTISEMENT.to_vec();
    *foreign.get_mut(5).ok_or("missing destination MAC")? = 3;
    let truncated = captured(
        fixture::ADVERTISEMENT.to_vec(),
        Some(identity()?),
        u32::try_from(fixture::ADVERTISEMENT.len() + 1)?,
    )?;
    let unknown = captured(
        fixture::ADVERTISEMENT.to_vec(),
        None,
        u32::try_from(fixture::ADVERTISEMENT.len())?,
    )?;
    let outgoing = captured_with_direction(
        fixture::ADVERTISEMENT.to_vec(),
        Some(identity()?),
        u32::try_from(fixture::ADVERTISEMENT.len())?,
        l2_capture::Direction::Outbound,
    )?;
    let events = vec![
        fixture::event(vlan)?,
        fixture::event(foreign)?,
        ReceiveEvent::Frame(truncated),
        ReceiveEvent::Frame(unknown),
        ReceiveEvent::Frame(outgoing),
    ];
    let mut link = Link::new(events, Some(0))?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert!(report.observations().is_empty());
    assert_eq!(report.unmatched_packets(), 2);
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.summary().outbound_packets(), 1);
    Ok(())
}

#[test]
fn expired_deadline_never_sends_or_claims_a_router() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![fixture::event(fixture::ADVERTISEMENT.to_vec())?],
        Some(0),
    )?;
    let report = HsrpMonitor::new(None, fixture::limits()?).run_until(
        &mut link,
        &AtomicBool::new(false),
        Instant::now(),
    )?;
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert_eq!(report.status(), HsrpStatus::Inconclusive);
    assert!(link.sent.is_empty());
    Ok(())
}

struct ErrorLink {
    source: LinuxInterfaceIdentity,
}

impl ActiveLink for ErrorLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.source
    }
    fn send(&mut self, _: &[u8], _: Instant, _: &AtomicBool) -> io::Result<()> {
        Err(io::Error::other("unexpected send"))
    }
    fn receive(&mut self, _: Instant, _: &AtomicBool, _: usize) -> io::Result<ReceiveEvent> {
        Err(io::Error::other(
            "AuthP@ss PAD-SECRET 4175746850407373 5041442d534543524554",
        ))
    }
    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Ok(None)
    }
    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Err(io::Error::other("AuthP@ss PAD-SECRET"))
    }
    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Err(io::Error::other("AuthP@ss PAD-SECRET"))
    }
}

#[test]
fn report_debug_never_prints_backend_error_strings() -> Result<(), Box<dyn Error>> {
    let mut link = ErrorLink {
        source: identity()?,
    };
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert!(report.summary().transport_error().is_some());
    let output = format!("{report:?}");
    for secret in [
        fixture::AUTH_MARKER,
        fixture::PAD_MARKER,
        "4175746850407373",
        "5041442d534543524554",
    ] {
        assert!(
            !output.contains(secret),
            "backend error leaked into report Debug"
        );
    }
    Ok(())
}

#[test]
fn every_truncated_prefix_is_unmatched_or_malformed_never_a_claim() -> Result<(), Box<dyn Error>> {
    let complete_length = 62;
    let events = (0..complete_length)
        .map(|end| {
            fixture::event(
                fixture::ADVERTISEMENT
                    .get(..end)
                    .ok_or("missing prefix")?
                    .to_vec(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert!(
        report
            .observations()
            .iter()
            .all(|item| !matches!(item.evidence(), HsrpEvidence::Advertisement(_)))
    );
    assert_ne!(report.status(), HsrpStatus::Observed);
    Ok(())
}

#[test]
fn cancellation_and_capture_loss_remain_separate_from_observed_claims() -> Result<(), Box<dyn Error>>
{
    let mut cancelled_link = Link::new(vec![], Some(0))?;
    let cancelled = HsrpMonitor::new(None, fixture::limits()?)
        .run(&mut cancelled_link, &AtomicBool::new(true))?;
    assert_eq!(cancelled.status(), HsrpStatus::Inconclusive);
    assert_eq!(cancelled.summary().stop_reason(), StopReason::Cancelled);
    let mut lossy = Link::new(
        vec![fixture::event(fixture::ADVERTISEMENT.to_vec())?],
        Some(4),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut lossy, &AtomicBool::new(false))?;
    assert_eq!(report.status(), HsrpStatus::Observed);
    assert_eq!(report.summary().capture_loss(), Some(4));
    assert!(lossy.sent.is_empty());
    Ok(())
}

#[test]
fn packet_and_byte_limits_account_for_accepted_frames() -> Result<(), Box<dyn Error>> {
    for (packets, bytes, reason) in [
        (1, 4096, StopReason::PacketLimit),
        (
            4,
            u64::try_from(fixture::ADVERTISEMENT.len())?,
            StopReason::ByteLimit,
        ),
    ] {
        let events = vec![
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
        ];
        let mut link = Link::new(events, Some(0))?;
        let limits = Limits::new(Duration::from_millis(20), packets, bytes)?;
        let report = HsrpMonitor::new(None, limits).run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), HsrpStatus::Observed);
        assert_eq!(report.observations().len(), 1);
        assert_eq!(report.summary().received_packets(), 1);
        assert_eq!(report.summary().stop_reason(), reason);
        assert!(!report.summary().send_attempted());
    }
    Ok(())
}

#[test]
fn backend_deadline_is_reported_separately_from_an_observed_claim() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(
        vec![
            fixture::event(fixture::ADVERTISEMENT.to_vec())?,
            ReceiveEvent::BackendTimedOut,
        ],
        Some(0),
    )?;
    let report =
        HsrpMonitor::new(None, fixture::limits()?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), HsrpStatus::Observed);
    assert_eq!(report.summary().stop_reason(), StopReason::BackendDeadline);
    assert!(link.sent.is_empty());
    Ok(())
}
