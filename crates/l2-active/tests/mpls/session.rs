use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::{
    Limits, ReceiveEvent, StopReason,
    mpls::{MplsEvidence, MplsLabel, MplsMalformed, MplsMonitor, MplsStatus, MplsUnsupported},
};

use crate::{
    fixture::{
        BAD_ALERT, BAD_NULL, DESTINATION, ELI, EXTENSION, IMPLICIT_NULL, MAX_DEPTH, MNA,
        NO_PAYLOAD, NULL_V4, NULL_V6, OVER_DEPTH, SHORT, VALID, ZERO_TTL, capture, monitor,
    },
    support::{Link, captured, captured_with_direction, identity},
};

#[test]
fn independently_encoded_stack_exposes_labels_without_sending_or_payload()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(VALID)?)], Some(0))?;
    let report = monitor(Some(100), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Observed);
    assert!(!report.has_unexpected_top_label());
    assert_eq!(report.summary().sent_packets(), 0);
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    let item = report.observations().first().ok_or("missing MPLS stack")?;
    assert_eq!(item.evidence(), MplsEvidence::Stack);
    assert_eq!(
        item.source_mac().ok_or("missing source MAC")?.bytes(),
        [2, 0, 0, 0, 0, 2]
    );
    let labels = item.labels().collect::<Vec<_>>();
    let [top, bottom] = labels.as_slice() else {
        return Err("expected two labels".into());
    };
    assert_eq!(
        (
            top.value(),
            top.traffic_class(),
            top.bottom_of_stack(),
            top.ttl()
        ),
        (100, 5, false, 64)
    );
    assert_eq!(
        (
            bottom.value(),
            bottom.traffic_class(),
            bottom.bottom_of_stack(),
            bottom.ttl()
        ),
        (1_048_575, 7, true, 1)
    );
    assert_eq!(item.captured_bytes_after_stack(), Some(VALID.len() - 22));
    assert_eq!(item.frame().bytes(), VALID);
    for marker in [
        "SENSITIVE-PAYLOAD",
        "53454e534954495645",
        "83, 69, 78, 83, 73, 84, 73, 86, 69",
    ] {
        assert!(!format!("{report:?}").contains(marker));
    }
    Ok(())
}

#[test]
fn top_label_expectations_and_zero_ttl_are_observations_not_forwarding_verdicts()
-> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(ZERO_TTL)?)], Some(0))?;
    let report = monitor(Some(101), 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Observed);
    assert_eq!(report.expected_top_label(), Some(101));
    assert!(report.has_unexpected_top_label());
    assert!(
        report
            .observations()
            .first()
            .ok_or("missing stack")?
            .top_ttl_is_zero()
    );
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(VALID)?)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert!(!report.has_unexpected_top_label());
    assert!(
        !report
            .observations()
            .first()
            .ok_or("missing stack")?
            .top_ttl_is_zero()
    );
    Ok(())
}

#[test]
fn explicit_null_at_bottom_is_accepted_but_invalid_special_labels_are_retained()
-> Result<(), Box<dyn Error>> {
    for frame in [NULL_V4, NULL_V6] {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), MplsStatus::Observed);
    }
    for frame in [BAD_NULL, BAD_ALERT, IMPLICIT_NULL] {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), MplsStatus::Inconclusive);
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing candidate")?
                .evidence(),
            MplsEvidence::Malformed(MplsMalformed::SpecialPurposeLabel)
        );
    }
    Ok(())
}

#[test]
fn unsupported_special_purpose_entries_stop_before_action_or_extended_data()
-> Result<(), Box<dyn Error>> {
    for (frame, value) in [(MNA, 4), (ELI, 7), (EXTENSION, 15)] {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        let item = report.observations().first().ok_or("missing candidate")?;
        assert_eq!(
            item.evidence(),
            MplsEvidence::Unsupported(MplsUnsupported::SpecialPurposeLabel(value))
        );
        assert_eq!(
            item.labels().map(MplsLabel::value).collect::<Vec<_>>(),
            vec![100, value]
        );
        assert_eq!(item.captured_bytes_after_stack(), None);
    }
    Ok(())
}

#[test]
fn all_other_special_purpose_values_are_preserved_as_unsupported() -> Result<(), Box<dyn Error>> {
    for value in 4_u8..=15 {
        let mut frame = MNA.to_vec();
        let field = frame.get_mut(20).ok_or("missing special-purpose label")?;
        *field = (value << 4) | (*field & 0x0f);
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(&frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        let item = report.observations().first().ok_or("missing candidate")?;
        assert_eq!(
            item.evidence(),
            MplsEvidence::Unsupported(MplsUnsupported::SpecialPurposeLabel(u32::from(value)))
        );
        assert_eq!(item.labels().count(), 2);
    }
    Ok(())
}

#[test]
fn every_prefix_through_the_bottom_entry_is_never_a_complete_stack() -> Result<(), Box<dyn Error>> {
    let frames = (0..=22)
        .map(|end| {
            Ok(ReceiveEvent::Frame(capture(
                VALID.get(..end).ok_or("invalid prefix")?,
            )?))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(frames, Some(0))?;
    let report = monitor(None, 23, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Inconclusive);
    assert_eq!(report.summary().received_packets(), 23);
    assert!(
        report
            .observations()
            .iter()
            .all(|item| item.evidence() != MplsEvidence::Stack)
    );
    Ok(())
}

#[test]
fn missing_stack_or_payload_and_excessive_depth_are_not_accepted() -> Result<(), Box<dyn Error>> {
    for (frame, expected) in [
        (
            SHORT,
            MplsEvidence::Malformed(MplsMalformed::TruncatedStack),
        ),
        (
            NO_PAYLOAD,
            MplsEvidence::Malformed(MplsMalformed::MissingPayload),
        ),
        (
            OVER_DEPTH,
            MplsEvidence::Unsupported(MplsUnsupported::StackDepthLimit),
        ),
    ] {
        let mut link = Link::new(vec![ReceiveEvent::Frame(capture(frame)?)], Some(0))?;
        let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
        assert_eq!(report.status(), MplsStatus::Inconclusive);
        assert_eq!(
            report
                .observations()
                .first()
                .ok_or("missing candidate")?
                .evidence(),
            expected
        );
    }
    let mut link = Link::new(vec![ReceiveEvent::Frame(capture(MAX_DEPTH)?)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Observed);
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing candidate")?
            .labels()
            .count(),
        16
    );
    Ok(())
}

#[test]
fn wrong_destination_vlan_or_ethertype_remains_outside_scope() -> Result<(), Box<dyn Error>> {
    let mut foreign = VALID.to_vec();
    *foreign.get_mut(5).ok_or("missing destination")? = 2;
    let mut upstream = VALID.to_vec();
    *upstream.get_mut(13).ok_or("missing EtherType")? = 0x48;
    let mut tagged = VALID.to_vec();
    tagged.splice(12..12, [0x81, 0, 0, 1]);
    let frames = [foreign, upstream, tagged]
        .iter()
        .map(|frame| Ok(ReceiveEvent::Frame(capture(frame)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(frames, Some(0))?;
    let report = monitor(None, 3, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.unrelated_packets(), 3);
    Ok(())
}

#[test]
fn invalid_source_is_preserved_and_untrusted_capture_provenance_is_not_interpreted()
-> Result<(), Box<dyn Error>> {
    let mut bad_source = VALID.to_vec();
    bad_source.get_mut(6..12).ok_or("missing source")?.fill(0);
    let original_len = u32::try_from(VALID.len())?;
    let outbound = captured_with_direction(
        VALID.to_vec(),
        Some(identity()?),
        original_len,
        l2_capture::Direction::Outbound,
    )?;
    let unknown = captured(VALID.to_vec(), None, original_len)?;
    let truncated = captured(VALID.to_vec(), Some(identity()?), original_len + 1)?;
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(&bad_source)?),
            ReceiveEvent::Frame(outbound),
            ReceiveEvent::Frame(unknown),
            ReceiveEvent::Frame(truncated),
        ],
        Some(0),
    )?;
    let report = monitor(None, 4, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report
            .observations()
            .first()
            .ok_or("missing candidate")?
            .evidence(),
        MplsEvidence::Malformed(MplsMalformed::SourceMac)
    );
    assert_eq!(report.summary().outbound_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.summary().truncated_packets(), 1);
    Ok(())
}

#[test]
fn vlan_auxiliary_metadata_is_unscoped_even_when_frame_bytes_are_untagged()
-> Result<(), Box<dyn Error>> {
    use l2_capture::{
        CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, VlanAuxData,
    };

    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 5,
        },
        u32::try_from(VALID.len())?,
        None,
        None,
        Direction::Inbound,
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 10,
        }),
        FcsStatus::Absent,
    )
    .with_linux_interface(identity()?);
    let frame = CapturedFrame::new(VALID.to_vec(), metadata)?;
    let mut link = Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    let report = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), MplsStatus::Inconclusive);
    assert!(report.observations().is_empty());
    assert_eq!(report.summary().unscoped_packets(), 1);
    Ok(())
}

#[test]
fn receive_budgets_and_observation_capacity_bound_work_without_sending()
-> Result<(), Box<dyn Error>> {
    let frames = (0..80)
        .map(|_| Ok(ReceiveEvent::Frame(capture(VALID)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = Link::new(frames, Some(0))?;
    let report = monitor(None, 80, 8_192)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    let mut link = Link::new(
        vec![
            ReceiveEvent::Frame(capture(VALID)?),
            ReceiveEvent::Frame(capture(VALID)?),
        ],
        Some(0),
    )?;
    let report =
        monitor(None, 2, u64::try_from(VALID.len())?)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::ByteLimit);
    assert_eq!(report.summary().received_packets(), 1);
    Ok(())
}

#[test]
fn cancellation_expiration_and_capture_loss_are_preserved() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![], Some(2))?;
    let cancelled = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(true))?;
    assert_eq!(cancelled.status(), MplsStatus::Inconclusive);
    assert_eq!(cancelled.summary().stop_reason(), StopReason::Cancelled);
    let expired =
        monitor(None, 1, 4_096)?.run_until(&mut link, &AtomicBool::new(false), Instant::now())?;
    assert_eq!(expired.summary().stop_reason(), StopReason::Deadline);
    let silent = monitor(None, 1, 4_096)?.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(silent.summary().capture_loss(), Some(2));
    assert_eq!(silent.status(), MplsStatus::Inconclusive);
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
fn invalid_destination_and_out_of_range_expected_label_are_rejected() -> Result<(), Box<dyn Error>>
{
    let limits = Limits::new(std::time::Duration::from_millis(10), 1, 4_096)?;
    assert!(MplsMonitor::new([0; 6], None, limits).is_err());
    assert!(MplsMonitor::new([1, 0, 0, 0, 0, 1], None, limits).is_err());
    assert!(MplsMonitor::new(DESTINATION, Some(1_048_576), limits).is_err());
    assert!(MplsMonitor::new(DESTINATION, Some(1_048_575), limits).is_ok());
    Ok(())
}
