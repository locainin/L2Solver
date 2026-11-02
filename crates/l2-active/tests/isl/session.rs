use std::{error::Error, sync::atomic::AtomicBool, time::Instant};

use l2_active::{
    ReceiveEvent, StopReason,
    isl::{IslEvidence, IslMalformed, IslMonitor, IslObservation, IslStatus},
};

use crate::{fixture, support::Link};

#[test]
fn independent_isl_frame_exposes_bounded_header_claims_without_a_send() -> Result<(), Box<dyn Error>>
{
    let mut link = Link::new(vec![fixture::event(fixture::VALID)?], Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.status(), IslStatus::Observed);
    let observation = report.observations().first().ok_or("missing ISL frame")?;
    let IslEvidence::Frame(header) = observation.evidence() else {
        return Err("ISL header was not decoded".into());
    };
    assert_eq!(header.destination_prefix(), [1, 0, 0x0c, 0, 0]);
    assert_eq!(header.source_mac(), [2, 0, 0, 0, 0, 2]);
    assert_eq!(header.media_type(), 0);
    assert_eq!(header.user(), 3);
    assert_eq!(header.priority(), 3);
    assert_eq!(header.declared_length(), 78);
    assert_eq!(header.llc(), [0xaa, 0xaa, 3]);
    assert_eq!(header.hsa(), [0, 0, 0x0c]);
    assert_eq!(header.vlan_id(), 37);
    assert!(header.bpdu());
    assert_eq!(header.port_index(), 17);
    assert_eq!(header.reserved(), 0);
    assert_eq!(header.inner_frame_length(), 66);
    assert_eq!(observation.frame().bytes(), fixture::VALID);
    assert_eq!(
        observation.frame().metadata().linux_interface(),
        Some(crate::support::identity()?)
    );
    assert!(!report.summary().send_attempted());
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[test]
fn isl_debug_omits_inner_user_traffic_and_complete_raw_frame() -> Result<(), Box<dyn Error>> {
    let mut link = Link::new(vec![fixture::event(fixture::VALID)?], Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let debug = format!("{report:?}");
    assert!(!debug.contains("PRIVATE-USER-CONTENT"));
    assert!(!debug.contains("80, 82, 73, 86, 65, 84, 69"));
    Ok(())
}

#[test]
fn isl_all_ethernet_user_nibbles_and_both_multicast_prefixes_are_supported()
-> Result<(), Box<dyn Error>> {
    let mut frames = Vec::new();
    for first in [1, 3] {
        for user in 0..16 {
            let frame = fixture::change(&fixture::change(fixture::VALID, 0, first)?, 5, user)?;
            frames.push(fixture::event(&frame)?);
        }
    }
    let mut link = Link::new(frames, Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(40, 8192)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 32);
    assert!(
        report
            .observations()
            .iter()
            .all(|item| matches!(item.evidence(), IslEvidence::Frame(_)))
    );
    assert_eq!(link.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}

#[test]
fn isl_retains_malformed_unsupported_media_and_unspecified_length_distinctly()
-> Result<(), Box<dyn Error>> {
    let short_length = fixture::change(fixture::VALID, 13, 29)?;
    let truncated_length = fixture::change(fixture::VALID, 13, 255)?;
    let bad_source = fixture::change(fixture::VALID, 6, 1)?;
    let mut bad_inner = fixture::VALID.to_vec();
    *bad_inner.get_mut(38).ok_or("missing inner ethertype")? = 5;
    *bad_inner.get_mut(39).ok_or("missing inner ethertype")? = 0xdd;
    let frames: &[&[u8]] = &[
        fixture::FOREIGN,
        fixture::UNSUPPORTED_MEDIA,
        fixture::UNSUPPORTED_LENGTH,
        fixture::INVALID_LLC,
        &short_length,
        &truncated_length,
        &bad_source,
        &bad_inner,
    ];
    let events = frames
        .iter()
        .map(|frame| fixture::event(frame))
        .collect::<Result<Vec<_>, _>>()?;
    let mut link = Link::new(events, Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(12, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.unmatched_packets(), 1);
    let evidence = |index| {
        report
            .observations()
            .get(index)
            .map(IslObservation::evidence)
    };
    assert!(matches!(
        evidence(0),
        Some(IslEvidence::UnsupportedMedia(1))
    ));
    assert!(matches!(evidence(1), Some(IslEvidence::UnsupportedLength)));
    assert!(matches!(
        evidence(2),
        Some(IslEvidence::Malformed(IslMalformed::Header))
    ));
    assert!(matches!(
        evidence(3),
        Some(IslEvidence::Malformed(IslMalformed::Length))
    ));
    assert!(matches!(
        evidence(4),
        Some(IslEvidence::Malformed(IslMalformed::Length))
    ));
    assert!(matches!(
        evidence(5),
        Some(IslEvidence::Malformed(IslMalformed::SourceMac))
    ));
    assert!(matches!(
        evidence(6),
        Some(IslEvidence::Malformed(IslMalformed::InnerEthernet))
    ));
    assert_eq!(report.status(), IslStatus::Inconclusive);
    Ok(())
}

#[test]
fn isl_never_claims_crc_validation_for_unchecked_fcs_bytes() -> Result<(), Box<dyn Error>> {
    let mut wire = fixture::VALID.to_vec();
    *wire.last_mut().ok_or("missing inner FCS")? ^= 1;
    let mut link = Link::new(vec![fixture::event(&wire)?], Some(0))?;
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(matches!(
        report.observations().first().map(IslObservation::evidence),
        Some(IslEvidence::Frame(_))
    ));
    assert!(!format!("{report:?}").to_lowercase().contains("valid crc"));
    Ok(())
}

#[test]
fn isl_capture_limits_cancellation_failure_and_loss_are_accounted_without_sending()
-> Result<(), Box<dyn Error>> {
    let monitor = IslMonitor::new(fixture::limits(4, 4096)?);
    let mut link = Link::new(
        vec![fixture::event(fixture::VALID)?, ReceiveEvent::InterfaceDown],
        Some(3),
    )?;
    link.backlog = Some(true);
    let report = monitor.run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::InterfaceDown);
    assert_eq!(report.summary().capture_loss(), Some(3));
    assert_eq!(report.summary().capture_backlog(), Some(true));
    assert_eq!(report.observations().len(), 1);
    let mut idle = Link::new(vec![fixture::event(fixture::VALID)?], None)?;
    assert_eq!(
        monitor
            .run(&mut idle, &AtomicBool::new(true))?
            .summary()
            .stop_reason(),
        StopReason::Cancelled
    );
    assert_eq!(
        monitor
            .run_until(&mut idle, &AtomicBool::new(false), Instant::now())?
            .summary()
            .stop_reason(),
        StopReason::Deadline
    );
    assert!(link.sent.is_empty() && idle.sent.is_empty());
    Ok(())
}
