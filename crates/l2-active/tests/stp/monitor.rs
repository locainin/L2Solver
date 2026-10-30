use std::{
    error::Error,
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{
    ReceiveEvent, StopReason,
    stp::{MalformedStp, StpEvidence, StpMonitor},
};
use l2_codecs::{BridgeId, StpVersion};

use crate::{
    fixture::{self, BRIDGE, ROOT, SOURCE},
    support::{Link, captured, identity},
};

#[test]
fn captures_stp_and_rstp_fields_without_transmitting() -> Result<(), Box<dyn Error>> {
    let first = fixture::frame(SOURCE, ROOT, false);
    let second = fixture::frame(SOURCE, ROOT, true);
    let mut link = Link::new(
        vec![fixture::event(first.clone())?, fixture::event(second)?],
        Some(0),
    )?;
    link.send_error = Some(io::ErrorKind::PermissionDenied);
    let report =
        StpMonitor::new(fixture::limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(link.sent_deadline.is_none());
    assert!(!report.summary().send_attempted());
    assert_eq!(report.summary().total_received_packets(), Some(2));
    assert_eq!(report.observations().len(), 2);
    let first_observation = report.observations().first().ok_or("missing STP frame")?;
    assert_eq!(first_observation.frame().bytes(), first);
    assert_eq!(first_observation.evidence(), StpEvidence::Decoded);
    let parsed = first_observation.decoded().ok_or("missing decoded BPDU")?;
    assert_eq!(parsed.version, StpVersion::Stp);
    assert_eq!(parsed.root, Some(BridgeId::from_wire(0x8001, ROOT)));
    assert_eq!(parsed.bridge, Some(BridgeId::from_wire(0x9002, BRIDGE)));
    assert_eq!(parsed.port.map(|port| port.raw), Some(0x8001));
    assert_eq!(parsed.timers.map(|timers| timers.hello_time), Some(0x0200));
    let rapid = report.observations().get(1).ok_or("missing RSTP frame")?;
    assert_eq!(
        rapid.decoded().map(|parsed| parsed.version),
        Some(StpVersion::Rstp)
    );
    assert!(!report.has_sender_root_changes());
    Ok(())
}

#[test]
fn changed_roots_are_compared_only_for_the_same_sender_bridge_and_port()
-> Result<(), Box<dyn Error>> {
    let changed = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let other_sender = [0x02, 0, 0, 0, 0, 2];
    let mut first_link = Link::new(
        vec![
            fixture::event(fixture::frame(SOURCE, ROOT, false))?,
            fixture::event(fixture::frame(other_sender, changed, false))?,
        ],
        Some(0),
    )?;
    let monitor = StpMonitor::new(fixture::limits(10, 4096)?);
    assert!(
        !monitor
            .run(&mut first_link, &AtomicBool::new(false))?
            .has_sender_root_changes()
    );

    let mut second_link = Link::new(
        vec![
            fixture::event(fixture::frame(SOURCE, ROOT, false))?,
            fixture::event(fixture::frame(SOURCE, changed, false))?,
        ],
        Some(0),
    )?;
    let report = monitor.run(&mut second_link, &AtomicBool::new(false))?;
    assert!(report.has_sender_root_changes());

    let mut different_bridge = fixture::frame(SOURCE, changed, false);
    *different_bridge.get_mut(41).ok_or("missing bridge id")? ^= 1;
    let mut different_port = fixture::frame(SOURCE, changed, false);
    *different_port.get_mut(43).ok_or("missing port id")? ^= 1;
    let mut different_link = Link::new(
        vec![
            fixture::event(fixture::frame(SOURCE, ROOT, false))?,
            fixture::event(different_bridge)?,
            fixture::event(different_port)?,
        ],
        Some(0),
    )?;
    let report = monitor.run(&mut different_link, &AtomicBool::new(false))?;
    assert!(!report.has_sender_root_changes());
    Ok(())
}

#[test]
fn malformed_and_unsupported_candidates_retain_exact_frames() -> Result<(), Box<dyn Error>> {
    let mut malformed = fixture::frame(SOURCE, ROOT, false);
    *malformed.get_mut(17).ok_or("missing protocol id")? = 1;
    let mut unsupported = fixture::frame(SOURCE, ROOT, false);
    *unsupported.get_mut(19).ok_or("missing version")? = 3;
    let mut unrelated = fixture::frame(SOURCE, ROOT, false);
    *unrelated.get_mut(0).ok_or("missing destination")? = 2;
    let mut link = Link::new(
        vec![
            fixture::event(malformed.clone())?,
            fixture::event(unsupported.clone())?,
            fixture::event(unrelated)?,
        ],
        Some(0),
    )?;
    let report =
        StpMonitor::new(fixture::limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 2);
    let bad = report
        .observations()
        .first()
        .ok_or("missing malformed frame")?;
    assert!(matches!(bad.evidence(), StpEvidence::Malformed(_)));
    assert_eq!(bad.frame().bytes(), malformed);
    assert!(bad.decoded().is_none());
    let unhandled = report
        .observations()
        .get(1)
        .ok_or("missing unsupported frame")?;
    assert!(matches!(unhandled.evidence(), StpEvidence::Unsupported(_)));
    assert_eq!(unhandled.frame().bytes(), unsupported);
    assert_eq!(report.unrelated_packets(), 1);
    Ok(())
}

#[test]
fn malformed_envelopes_and_sources_are_distinct_from_out_of_scope_captures()
-> Result<(), Box<dyn Error>> {
    let mut short_payload = fixture::frame(SOURCE, ROOT, false);
    short_payload.truncate(30);
    let mut multicast_source = fixture::frame(SOURCE, ROOT, false);
    *multicast_source
        .get_mut(6)
        .ok_or("missing source address")? = 1;
    let mut bad_llc = fixture::frame(SOURCE, ROOT, false);
    *bad_llc.get_mut(15).ok_or("missing LLC source")? = 0xff;
    let good = fixture::frame(SOURCE, ROOT, false);
    let truncated_capture = ReceiveEvent::Frame(captured(
        good.clone(),
        Some(identity()?),
        u32::try_from(good.len() + 1)?,
    )?);
    let unknown_interface = ReceiveEvent::Frame(captured(good, None, 60)?);
    let mut link = Link::new(
        vec![
            fixture::event(short_payload)?,
            fixture::event(multicast_source)?,
            fixture::event(bad_llc)?,
            truncated_capture,
            unknown_interface,
        ],
        Some(0),
    )?;
    let report =
        StpMonitor::new(fixture::limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    let observations = report.observations();
    assert_eq!(observations.len(), 3);
    assert!(matches!(
        observations
            .first()
            .ok_or("missing Ethernet error")?
            .evidence(),
        StpEvidence::Malformed(MalformedStp::Ethernet(_))
    ));
    assert_eq!(
        observations
            .get(1)
            .ok_or("missing source error")?
            .evidence(),
        StpEvidence::Malformed(MalformedStp::SourceAddress)
    );
    assert!(matches!(
        observations.get(2).ok_or("missing BPDU error")?.evidence(),
        StpEvidence::Malformed(MalformedStp::Bpdu(_))
    ));
    assert_eq!(report.summary().truncated_packets(), 1);
    assert_eq!(report.summary().unscoped_packets(), 1);
    assert_eq!(report.summary().total_received_packets(), Some(5));
    Ok(())
}

#[test]
fn tagged_and_non_stp_llc_frames_are_not_misclassified() -> Result<(), Box<dyn Error>> {
    let original = fixture::frame(SOURCE, ROOT, false);
    let mut tagged = original.clone();
    tagged.splice(12..12, [0x81, 0, 0, 1]);
    let mut different_llc = original;
    *different_llc.get_mut(14).ok_or("missing LLC destination")? = 0x43;
    let mut link = Link::new(
        vec![fixture::event(tagged)?, fixture::event(different_llc)?],
        Some(0),
    )?;
    let report =
        StpMonitor::new(fixture::limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert!(report.observations().is_empty());
    assert_eq!(report.unrelated_packets(), 2);
    Ok(())
}

#[test]
fn repeated_frames_are_deduplicated_but_all_capture_work_is_charged() -> Result<(), Box<dyn Error>>
{
    let bytes = fixture::frame(SOURCE, ROOT, false);
    let mut link = Link::new(
        vec![fixture::event(bytes.clone())?, fixture::event(bytes)?],
        Some(4),
    )?;
    link.backlog = Some(true);
    let report =
        StpMonitor::new(fixture::limits(10, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 1);
    assert_eq!(report.summary().total_received_packets(), Some(2));
    assert_eq!(report.summary().capture_loss(), Some(4));
    assert_eq!(report.summary().capture_backlog(), Some(true));
    Ok(())
}

#[test]
fn cancelled_expired_or_failed_capture_is_inconclusive() -> Result<(), Box<dyn Error>> {
    let monitor = StpMonitor::new(fixture::limits(10, 4096)?);
    let mut cancelled = Link::new(Vec::new(), None)?;
    let report = monitor.run(&mut cancelled, &AtomicBool::new(true))?;
    assert_eq!(report.summary().stop_reason(), StopReason::Cancelled);
    assert!(report.observations().is_empty());

    let mut expired = Link::new(Vec::new(), None)?;
    let report = monitor.run_until(&mut expired, &AtomicBool::new(false), Instant::now())?;
    assert_eq!(report.summary().stop_reason(), StopReason::Deadline);
    assert!(expired.sent_deadline.is_none());

    let mut failed = Link::new(Vec::new(), None)?;
    failed.receive_error = Some(io::ErrorKind::BrokenPipe);
    let report = monitor.run_until(
        &mut failed,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(1),
    )?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert_eq!(report.summary().total_received_packets(), None);
    Ok(())
}

#[test]
fn distinct_candidates_stop_at_the_fixed_observation_capacity() -> Result<(), Box<dyn Error>> {
    let mut events = Vec::new();
    for suffix in 0..=64_u8 {
        let mut root = ROOT;
        root[5] = suffix;
        events.push(fixture::event(fixture::frame(SOURCE, root, false))?);
    }
    let mut link = Link::new(events, Some(0))?;
    let report =
        StpMonitor::new(fixture::limits(100, 8192)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.observations().len(), 64);
    assert_eq!(report.summary().received_packets(), 64);
    assert_eq!(report.summary().stop_reason(), StopReason::ObservationLimit);
    Ok(())
}
