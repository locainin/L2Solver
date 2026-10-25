//! Passive replay uses capture time for aging while retaining delivery order

use crate::{replay_time, report, stp_render};
use l2_engine::{Clock, EngineConfig, Event, EventEngine, FakeClock, StpObserver, StpUpdate};
use l2_io::LinkIo;
use std::{error::Error, io::Write, time::Duration};

pub fn observe<L: LinkIo>(link: &mut L, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut engine = EventEngine::new(FakeClock::default(), EngineConfig::default())?;
    let mut observer = StpObserver::new(Duration::from_secs(20))?;
    let mut origin = None;
    let mut frames = 0_u64;
    let mut stp_frames = 0_u64;
    let mut regressions = 0_u64;
    let mut missing = 0_u64;
    let mut malformed = 0_u64;
    let mut invalid = 0_u64;
    let mut unsupported_stp = 0_u64;
    let mut unsupported_link = 0_u64;
    let mut truncated = 0_u64;
    writeln!(
        output,
        "Passive STP advertisement observation (sample lifetime: 20 seconds)"
    )?;
    while let Some(packet) = link.recv()? {
        frames += 1;
        truncated += u64::from(packet.is_truncated());
        advance_replay_clock(
            &mut engine,
            &packet,
            &mut origin,
            &mut regressions,
            &mut missing,
        )?;
        let update = observer.expire(engine.clock().now())?;
        if update != StpUpdate::Unchanged {
            write!(output, "time={} STP ", engine.clock().now())?;
            stp_render::update(output, update)?;
            writeln!(output)?;
        }
        engine.enqueue(Event::FrameReceived(packet))?;
        if let Some(envelope) = engine.next_ready()?
            && let Event::FrameReceived(frame) = envelope.event()
        {
            let assessment =
                report::assess_with_link_type(frame.metadata().link_type(), frame.bytes());
            count_assessment(
                &assessment,
                frame.metadata().link_type(),
                &mut malformed,
                &mut invalid,
                &mut unsupported_stp,
                &mut unsupported_link,
            );
            if let Some(stp) = assessment.stp {
                stp_frames += 1;
                let update = observer.observe(envelope.at(), frame.metadata().interface(), &stp)?;
                write!(
                    output,
                    "event={} time={} interface={}:{} STP {:?} ",
                    envelope.sequence().get(),
                    envelope.at(),
                    frame.metadata().interface().section,
                    frame.metadata().interface().index,
                    stp.version
                )?;
                stp_render::update(output, update)?;
                writeln!(output)?;
            }
            if let Some(diagnostic) = assessment.diagnostic {
                writeln!(output, "event={} {diagnostic}", envelope.sequence().get())?;
            }
        }
    }
    writeln!(
        output,
        "frames={frames} stp={stp_frames} malformed={malformed} invalid={invalid} unsupported_stp={unsupported_stp} truncated={truncated} advertisement_changes={} timestamp_regressions={regressions} missing_timestamps={missing} unsupported_link={unsupported_link}",
        observer.root_changes()
    )?;
    let source_complete = crate::source_collection::text(link.collection_summary(), output)?;
    Ok(source_complete
        && malformed == 0
        && invalid == 0
        && unsupported_stp == 0
        && unsupported_link == 0
        && truncated == 0
        && regressions == 0
        && missing == 0)
}

const fn count_assessment(
    assessment: &report::Assessment<'_>,
    link_type: l2_capture::LinkType,
    malformed: &mut u64,
    invalid: &mut u64,
    unsupported_stp: &mut u64,
    unsupported_link: &mut u64,
) {
    match assessment.status {
        report::Status::Malformed => *malformed += 1,
        report::Status::Invalid => *invalid += 1,
        report::Status::Unsupported if assessment.diagnostic.is_some() => {
            if link_type.is_ethernet() {
                *unsupported_stp += 1;
            } else {
                *unsupported_link += 1;
            }
        }
        _ => {}
    }
}

fn advance_replay_clock(
    engine: &mut EventEngine<FakeClock>,
    packet: &l2_capture::CapturedFrame,
    origin: &mut Option<i128>,
    regressions: &mut u64,
    missing: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let Some(timestamp) = packet.metadata().timestamp() else {
        // Missing timestamps preserve arrival order without inventing elapsed time
        *missing = missing.saturating_add(1);
        return Ok(());
    };
    let absolute = replay_time::nanoseconds(timestamp);
    // Anchor replay at the first known capture instant
    let start = *origin.get_or_insert(absolute);
    let elapsed = absolute - start;
    let now = engine.clock().now().nanos();
    if elapsed < i128::from(now) {
        // A regressing capture clock cannot move the monotonic engine backwards
        *regressions = regressions.saturating_add(1);
        return Ok(());
    }
    let elapsed = u64::try_from(elapsed).map_err(|_| {
        "capture time span exceeds the observation clock range; use inspect or json for exact timestamps"
    })?;
    engine.clock_mut().advance_nanos(elapsed - now)?;
    Ok(())
}
