use std::error::Error;
use std::time::{Duration, Instant};

use super::RenderVerbosity;
use super::cancellation::{HandlerTarget, record_interrupt};
use super::render::{RedrawGate, render_human_line, render_json_line};
use l2_workbench::job::{Job, Phase};

#[test]
fn redirected_human_output_never_contains_ansi_codes() -> Result<(), Box<dyn Error>> {
    let job = Job::new("redirected run");
    job.start(Phase::Ingestion, Some(10))?;
    job.advance(Phase::Ingestion, 2)?;
    let snapshot = job.snapshot()?;

    let line = render_human_line(&snapshot, RenderVerbosity::Normal);

    assert!(!line.contains('\u{1b}'));
    assert!(line.contains("redirected run"));
    Ok(())
}

#[test]
fn quiet_verbosity_suppresses_human_status() -> Result<(), Box<dyn Error>> {
    let job = Job::new("quiet run");
    let snapshot = job.snapshot()?;

    assert!(render_human_line(&snapshot, RenderVerbosity::Quiet).is_empty());
    Ok(())
}

#[test]
fn json_mode_emits_a_parseable_newline_delimited_snapshot() -> Result<(), Box<dyn Error>> {
    let job = Job::new("machine-readable run");
    job.start(Phase::Preparation, None)?;
    let snapshot = job.snapshot()?;

    let line = render_json_line(&snapshot)?;
    let parsed: serde_json::Value = serde_json::from_str(line.trim_end())?;

    assert!(line.ends_with('\n'));
    assert_eq!(parsed["label"], "machine-readable run");
    assert_eq!(parsed["current_phase"], "preparation");
    Ok(())
}

#[test]
fn redraw_gate_limits_updates_and_still_emits_heartbeats() {
    let start = Instant::now();
    let mut gate = RedrawGate::default();

    assert!(gate.should_render(start, true));
    assert!(!gate.should_render(start + Duration::from_millis(100), true));
    assert!(gate.should_render(start + Duration::from_millis(250), true));
    assert!(!gate.should_render(start + Duration::from_millis(500), false));
    assert!(gate.should_render(start + Duration::from_millis(1_250), false));
}

#[test]
fn first_interrupt_requests_cancellation_and_second_is_hard_exit() {
    let job = Job::new("interrupt handling");
    let mut target = HandlerTarget {
        active_job: Some(job.clone()),
        first_interrupt_seen: false,
    };

    assert!(record_interrupt(&mut target));
    assert!(job.is_cancelled());
    assert!(!record_interrupt(&mut target));
}
