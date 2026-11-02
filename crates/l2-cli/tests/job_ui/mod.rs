use std::error::Error;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::RenderVerbosity;
use super::cancellation::{HandlerTarget, record_interrupt};
use super::render::{JsonEvent, JsonEventTracker, RedrawGate, render_human_line, render_json_line};
use super::renderer::{LinePolicy, observe_lines};
use l2_workbench::job::{
    Counter, Job, Phase, PhaseOutcome, PhaseState, RecoveryTransition, RecoveryTransitionOutcome,
    RecoveryTransitionStage,
};

fn capture_json_lines(job: &Job, policy: LinePolicy) -> Result<Vec<String>, Box<dyn Error>> {
    let stop = AtomicBool::new(true);
    let output = Mutex::new(Vec::new());
    observe_lines(
        job,
        &stop,
        render_json_line,
        |line| {
            output
                .lock()
                .map_err(|_| std::io::Error::other("test output lock is poisoned"))?
                .push(line.to_owned());
            Ok(())
        },
        policy,
    )?;
    Ok(output
        .into_inner()
        .map_err(|_| std::io::Error::other("test output lock is poisoned"))?)
}

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
fn human_status_escapes_control_characters_in_label_and_phase_message() -> Result<(), Box<dyn Error>>
{
    let job = Job::new("source\n\u{1b}[2J");
    job.start(Phase::Ingestion, None)?;
    job.set_current(Phase::Ingestion, "record\t\u{1b}[31m")?;
    let snapshot = job.snapshot()?;

    let line = render_human_line(&snapshot, RenderVerbosity::Normal);

    assert!(line.chars().all(|character| !character.is_control()));
    assert!(line.contains("source\\n\\u{1b}[2J"));
    assert!(line.contains("record\\t\\u{1b}[31m"));
    Ok(())
}

#[test]
fn quiet_verbosity_suppresses_human_status() -> Result<(), Box<dyn Error>> {
    let job = Job::new("quiet run");
    let snapshot = job.snapshot()?;

    assert_eq!(render_human_line(&snapshot, RenderVerbosity::Quiet), "");
    Ok(())
}

#[test]
fn normal_human_status_shows_candidates_rate_and_unknown_eta() -> Result<(), Box<dyn Error>> {
    let job = Job::new("dynamic candidate scan");
    job.start(Phase::TransformDiscovery, None)?;
    job.advance(Phase::TransformDiscovery, 12)?;
    job.increment(Counter::CandidatesExamined, 12)?;
    job.increment(Counter::CandidatesRejected, 3)?;
    std::thread::sleep(Duration::from_millis(10));
    let snapshot = job.snapshot()?;

    let line = render_human_line(&snapshot, RenderVerbosity::Normal);

    assert!(line.contains("candidates 12 examined, 3 rejected"));
    assert!(line.contains("rate ") && line.contains("work units/s"));
    assert!(line.contains("ETA unknown"));
    Ok(())
}

#[test]
fn ingestion_status_uses_byte_rate_and_waits_for_a_measured_eta() -> Result<(), Box<dyn Error>> {
    let job = Job::new("bounded ingestion");
    job.start(Phase::Ingestion, Some(10))?;
    job.advance(Phase::Ingestion, 1)?;
    let mut snapshot = job.snapshot()?;
    {
        let ingestion = snapshot
            .phases
            .iter_mut()
            .find(|phase| phase.phase == Phase::Ingestion)
            .ok_or_else(|| std::io::Error::other("ingestion phase should be in the snapshot"))?;
        ingestion.elapsed_ms = 999;
        ingestion.rate_per_second = Some(4);
    }

    let early_line = render_human_line(&snapshot, RenderVerbosity::Normal);
    assert!(early_line.contains("rate 4 bytes/s"));
    assert!(early_line.contains("ETA unknown"));

    snapshot
        .phases
        .iter_mut()
        .find(|phase| phase.phase == Phase::Ingestion)
        .ok_or_else(|| std::io::Error::other("ingestion phase should remain in the snapshot"))?
        .elapsed_ms = 1_000;
    snapshot
        .phases
        .iter_mut()
        .find(|phase| phase.phase == Phase::Ingestion)
        .ok_or_else(|| std::io::Error::other("ingestion phase should remain in the snapshot"))?
        .eta_seconds = Some(3);
    let measured_line = render_human_line(&snapshot, RenderVerbosity::Normal);
    assert!(measured_line.contains("about 3s remaining"));
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
    assert_eq!(
        parsed.get("label").and_then(serde_json::Value::as_str),
        Some("machine-readable run")
    );
    assert_eq!(
        parsed
            .get("current_phase")
            .and_then(serde_json::Value::as_str),
        Some("preparation")
    );
    Ok(())
}

#[test]
fn final_json_snapshot_includes_transition_recorded_before_stop() -> Result<(), Box<dyn Error>> {
    let job = Job::new("publication progress");
    let stop = AtomicBool::new(false);
    let output = Mutex::new(Vec::new());

    observe_lines(
        &job,
        &stop,
        |snapshot| {
            // Record publication after this snapshot and request a final update
            if !stop.load(Ordering::Relaxed) {
                job.record_recovery_transition(RecoveryTransition {
                    stage: RecoveryTransitionStage::Publication,
                    outcome: RecoveryTransitionOutcome::Published,
                    sample: None,
                })?;
                stop.store(true, Ordering::Release);
            }
            render_json_line(snapshot)
        },
        |line| {
            output
                .lock()
                .map_err(|_| std::io::Error::other("test output lock is poisoned"))?
                .push(line.to_owned());
            Ok(())
        },
        LinePolicy::EverySnapshot,
    )?;

    let lines = output
        .into_inner()
        .map_err(|_| std::io::Error::other("test output lock is poisoned"))?;
    let last = lines.last().ok_or("final progress snapshot is missing")?;
    let snapshot: serde_json::Value = serde_json::from_str(last)?;
    let records = snapshot
        .pointer("/recovery_transitions/records")
        .and_then(serde_json::Value::as_array)
        .ok_or("transition records are missing")?;
    assert!(records.iter().any(|record| {
        record.get("stage").and_then(serde_json::Value::as_str) == Some("publication")
            && record.get("outcome").and_then(serde_json::Value::as_str) == Some("published")
    }));
    Ok(())
}

#[test]
fn quiet_json_filters_routine_progress_but_keeps_cancellation_ndjson() -> Result<(), Box<dyn Error>>
{
    let running_job = Job::new("quiet machine-readable run");
    running_job.start(Phase::TransformDiscovery, None)?;
    running_job.advance(Phase::TransformDiscovery, 4)?;
    let running_snapshot = running_job.snapshot()?;
    let mut events = JsonEventTracker::default();

    assert_eq!(events.pending_event(&running_snapshot), None);
    assert_eq!(
        capture_json_lines(&running_job, LinePolicy::QuietJsonEvents)?,
        [] as [std::string::String; 0]
    );

    running_job.request_cancel();
    let cancellation_snapshot = running_job.snapshot()?;
    let cancellation_event = events
        .pending_event(&cancellation_snapshot)
        .ok_or_else(|| std::io::Error::other("cancellation event should be emitted"))?;
    assert_eq!(cancellation_event, JsonEvent::CancellationRequested);
    let cancellation_lines = capture_json_lines(&running_job, LinePolicy::QuietJsonEvents)?;
    assert_eq!(cancellation_lines.len(), 1);
    let cancellation_line = cancellation_lines
        .first()
        .ok_or_else(|| std::io::Error::other("cancellation snapshot should be emitted"))?;
    let cancellation_json: serde_json::Value = serde_json::from_str(cancellation_line.trim_end())?;
    assert!(cancellation_line.ends_with('\n'));
    assert_eq!(
        cancellation_json
            .get("cancel_requested")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    events.mark_emitted(cancellation_event);
    assert_eq!(events.pending_event(&cancellation_snapshot), None);

    running_job.finish(Phase::TransformDiscovery, PhaseOutcome::Cancelled)?;
    let terminal_cancellation = running_job.snapshot()?;
    let terminal_event = events
        .pending_event(&terminal_cancellation)
        .ok_or_else(|| std::io::Error::other("cancelled phase event should be emitted"))?;
    assert_eq!(
        terminal_event,
        JsonEvent::TerminalPhase(Phase::TransformDiscovery, PhaseState::Cancelled)
    );
    let terminal_line = render_json_line(&terminal_cancellation)?;
    let terminal_json: serde_json::Value = serde_json::from_str(terminal_line.trim_end())?;
    assert!(terminal_line.ends_with('\n'));
    let transform_phase = terminal_json
        .get("phases")
        .and_then(serde_json::Value::as_array)
        .and_then(|phases| {
            phases.iter().find(|phase| {
                phase.get("phase").and_then(serde_json::Value::as_str)
                    == Some("transform_discovery")
            })
        })
        .ok_or_else(|| std::io::Error::other("transform phase should be in the JSON snapshot"))?;
    assert_eq!(
        transform_phase
            .get("state")
            .and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    events.mark_emitted(terminal_event);
    assert_eq!(events.pending_event(&terminal_cancellation), None);
    Ok(())
}

#[test]
fn quiet_json_keeps_failure_ndjson() -> Result<(), Box<dyn Error>> {
    let failed_job = Job::new("failed machine-readable run");
    failed_job.start(Phase::Preparation, None)?;
    failed_job.set_current(Phase::Preparation, "invalid source metadata")?;
    failed_job.finish(Phase::Preparation, PhaseOutcome::Failed)?;
    let failed_snapshot = failed_job.snapshot()?;
    let events = JsonEventTracker::default();
    let failed_event = events
        .pending_event(&failed_snapshot)
        .ok_or_else(|| std::io::Error::other("failed phase event should be emitted"))?;
    assert_eq!(
        failed_event,
        JsonEvent::TerminalPhase(Phase::Preparation, PhaseState::Failed)
    );
    let failed_lines = capture_json_lines(&failed_job, LinePolicy::QuietJsonEvents)?;
    assert_eq!(failed_lines.len(), 1);
    let failed_line = failed_lines
        .first()
        .ok_or_else(|| std::io::Error::other("failure snapshot should be emitted"))?;
    let failed_json: serde_json::Value = serde_json::from_str(failed_line.trim_end())?;
    assert!(failed_line.ends_with('\n'));
    let preparation_phase = failed_json
        .get("phases")
        .and_then(serde_json::Value::as_array)
        .and_then(|phases| {
            phases.iter().find(|phase| {
                phase.get("phase").and_then(serde_json::Value::as_str) == Some("preparation")
            })
        })
        .ok_or_else(|| std::io::Error::other("preparation phase should be in the JSON snapshot"))?;
    assert_eq!(
        preparation_phase
            .get("state")
            .and_then(serde_json::Value::as_str),
        Some("failed")
    );
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
