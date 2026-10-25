use std::fmt::Write as FmtWrite;
use std::time::{Duration, Instant};

use l2_workbench::job::{Counter, JobSnapshot, Phase, PhaseSnapshot, PhaseState};

use super::{RenderVerbosity, RendererError};

const MIN_REDRAW_INTERVAL: Duration = Duration::from_millis(250);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn render_json_line(snapshot: &JobSnapshot) -> Result<String, RendererError> {
    let mut line = serde_json::to_string(snapshot)?;
    line.push('\n');
    Ok(line)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JsonEvent {
    CancellationRequested,
    TerminalPhase(Phase, PhaseState),
}

#[derive(Debug, Default)]
pub(super) struct JsonEventTracker {
    emitted: Vec<JsonEvent>,
}

impl JsonEventTracker {
    pub(super) fn pending_event(&self, snapshot: &JobSnapshot) -> Option<JsonEvent> {
        // A cancellation request remains set, so quiet output reports it only once
        if snapshot.cancel_requested && !self.emitted.contains(&JsonEvent::CancellationRequested) {
            return Some(JsonEvent::CancellationRequested);
        }

        snapshot.phases.iter().find_map(|phase| {
            if matches!(phase.state, PhaseState::Failed | PhaseState::Cancelled) {
                let event = JsonEvent::TerminalPhase(phase.phase, phase.state);
                (!self.emitted.contains(&event)).then_some(event)
            } else {
                None
            }
        })
    }

    pub(super) fn mark_emitted(&mut self, event: JsonEvent) {
        self.emitted.push(event);
    }
}

pub(super) fn render_human_line(snapshot: &JobSnapshot, verbosity: RenderVerbosity) -> String {
    if verbosity == RenderVerbosity::Quiet {
        return String::new();
    }

    let mut line = snapshot.label.clone();
    if let Some(phase) = snapshot.current_phase {
        if let Some(progress) = snapshot.phase(phase) {
            let _ = write!(line, ": {}", phase.label());
            append_phase_detail(&mut line, progress);
        }
    } else {
        line.push_str(": starting");
    }

    let elapsed_seconds = snapshot.elapsed_ms / 1_000;
    let minutes = elapsed_seconds / 60;
    let seconds = elapsed_seconds % 60;
    let _ = write!(line, " · elapsed {minutes:02}:{seconds:02}");

    // Candidate totals explain discovery activity even at normal verbosity
    append_candidate_summary(&mut line, snapshot);

    if verbosity == RenderVerbosity::Verbose {
        for (counter, value) in &snapshot.counters {
            if !matches!(
                counter,
                Counter::CandidatesExamined | Counter::CandidatesRejected
            ) {
                let _ = write!(line, " · {} {value}", counter.label());
            }
        }
    }
    if snapshot.cancel_requested {
        line.push_str(" · cancellation requested");
    }
    line
}

fn append_candidate_summary(line: &mut String, snapshot: &JobSnapshot) {
    let examined = snapshot
        .counters
        .get(&Counter::CandidatesExamined)
        .copied()
        .unwrap_or_default();
    let rejected = snapshot
        .counters
        .get(&Counter::CandidatesRejected)
        .copied()
        .unwrap_or_default();
    let _ = write!(
        line,
        " · candidates {examined} examined, {rejected} rejected"
    );
}

fn append_phase_detail(line: &mut String, phase: &PhaseSnapshot) {
    if let Some(total) = phase.total {
        let _ = write!(line, " · {}/{}", phase.completed, total);
        if let Some(percent) = phase.progress_percent {
            let _ = write!(line, " ({percent}%)");
        }
    } else {
        let _ = write!(line, " · {} processed", phase.completed);
    }

    if let Some(rate_per_second) = phase.rate_per_second {
        let _ = write!(line, " · rate {rate_per_second} items/s");
    } else if phase.state == PhaseState::InProgress {
        line.push_str(" · rate unknown");
    }

    if let Some(eta_seconds) = phase.eta_seconds {
        let _ = write!(line, " · about {eta_seconds}s remaining");
    } else if phase.state == PhaseState::InProgress {
        line.push_str(" · ETA unknown");
    }
    if let Some(message) = &phase.message {
        let _ = write!(line, " · {message}");
    }
    if phase.state != PhaseState::InProgress {
        let _ = write!(line, " · {}", phase_state_label(phase.state));
    }
}

const fn phase_state_label(state: PhaseState) -> &'static str {
    match state {
        PhaseState::Pending => "pending",
        PhaseState::InProgress => "running",
        PhaseState::Completed => "completed",
        PhaseState::Failed => "failed",
        PhaseState::Cancelled => "cancelled",
        PhaseState::Skipped => "skipped",
        _ => "unknown",
    }
}

#[derive(Debug, Default)]
pub(super) struct RedrawGate {
    last_render: Option<Instant>,
}

impl RedrawGate {
    pub(super) fn should_render(&mut self, now: Instant, changed: bool) -> bool {
        let Some(last_render) = self.last_render else {
            self.last_render = Some(now);
            return true;
        };

        let elapsed = now.saturating_duration_since(last_render);
        if elapsed < MIN_REDRAW_INTERVAL || (!changed && elapsed < HEARTBEAT_INTERVAL) {
            return false;
        }

        // Store the successful draw time so repeated changes remain capped at four per second
        self.last_render = Some(now);
        true
    }
}
