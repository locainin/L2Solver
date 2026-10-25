use std::fmt::Write as FmtWrite;
use std::time::{Duration, Instant};

use l2_workbench::job::{JobSnapshot, PhaseSnapshot, PhaseState};

use super::{RenderVerbosity, RendererError};

const MIN_REDRAW_INTERVAL: Duration = Duration::from_millis(250);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn render_json_line(snapshot: &JobSnapshot) -> Result<String, RendererError> {
    let mut line = serde_json::to_string(snapshot)?;
    line.push('\n');
    Ok(line)
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

    if verbosity == RenderVerbosity::Verbose {
        for (counter, value) in &snapshot.counters {
            let _ = write!(line, " · {} {value}", counter.label());
        }
    }
    if snapshot.cancel_requested {
        line.push_str(" · cancellation requested");
    }
    line
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

    if let Some(eta_seconds) = phase.eta_seconds {
        let _ = write!(line, " · about {eta_seconds}s remaining");
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
