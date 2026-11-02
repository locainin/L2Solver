use std::io::{self, IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use l2_workbench::job::{Job, JobSnapshot, Phase};

use crate::arguments::ProgressMode;

use super::model::{RenderVerbosity, RendererError, RendererOptions};
use super::render::{JsonEventTracker, RedrawGate, render_human_line, render_json_line};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const SPINNER_INTERVAL: Duration = Duration::from_secs(1);
const DRAW_RATE_HZ: u8 = 4;
const BAR_TEMPLATE: &str = "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}";
const SPINNER_TEMPLATE: &str = "[{elapsed_precise}] {spinner:.cyan} {msg}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinePolicy {
    EverySnapshot,
    QuietJsonEvents,
}

/// Observes job snapshots and writes progress to stderr
#[must_use = "keep this renderer alive while progress should be observed"]
#[derive(Debug)]
pub struct Renderer {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), RendererError>>>,
}

impl Renderer {
    /// Starts a background observer using the requested output mode
    ///
    /// JSON mode emits NDJSON snapshots to stderr, with quiet mode limited to cancellation and
    /// failure events. Auto mode is silent when stderr is redirected, while Always mode emits
    /// plain lines in that case
    ///
    /// # Errors
    /// Returns an I/O or thread creation error when the observer cannot be started
    pub fn start(job: Job, options: RendererOptions) -> Result<Self, RendererError> {
        let should_observe = match options.mode {
            ProgressMode::Never => false,
            ProgressMode::Auto => {
                is_interactive_terminal() && options.verbosity != RenderVerbosity::Quiet
            }
            ProgressMode::Always => options.verbosity != RenderVerbosity::Quiet,
            ProgressMode::Json => true,
        };
        if !should_observe {
            // Avoid a background thread when the selected mode cannot produce output
            return Ok(Self {
                stop: Arc::new(AtomicBool::new(true)),
                worker: None,
            });
        }

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("l2-progress-renderer".to_owned())
            .spawn(move || run(&job, options, &worker_stop))?;

        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    /// Stops output and joins the observer thread
    ///
    /// # Errors
    /// Returns an output error or [`RendererError::WorkerPanicked`] if the observer failed
    pub fn finish(mut self) -> Result<(), RendererError> {
        self.stop.store(true, Ordering::Release);
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.join().map_err(|_| RendererError::WorkerPanicked)?
    }
}

impl Drop for Renderer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Drop is best-effort; explicit finish reports any output failure to the caller
            let _ = worker.join();
        }
    }
}

fn run(job: &Job, options: RendererOptions, stop: &AtomicBool) -> Result<(), RendererError> {
    let terminal = is_interactive_terminal();
    match options.mode {
        ProgressMode::Json => run_json(job, stop, options.verbosity),
        ProgressMode::Auto | ProgressMode::Always if terminal => run_terminal(job, stop, options),
        ProgressMode::Always => run_lines(job, stop, options.verbosity),
        ProgressMode::Auto | ProgressMode::Never => Ok(()),
    }
}

fn run_json(job: &Job, stop: &AtomicBool, verbosity: RenderVerbosity) -> Result<(), RendererError> {
    let line_policy = if verbosity == RenderVerbosity::Quiet {
        LinePolicy::QuietJsonEvents
    } else {
        LinePolicy::EverySnapshot
    };
    observe_lines(job, stop, render_json_line, write_stderr, line_policy)
}

fn run_lines(
    job: &Job,
    stop: &AtomicBool,
    verbosity: RenderVerbosity,
) -> Result<(), RendererError> {
    observe_lines(
        job,
        stop,
        |snapshot| Ok(render_human_line(snapshot, verbosity)),
        write_stderr_line,
        LinePolicy::EverySnapshot,
    )
}

pub(super) fn observe_lines(
    job: &Job,
    stop: &AtomicBool,
    render_line: impl Fn(&JobSnapshot) -> Result<String, RendererError>,
    write_line: impl Fn(&str) -> Result<(), RendererError>,
    line_policy: LinePolicy,
) -> Result<(), RendererError> {
    let mut gate = RedrawGate::default();
    let mut previous_line = None;
    let mut json_events = JsonEventTracker::default();

    loop {
        // A final snapshot must be taken after the stop request
        let finishing = stop.load(Ordering::Acquire);
        let snapshot = job.snapshot()?;
        let line = render_line(&snapshot)?;
        // The gate caps changed output and still refreshes unchanged status as a heartbeat
        let changed = previous_line.as_deref() != Some(line.as_str());
        let pending_event = if line_policy == LinePolicy::QuietJsonEvents {
            json_events.pending_event(&snapshot)
        } else {
            None
        };
        if line_policy == LinePolicy::EverySnapshot || pending_event.is_some() {
            let should_render =
                finishing || gate.should_render(Instant::now(), changed || pending_event.is_some());
            if should_render {
                write_line(&line)?;
                if let Some(event) = pending_event {
                    // Keep throttled events pending until a write succeeds
                    json_events.mark_emitted(event);
                }
            }
        }
        previous_line = Some(line);
        if finishing {
            return Ok(());
        }
        // Short sleeps keep explicit finish responsive without busy polling
        thread::sleep(POLL_INTERVAL);
    }
}

fn run_terminal(
    job: &Job,
    stop: &AtomicBool,
    options: RendererOptions,
) -> Result<(), RendererError> {
    let mut progress_bar = None;
    let mut progress_phase = None;

    loop {
        // Check for shutdown before capturing the last progress state
        let finishing = stop.load(Ordering::Acquire);
        let snapshot = job.snapshot()?;
        // The bar reads the same snapshot that persistence and JSON output consume
        update_progress_bar(
            &snapshot,
            options.verbosity,
            &mut progress_bar,
            &mut progress_phase,
        )?;

        if finishing {
            if let Some(progress_bar) = progress_bar {
                progress_bar.finish();
            }
            return Ok(());
        }
        // Indicatif supplies terminal redraw timing and a steady heartbeat
        thread::sleep(POLL_INTERVAL);
    }
}

fn update_progress_bar(
    snapshot: &JobSnapshot,
    verbosity: RenderVerbosity,
    progress_bar: &mut Option<ProgressBar>,
    progress_phase: &mut Option<Phase>,
) -> Result<(), RendererError> {
    let Some(phase) = snapshot.current_phase else {
        return Ok(());
    };
    let Some(phase_snapshot) = snapshot.phase(phase) else {
        return Ok(());
    };

    if *progress_phase != Some(phase) {
        // A new bar gives each phase its own denominator and elapsed clock
        if let Some(previous) = progress_bar.take() {
            previous.finish_and_clear();
        }
        // Unknown discovery totals use a spinner instead of a guessed percentage
        let bar = ProgressBar::with_draw_target(
            phase_snapshot.total,
            ProgressDrawTarget::stderr_with_hz(DRAW_RATE_HZ),
        );
        bar.set_style(progress_style(phase_snapshot.total.is_some())?);
        bar.enable_steady_tick(SPINNER_INTERVAL);
        *progress_bar = Some(bar);
        *progress_phase = Some(phase);
    }

    if let Some(bar) = progress_bar.as_ref() {
        if let Some(total) = phase_snapshot.total {
            bar.set_position(phase_snapshot.completed.min(total));
        } else {
            bar.set_position(phase_snapshot.completed);
        }
        bar.set_message(render_human_line(snapshot, verbosity));
        if matches!(
            phase_snapshot.state,
            l2_workbench::job::PhaseState::Completed
                | l2_workbench::job::PhaseState::Failed
                | l2_workbench::job::PhaseState::Cancelled
                | l2_workbench::job::PhaseState::Skipped
        ) {
            bar.finish_with_message(render_human_line(snapshot, verbosity));
        }
    }
    Ok(())
}

fn progress_style(known_total: bool) -> Result<ProgressStyle, RendererError> {
    let template = if known_total {
        BAR_TEMPLATE
    } else {
        SPINNER_TEMPLATE
    };
    ProgressStyle::with_template(template)
        .map_err(|error| RendererError::InvalidStyle(error.to_string()))
}

fn write_stderr(line: &str) -> Result<(), RendererError> {
    let mut stderr = io::stderr().lock();
    stderr.write_all(line.as_bytes())?;
    stderr.flush()?;
    Ok(())
}

fn write_stderr_line(line: &str) -> Result<(), RendererError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{line}")?;
    stderr.flush()?;
    Ok(())
}

fn is_interactive_terminal() -> bool {
    let terminal_type = std::env::var_os("TERM");
    let terminal_type_is_useful = if cfg!(windows) {
        terminal_type.as_deref() != Some(std::ffi::OsStr::new("dumb"))
    } else {
        // Unix terminals with an unset TERM or TERM=dumb cannot render an interactive bar
        terminal_type
            .as_deref()
            .is_some_and(|value| value != std::ffi::OsStr::new("dumb"))
    };

    io::stderr().is_terminal() && terminal_type_is_useful
}
