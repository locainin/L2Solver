//! Run extraction and refinement with one observable cancellation state

mod cache;
mod checkpoint;
#[cfg(target_os = "linux")]
mod system_memory;
pub use cache::RecoveryCache;

use crate::{
    arguments::{ProgressMode, RecoveryOptions},
    outcome::RunOutcome,
};
use l2_cli::job_ui::{CancellationHandler, Renderer, RendererOptions};
use l2_workbench::job::{Job, JobError, JobSnapshot, MemoryBudget, MemoryError};
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    time::Duration,
};

/// Cadence for kernel observations and admission rechecks after workers have stopped
pub const MEMORY_OBSERVATION_INTERVAL: Duration = Duration::from_millis(250);
/// Four missed monitor intervals make an old sample unsuitable for pressure decisions
pub const MAX_MEMORY_SAMPLE_AGE: Duration = MEMORY_OBSERVATION_INTERVAL.saturating_mul(4);
/// Fraction of the effective limit kept for allocations outside the shared ledger
pub const MEMORY_SAFETY_MARGIN_DIVISOR: u64 = 8;

/// Refresh the shared observation before admitting another memory-intensive operation
pub fn refresh_memory_observation(memory: &MemoryBudget) -> Result<(), MemoryError> {
    #[cfg(target_os = "linux")]
    {
        system_memory::observe(memory)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = memory;
        Ok(())
    }
}

pub fn run(
    options: &RecoveryOptions,
    label: &str,
    operation: impl FnOnce(&Job) -> Result<bool, Box<dyn Error>>,
) -> Result<RunOutcome, Box<dyn Error>> {
    let memory = MemoryBudget::new(options.memory_limit);
    let job = Job::with_memory_budget(label, &memory);
    #[cfg(target_os = "linux")]
    let memory_monitor = system_memory::Monitor::start(&memory)?;
    let handler = CancellationHandler::install()?;
    let registration = handler.activate(job.clone())?;
    let renderer = Renderer::start(job.clone(), RendererOptions::from(options))?;
    let result = operation(&job);
    // Only the operation can decide whether cancellation stopped the work
    let operation_cancelled = result
        .as_ref()
        .err()
        .is_some_and(|error| is_cancellation(error.as_ref()));
    // Cleanup runs for both success and failure before the process reports an outcome
    #[cfg(target_os = "linux")]
    let monitoring = memory_monitor.finish();
    let rendering = renderer.finish();
    let unregistering = registration.finish();
    let cleanup_failed = rendering.is_err() || unregistering.is_err();
    #[cfg(target_os = "linux")]
    let cleanup_failed = cleanup_failed || monitoring.is_err();
    let result = retain_cleanup_error(
        result,
        rendering.map_err(|error| Box::new(error) as Box<dyn Error>),
        "progress renderer",
    );
    #[cfg(target_os = "linux")]
    let result = retain_cleanup_error(result, monitoring, "memory monitor");
    let result = retain_cleanup_error(
        result,
        unregistering.map_err(|error| Box::new(error) as Box<dyn Error>),
        "cancellation registration",
    );
    if operation_cancelled && !cleanup_failed {
        if options.progress == ProgressMode::Json {
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                serde_json::json!({
                    "type": "interrupted", "exit_status": 130,
                    "message": "Committed cache work remains available"
                })
            );
        } else {
            let _ = writeln!(
                io::stderr().lock(),
                "Interrupted (exit status 130); committed cache work remains available"
            );
        }
        return Ok(RunOutcome::Interrupted);
    }
    let complete = result?;
    if !options.quiet && options.progress != ProgressMode::Json {
        // A failed diagnostic write cannot change the operation's result
        let _ = write_cache_fallback_summary(&mut io::stderr().lock(), &job.snapshot()?, options);
    }
    Ok(if complete {
        RunOutcome::Completed
    } else {
        RunOutcome::Incomplete
    })
}

fn is_cancellation(error: &(dyn Error + 'static)) -> bool {
    crate::memory_error::find_map(error, |cause| {
        // A checkpoint failure must remain visible even when cancellation happened first
        if cause.is::<CleanupFailure>() {
            return Some(false);
        }
        if matches!(cause.downcast_ref::<JobError>(), Some(JobError::Cancelled))
            || matches!(
                cause.downcast_ref::<MemoryError>(),
                Some(MemoryError::Cancelled)
            )
        {
            return Some(true);
        }
        None
    })
    .unwrap_or(false)
}

fn retain_cleanup_error<T>(
    result: Result<T, Box<dyn Error>>,
    cleanup: Result<(), Box<dyn Error>>,
    stage: &'static str,
) -> Result<T, Box<dyn Error>> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => Err(Box::new(CleanupFailure {
            primary,
            secondary,
            stage,
        })),
    }
}

#[derive(Debug)]
struct CleanupFailure {
    primary: Box<dyn Error>,
    secondary: Box<dyn Error>,
    stage: &'static str,
}

impl fmt::Display for CleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; {} failure: {}",
            self.primary, self.stage, self.secondary
        )
    }
}

impl Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

fn write_cache_fallback_summary(
    output: &mut impl Write,
    snapshot: &JobSnapshot,
    options: &RecoveryOptions,
) -> io::Result<()> {
    if options.quiet || options.progress == ProgressMode::Json {
        return Ok(());
    }
    let records = snapshot.cache_fallbacks.records();
    if records.is_empty() {
        return Ok(());
    }

    // Keep human diagnostics on one line; JSON progress carries the structured snapshot
    write!(output, "Cache fallback summary:")?;
    let mut separator = " ";
    for record in records {
        write!(
            output,
            "{separator}{} {} x{}",
            record.stage().label(),
            record.kind().label(),
            record.count()
        )?;
        separator = "; ";
        // The shared job model has already escaped and capped this sample
        if let Some(detail) = record.sample_detail() {
            write!(output, " ({detail})")?;
        }
    }
    writeln!(output)
}

#[cfg(test)]
#[path = "../tests/recovery_job/observability.rs"]
mod observability_tests;

#[cfg(test)]
#[path = "../tests/recovery_job/outcome.rs"]
mod outcome_tests;
