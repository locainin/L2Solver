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
use l2_workbench::job::{Job, JobSnapshot, MemoryBudget, MemoryError};
use std::{
    error::Error,
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
    // Cleanup runs for both success and failure before the process reports an outcome
    #[cfg(target_os = "linux")]
    let monitoring = memory_monitor.finish();
    let rendering = renderer.finish();
    let unregistering = registration.finish();
    if job.is_cancelled() {
        if options.progress == crate::arguments::ProgressMode::Json {
            writeln!(
                io::stderr().lock(),
                "{}",
                serde_json::json!({
                    "type": "interrupted", "exit_status": 130,
                    "message": "Committed cache work remains available"
                })
            )?;
        } else {
            writeln!(
                io::stderr().lock(),
                "Interrupted (exit status 130); committed cache work remains available"
            )?;
        }
        return Ok(RunOutcome::Interrupted);
    }
    rendering?;
    #[cfg(target_os = "linux")]
    monitoring?;
    unregistering?;
    if !options.quiet && options.progress != ProgressMode::Json {
        write_cache_fallback_summary(&mut io::stderr().lock(), &job.snapshot()?, options)?;
    }
    result.map(|complete| {
        if complete {
            RunOutcome::Completed
        } else {
            RunOutcome::Incomplete
        }
    })
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
