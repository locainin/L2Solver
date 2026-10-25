//! Run extraction and refinement with one observable cancellation state

mod checkpoint;
pub use checkpoint::CheckpointWriter;

use crate::{arguments::RecoveryOptions, outcome::RunOutcome};
use l2_cli::job_ui::{CancellationHandler, Renderer, RendererOptions};
use l2_workbench::job::Job;
use std::{
    error::Error,
    io::{self, Write},
};

pub fn run(
    options: &RecoveryOptions,
    label: &str,
    operation: impl FnOnce(&Job) -> Result<bool, Box<dyn Error>>,
) -> Result<RunOutcome, Box<dyn Error>> {
    let job = Job::new(label);
    let handler = CancellationHandler::install()?;
    let registration = handler.activate(job.clone())?;
    let renderer = Renderer::start(job.clone(), RendererOptions::from(options))?;
    let result = operation(&job);
    // Cleanup runs for both success and failure before the process reports an outcome
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
    unregistering?;
    result.map(|complete| {
        if complete {
            RunOutcome::Completed
        } else {
            RunOutcome::Incomplete
        }
    })
}
