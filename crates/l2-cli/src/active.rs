//! Dispatch one active command using the process cancellation handler

use std::{error::Error, io::Write};

use crate::outcome::RunOutcome;

pub fn run(
    options: &l2_active_cli::ActiveArgs,
    output: &mut impl Write,
) -> Result<RunOutcome, Box<dyn Error>> {
    let outcome = l2_active_cli::execute_process(options, output)?;
    Ok(match outcome {
        l2_active_cli::ActiveOutcome::Completed => RunOutcome::Completed,
        l2_active_cli::ActiveOutcome::Incomplete => RunOutcome::Incomplete,
        l2_active_cli::ActiveOutcome::Findings => RunOutcome::Findings,
        l2_active_cli::ActiveOutcome::Cancelled => RunOutcome::Interrupted,
    })
}
