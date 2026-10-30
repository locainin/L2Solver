//! Standalone entry point for the active assessment frontend

use std::{
    io::{self, Write},
    process::ExitCode,
};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, BrokenPipeWriter, Cli, Error, execute_process, write_error};

fn main() -> ExitCode {
    let options = Cli::parse().active;
    let mut output = BrokenPipeWriter::new(io::stdout().lock());
    let result = execute_process(&options, &mut output).and_then(|outcome| {
        output.flush().map_err(Error::Output)?;
        Ok(outcome)
    });
    match result {
        Ok(ActiveOutcome::Completed) => ExitCode::SUCCESS,
        Ok(ActiveOutcome::Incomplete) => ExitCode::from(3),
        Ok(ActiveOutcome::Findings) => ExitCode::from(4),
        Ok(ActiveOutcome::Cancelled) => ExitCode::from(130),
        Err(error) => {
            let _ = write_error(&error, options.format, &mut io::stderr().lock());
            ExitCode::FAILURE
        }
    }
}
