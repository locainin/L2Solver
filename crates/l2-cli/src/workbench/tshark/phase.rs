use super::{preparation::PreparedCapture, process};
use std::{error::Error, ffi::OsString, process::ExitStatus, time::Instant};

pub(super) fn run_phase(
    prepared: &PreparedCapture,
    arguments: &[OsString],
    stdout_maximum: usize,
) -> Result<process::Output, Box<dyn Error>> {
    let remaining = prepared.deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(process::ProcessError::TimedOut.into());
    }
    let mut launch = prepared
        .sandbox
        .command(arguments, &prepared.environment, None)?;
    Ok(process::run_launch(
        &mut launch,
        remaining,
        stdout_maximum,
        prepared.diagnostic_maximum,
        None,
    )?)
}

pub(super) fn require_success(
    phase: &str,
    status: ExitStatus,
    stderr: &[u8],
) -> Result<(), Box<dyn Error>> {
    if status.success() {
        return Ok(());
    }
    let diagnostics = String::from_utf8_lossy(stderr);
    Err(format!(
        "TShark {phase} failed with {status}: {}",
        diagnostics.trim()
    )
    .into())
}
