#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs::OpenOptions,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, BrokenPipeWriter, Cli, execute};

fn closed_stdout() -> Result<Stdio, Box<dyn Error>> {
    let (reader, writer) = UnixStream::pair()?;
    drop(reader);
    Ok(Stdio::from(OwnedFd::from(writer)))
}

#[test]
fn closed_stdout_preserves_cancellation() -> Result<(), Box<dyn Error>> {
    let options = Cli::try_parse_from([
        "l2solver-active",
        "arp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "192.0.2.1",
        "--format",
        "json",
    ])?;
    let (reader, writer) = UnixStream::pair()?;
    drop(reader);
    let mut output = BrokenPipeWriter::new(writer);
    let outcome = execute(&options.active, &AtomicBool::new(true), &mut output)?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    Ok(())
}

#[test]
fn closed_stdout_preserves_success_for_text_and_json_capability_queries()
-> Result<(), Box<dyn Error>> {
    for format in ["text", "json"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
            .args(["capabilities", "--interface", "lo", "--format", format])
            .stdout(closed_stdout()?)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn non_pipe_stdout_failure_still_produces_a_json_error() -> Result<(), Box<dyn Error>> {
    let full = OpenOptions::new().write(true).open("/dev/full")?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["capabilities", "--interface", "lo", "--format", "json"])
        .stdout(Stdio::from(full))
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error.get("stage").and_then(serde_json::Value::as_str),
        Some("output")
    );
    Ok(())
}
