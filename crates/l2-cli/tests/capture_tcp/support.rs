#[path = "frame.rs"]
mod frame;
pub use frame::{frame, metadata};

use l2_capture::{CapturedFrame, FcsStatus, InterfaceId};
use l2_pcap::{InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgWriter, TimestampResolution};
use serde_json::Value;
use std::{
    error::Error,
    io::Write,
    process::{Command, Output, Stdio},
};

pub fn capture(frames: &[CapturedFrame]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let max_interface = frames
        .iter()
        .map(|frame| frame.metadata().interface().index)
        .max()
        .unwrap_or(0);
    for index in 0..=max_interface {
        writer.add_interface(
            InterfaceId { section: 0, index },
            InterfaceConfig::new(
                65_535,
                TimestampResolution::MICROSECOND,
                0,
                FcsStatus::Unknown,
            )?,
        )?;
    }
    for frame in frames {
        writer.write_frame(frame)?;
    }
    writer.finish()?;
    Ok(writer.into_inner())
}

pub fn run_bytes(bytes: &[u8], args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "tcp-range", "-"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("stdin pipe unavailable")?;
    // Tiny usage-error fixtures can close stdin before consuming it
    if let Err(error) = input.write_all(bytes)
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(error.into());
    }
    drop(input);
    Ok(child.wait_with_output()?)
}

pub fn run(frames: &[CapturedFrame], args: &[&str]) -> Result<Output, Box<dyn Error>> {
    run_bytes(&capture(frames)?, args)
}

pub fn report(output: &Output) -> Result<Value, Box<dyn Error>> {
    if !matches!(output.status.code(), Some(0 | 3)) {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn bytes(value: &Value, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    value
        .pointer(path)
        .and_then(Value::as_array)
        .ok_or("missing byte array")?
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| "invalid byte".into())
        })
        .collect()
}
