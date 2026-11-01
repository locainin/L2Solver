//! Render cancellation or timeout before a probe can send

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use serde::Serialize;

use super::{ActiveOutcome, Error, OutputFormat};

#[cfg(test)]
#[path = "../tests/cli/preflight.rs"]
mod tests;

pub fn discovery_deadline() -> Result<Instant, Error> {
    Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| Error::Discovery(std::io::Error::other("discovery deadline overflow")))
}

pub fn discover(
    selector: &l2_active_linux::InterfaceSelector,
    cancelled: &AtomicBool,
) -> Result<l2_active_linux::InterfaceInfo, Error> {
    l2_active_linux::discover_until(selector, discovery_deadline()?, cancelled)
        .map_err(Error::Discovery)
}

pub fn cancelled_discovery<T>(
    result: Result<T, Error>,
    cancelled: &AtomicBool,
) -> Result<Option<T>, Error> {
    match result {
        Err(Error::Discovery(error))
            if error.kind() == std::io::ErrorKind::Interrupted
                && cancelled.load(Ordering::Acquire) =>
        {
            Ok(None)
        }
        other => other.map(Some),
    }
}

#[derive(Serialize)]
struct Stopped<'a> {
    operation: &'static str,
    status: &'static str,
    completion: &'static str,
    stop_reason: &'static str,
    stage: &'static str,
    scope: PreflightScope<'a>,
    tx: PreflightTransmit,
    cleanup: PreflightCleanup,
}

#[derive(Serialize)]
struct PreflightScope<'a> {
    interface: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<std::net::IpAddr>,
}

#[derive(Serialize)]
struct PreflightTransmit {
    attempted: bool,
    attempt_scope: &'static str,
    acceptance: &'static str,
    accepted_packets: u32,
    accepted_bytes: u64,
    delivery_confirmed: bool,
}

#[derive(Serialize)]
struct PreflightCleanup {
    state: &'static str,
}

#[derive(Clone, Copy)]
pub enum PreflightStop {
    Cancelled,
    #[cfg(target_os = "linux")]
    HelperTimeout,
}

#[derive(Clone, Copy)]
pub enum HelperStage {
    NotStarted,
    #[cfg(target_os = "linux")]
    Opening,
}

#[cfg(target_os = "linux")]
pub fn open_failure(
    error: std::io::Error,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<PreflightStop, Error> {
    use std::sync::atomic::Ordering;

    match error.kind() {
        std::io::ErrorKind::Interrupted if cancelled.load(Ordering::Acquire) => {
            Ok(PreflightStop::Cancelled)
        }
        std::io::ErrorKind::TimedOut => Ok(PreflightStop::HelperTimeout),
        _ => Err(Error::Helper(error)),
    }
}

pub fn write_stopped(
    operation: &'static str,
    interface: &l2_active_linux::InterfaceSelector,
    target: Option<std::net::IpAddr>,
    format: OutputFormat,
    output: &mut impl Write,
    stop: PreflightStop,
    helper: HelperStage,
) -> Result<ActiveOutcome, Error> {
    let (status, completion, reason, outcome) = match stop {
        PreflightStop::Cancelled => (
            "cancelled",
            "cancelled",
            "cancelled",
            ActiveOutcome::Cancelled,
        ),
        #[cfg(target_os = "linux")]
        PreflightStop::HelperTimeout => (
            "inconclusive",
            "incomplete",
            "helper_open_timeout",
            ActiveOutcome::Incomplete,
        ),
    };
    let (stage, cleanup) = match helper {
        HelperStage::NotStarted => ("preflight", "not_started"),
        #[cfg(target_os = "linux")]
        HelperStage::Opening => ("helper_open", "unconfirmed"),
    };
    match format {
        OutputFormat::Text => {
            writeln!(
                output,
                "{operation} {reason} before transmission; helper cleanup: {cleanup}"
            )
            .map_err(Error::Output)?;
        }
        OutputFormat::Json => {
            let report = Stopped {
                operation,
                status,
                completion,
                stop_reason: reason,
                stage,
                scope: PreflightScope {
                    interface: interface.name(),
                    target,
                },
                tx: PreflightTransmit {
                    attempted: false,
                    attempt_scope: "link_send_call",
                    acceptance: "not_attempted",
                    accepted_packets: 0,
                    accepted_bytes: 0,
                    delivery_confirmed: false,
                },
                cleanup: PreflightCleanup { state: cleanup },
            };
            serde_json::to_writer(&mut *output, &report).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)?;
        }
    }
    Ok(outcome)
}
