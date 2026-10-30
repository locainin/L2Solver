//! Shared collection quality and presentation for native operations

use std::{fmt::Write as _, io};

use l2_active::{Limits, RunSummary, StopReason};
use l2_active_linux::InterfaceSelector;
use serde::Serialize;

use super::{ActiveOutcome, Error, diagnostic::io_code};

#[cfg(test)]
#[path = "../tests/reporting/mod.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendMode {
    Single,
    Listen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Evidence {
    Observed,
    Findings,
    Inconclusive,
}

pub fn outcome(
    summary: &RunSummary,
    mode: SendMode,
    evidence: Evidence,
    close_error: Option<&io::Error>,
) -> ActiveOutcome {
    if summary.stop_reason() == StopReason::Cancelled {
        return ActiveOutcome::Cancelled;
    }
    if !complete(summary, mode, close_error) || evidence == Evidence::Inconclusive {
        return ActiveOutcome::Incomplete;
    }
    match evidence {
        Evidence::Findings => ActiveOutcome::Findings,
        Evidence::Observed => ActiveOutcome::Completed,
        Evidence::Inconclusive => ActiveOutcome::Incomplete,
    }
}

pub fn complete(summary: &RunSummary, mode: SendMode, close_error: Option<&io::Error>) -> bool {
    let transmission_complete = match mode {
        SendMode::Single => summary.sent_packets() == 1,
        SendMode::Listen => !summary.send_attempted() && summary.sent_packets() == 0,
    };
    summary.stop_reason() == StopReason::Deadline
        && transmission_complete
        && summary.capture_loss() == Some(0)
        && summary.capture_backlog() == Some(false)
        && summary.truncated_packets() == 0
        && summary.unscoped_packets() == 0
        && summary.total_received_packets().is_some()
        && summary.total_received_bytes().is_some()
        && summary.transport_error().is_none()
        && summary.loss_error().is_none()
        && summary.accounting_error().is_none()
        && summary.backlog_error().is_none()
        && close_error.is_none()
}

#[derive(Debug, Serialize)]
pub struct InterfaceView<'a> {
    interface: &'a str,
    ifindex: u32,
    namespace_device: u64,
    namespace_inode: u64,
    interface_device: u64,
    interface_inode: u64,
}

impl<'a> InterfaceView<'a> {
    pub fn new(selector: &'a InterfaceSelector, summary: &RunSummary) -> Self {
        let identity = summary.interface();
        Self {
            interface: selector.name(),
            ifindex: identity.ifindex(),
            namespace_device: identity.namespace_device(),
            namespace_inode: identity.namespace_inode(),
            interface_device: identity.interface_device(),
            interface_inode: identity.interface_inode(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LimitsView {
    requested_timeout_ms: u128,
    received_packets: u32,
    received_bytes: u64,
}

impl LimitsView {
    pub const fn new(limits: Limits) -> Self {
        Self {
            requested_timeout_ms: limits.timeout().as_millis(),
            received_packets: limits.max_received_packets(),
            received_bytes: limits.max_received_bytes(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Transmit {
    attempted: bool,
    attempt_scope: &'static str,
    acceptance: &'static str,
    accepted_packets: u32,
    accepted_bytes: u64,
    delivery_confirmed: bool,
}

#[derive(Debug, Serialize)]
struct Receive {
    setup_packets: Option<u32>,
    setup_bytes: Option<u64>,
    // Setup drains and protocol collection have separate resource counters
    collection_packets: u32,
    collection_bytes: u64,
    total_packets: Option<u64>,
    total_bytes: Option<u64>,
    outbound_packets: u32,
    truncated_packets: u32,
    unscoped_packets: u32,
    capture_loss: Option<u64>,
    final_backlog: Option<bool>,
}

#[derive(Debug, Serialize)]
struct Diagnostic {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct Cleanup {
    confirmed: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QualityView {
    capture_scope: &'static str,
    tx: Transmit,
    rx: Receive,
    stop_reason: &'static str,
    transport_error: Option<Diagnostic>,
    loss_error: Option<Diagnostic>,
    accounting_error: Option<Diagnostic>,
    backlog_error: Option<Diagnostic>,
    cleanup: Cleanup,
}

impl QualityView {
    pub fn new(summary: &RunSummary, close_error: Option<&io::Error>) -> Self {
        Self {
            capture_scope: "inbound_fixed_profile",
            tx: Transmit {
                attempted: summary.send_attempted(),
                attempt_scope: "link_send_call",
                acceptance: acceptance(summary),
                accepted_packets: summary.sent_packets(),
                accepted_bytes: summary.sent_bytes(),
                delivery_confirmed: false,
            },
            rx: Receive {
                setup_packets: summary
                    .pre_send_usage()
                    .map(l2_active::PreSendUsage::packets),
                setup_bytes: summary.pre_send_usage().map(l2_active::PreSendUsage::bytes),
                collection_packets: summary.received_packets(),
                collection_bytes: summary.received_bytes(),
                total_packets: summary.total_received_packets(),
                total_bytes: summary.total_received_bytes(),
                outbound_packets: summary.outbound_packets(),
                truncated_packets: summary.truncated_packets(),
                unscoped_packets: summary.unscoped_packets(),
                capture_loss: summary.capture_loss(),
                final_backlog: summary.capture_backlog(),
            },
            stop_reason: stop_name(summary.stop_reason()),
            transport_error: summary.transport_error().map(diagnostic),
            loss_error: summary.loss_error().map(diagnostic),
            accounting_error: summary.accounting_error().map(diagnostic),
            backlog_error: summary.backlog_error().map(diagnostic),
            cleanup: Cleanup {
                confirmed: close_error.is_none(),
                error: close_error.map(ToString::to_string),
            },
        }
    }
}

pub const fn acceptance(summary: &RunSummary) -> &'static str {
    if summary.sent_packets() > 0 {
        "confirmed"
    } else if summary.send_attempted() {
        "unconfirmed"
    } else {
        "not_attempted"
    }
}

pub const fn completion_name(outcome: ActiveOutcome) -> &'static str {
    match outcome {
        ActiveOutcome::Completed | ActiveOutcome::Findings => "complete",
        ActiveOutcome::Incomplete => "incomplete",
        ActiveOutcome::Cancelled => "cancelled",
    }
}

pub const fn stop_name(reason: StopReason) -> &'static str {
    match reason {
        StopReason::Deadline => "deadline",
        StopReason::BackendDeadline => "backend_deadline",
        StopReason::Cancelled => "cancelled",
        StopReason::InterfaceDown => "interface_down",
        StopReason::PacketLimit => "packet_limit",
        StopReason::ByteLimit => "byte_limit",
        StopReason::ObservationLimit => "observation_limit",
        StopReason::TransportError => "transport_error",
        StopReason::BackendViolation => "backend_violation",
        StopReason::AccountingUnavailable => "accounting_unavailable",
    }
}

fn diagnostic(error: &io::Error) -> Diagnostic {
    Diagnostic {
        code: io_code(error.kind()),
        message: error.to_string(),
    }
}

pub fn frame_hex(bytes: &[u8]) -> Result<String, Error> {
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len() * 2)
        .map_err(|_| Error::Allocation)?;
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

pub fn write_text_quality(
    summary: &RunSummary,
    close_error: Option<&io::Error>,
    output: &mut impl io::Write,
) -> Result<(), Error> {
    writeln!(output, "Capture counts cover inbound candidates admitted by the operation profile; outgoing, excluded traffic, and physical NIC visibility are not assessed")
        .map_err(Error::Output)?;
    writeln!(output, "Send called: {}; socket acceptance: {}; accepted: {} packets, {} bytes; physical delivery unconfirmed",
        summary.send_attempted(), acceptance(summary), summary.sent_packets(), summary.sent_bytes())
        .map_err(Error::Output)?;
    writeln!(
        output,
        "Captured totals: {} packets, {} bytes; collection: {} packets, {} bytes",
        optional_count(summary.total_received_packets()),
        optional_count(summary.total_received_bytes()),
        summary.received_packets(),
        summary.received_bytes()
    )
    .map_err(Error::Output)?;
    writeln!(
        output,
        "Outbound: {}; truncated: {}; out of scope: {}; capture loss: {}; final backlog: {}",
        summary.outbound_packets(),
        summary.truncated_packets(),
        summary.unscoped_packets(),
        optional_count(summary.capture_loss()),
        match summary.capture_backlog() {
            Some(true) => "present",
            Some(false) => "none at sample",
            None => "unavailable",
        }
    )
    .map_err(Error::Output)?;
    // Failure diagnostics accompany retained evidence instead of replacing it
    for (stage, error) in [
        ("Transport", summary.transport_error()),
        ("Capture loss", summary.loss_error()),
        ("Accounting", summary.accounting_error()),
        ("Backlog", summary.backlog_error()),
    ] {
        if let Some(error) = error {
            writeln!(
                output,
                "{stage} error ({}): {}",
                io_code(error.kind()),
                error.to_string().escape_debug()
            )
            .map_err(Error::Output)?;
        }
    }
    match close_error {
        Some(error) => writeln!(
            output,
            "Helper cleanup: unconfirmed ({})",
            error.to_string().escape_debug()
        ),
        None => writeln!(output, "Helper cleanup: confirmed"),
    }
    .map_err(Error::Output)
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |count| count.to_string())
}
