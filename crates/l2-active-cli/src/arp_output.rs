//! Render source-qualified ARP replies and separate execution quality

#[cfg(test)]
#[path = "../tests/cli/arp_output.rs"]
mod tests;

use std::{
    io::{self, Write},
    net::Ipv4Addr,
};

use l2_active::{ArpProbe, ArpReport};
use l2_active_linux::InterfaceSelector;
use serde::Serialize;

use super::{
    ActiveOutcome, Error, OutputFormat,
    mac::format_mac,
    neighbor_output::{evidence, status_name},
    report_common::{self, InterfaceView, LimitsView, QualityView, SendMode},
};

const LIMITATION: &str = "ARP replies are unauthenticated and do not establish freshness or protection; link state and queue readiness are sampled and cannot exclude brief outages, prior loss, or later arrivals";

#[derive(Serialize)]
struct Scope<'a> {
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    source_ip: Ipv4Addr,
    source_mac: String,
    target: Ipv4Addr,
    expected_mac: Option<String>,
}

#[derive(Serialize)]
struct Reply {
    mac: String,
    matches_expected: Option<bool>,
    captured_bytes: usize,
    original_bytes: u32,
    frame_hex: String,
}

#[derive(Serialize)]
struct Report<'a> {
    operation: &'static str,
    status: &'static str,
    completion: &'static str,
    scope: Scope<'a>,
    limits: LimitsView,
    #[serde(flatten)]
    quality: QualityView,
    conflicting_identities: bool,
    authenticated: bool,
    replies: Vec<Reply>,
    limitation: &'static str,
}

pub fn write(
    interface: &InterfaceSelector,
    probe: &ArpProbe,
    report: &ArpReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let summary = report.summary();
    let evidence = evidence(report.status(), report.has_conflicting_identities());
    let outcome = report_common::outcome(summary, SendMode::Single, evidence, close_error);
    match format {
        OutputFormat::Text => write_text(interface, probe, report, close_error, outcome, output)?,
        OutputFormat::Json => write_json(interface, probe, report, close_error, outcome, output)?,
    }
    Ok(outcome)
}

fn write_text(
    interface: &InterfaceSelector,
    probe: &ArpProbe,
    report: &ArpReport,
    close_error: Option<&io::Error>,
    outcome: ActiveOutcome,
    output: &mut impl Write,
) -> Result<(), Error> {
    let summary = report.summary();
    writeln!(
        output,
        "ARP probe: {} on {} (index {})",
        probe.target(),
        interface.name().escape_debug(),
        summary.interface().ifindex()
    )
    .map_err(Error::Output)?;
    writeln!(
        output,
        "Source: {} ({})",
        probe.source_ip(),
        format_mac(probe.source_mac().bytes())
    )
    .map_err(Error::Output)?;
    writeln!(
        output,
        "Status: {}  completion: {}  stop: {}",
        status_name(report.status()),
        report_common::completion_name(outcome),
        report_common::stop_name(summary.stop_reason())
    )
    .map_err(Error::Output)?;
    report_common::write_text_quality(summary, close_error, output)?;
    for observation in report.observations() {
        writeln!(
            output,
            "Reply: {}  expected match: {}",
            format_mac(observation.mac().bytes()),
            match report.expected_match(observation.mac()) {
                Some(true) => "yes",
                Some(false) => "no",
                None => "not specified",
            }
        )
        .map_err(Error::Output)?;
    }
    writeln!(
        output,
        "Conflicting identities: {}",
        if report.has_conflicting_identities() {
            "yes"
        } else {
            "no"
        }
    )
    .map_err(Error::Output)?;
    writeln!(output, "{LIMITATION}").map_err(Error::Output)
}

fn write_json(
    interface: &InterfaceSelector,
    probe: &ArpProbe,
    report: &ArpReport,
    close_error: Option<&io::Error>,
    outcome: ActiveOutcome,
    output: &mut impl Write,
) -> Result<(), Error> {
    let summary = report.summary();
    let mut replies = Vec::new();
    replies
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    for observation in report.observations() {
        let frame = observation.frame();
        replies.push(Reply {
            mac: format_mac(observation.mac().bytes()),
            matches_expected: report.expected_match(observation.mac()),
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: report_common::frame_hex(frame.bytes())?,
        });
    }
    let value = Report {
        operation: "arp_probe",
        status: status_name(report.status()),
        completion: report_common::completion_name(outcome),
        scope: Scope {
            interface: InterfaceView::new(interface, summary),
            source_ip: probe.source_ip(),
            source_mac: format_mac(probe.source_mac().bytes()),
            target: probe.target(),
            expected_mac: probe.expected().map(|mac| format_mac(mac.bytes())),
        },
        limits: LimitsView::new(probe.limits()),
        quality: QualityView::new(summary, close_error),
        conflicting_identities: report.has_conflicting_identities(),
        authenticated: false,
        replies,
        limitation: LIMITATION,
    };
    serde_json::to_writer(&mut *output, &value).map_err(Error::Json)?;
    writeln!(output).map_err(Error::Output)
}
