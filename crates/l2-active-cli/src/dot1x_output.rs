//! Present captured EAP Requests without claiming authentication or causation

#[cfg(test)]
#[path = "../tests/cli/dot1x_output.rs"]
mod tests;

use std::io::{self, Write};

use l2_active::dot1x::{Dot1xDestination, Dot1xProbe, Dot1xReport, Dot1xStatus};
use l2_active_linux::VlanInfo;
use serde::Serialize;

use super::{
    ActiveOutcome, Dot1xProbeArgs, Error, OutputFormat,
    interface_view::InterfaceView,
    mac::format_mac,
    report_common::{self, Evidence, LimitsView, QualityView, SendMode},
};

const LIMITATION: &str = "EAP Requests are unauthenticated and have no transaction binding to Start; they do not prove causation, successful authentication, or port enforcement";

#[derive(Serialize)]
struct Scope<'a> {
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    source_mac: String,
    dedicated_interface_acknowledged: bool,
}

#[derive(Serialize)]
struct Request {
    source_mac: String,
    destination: &'static str,
    eapol_version: u8,
    identifier: u8,
    #[serde(rename = "request_type")]
    kind: u8,
    captured_bytes: usize,
    original_bytes: u32,
    frame_hex: String,
}

#[derive(Serialize)]
struct Malformed {
    reason: String,
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
    authenticated: bool,
    requests: Vec<Request>,
    malformed: Vec<Malformed>,
    unrelated_packets: u32,
    limitation: &'static str,
}

pub fn write(
    options: &Dot1xProbeArgs,
    vlan: Option<VlanInfo>,
    probe: &Dot1xProbe,
    report: &Dot1xReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let evidence = if report.status() == Dot1xStatus::Observed && report.malformed().is_empty() {
        Evidence::Observed
    } else {
        Evidence::Inconclusive
    };
    let summary = report.summary();
    let outcome = report_common::outcome(summary, SendMode::Single, evidence, close_error);
    match format {
        OutputFormat::Text => {
            writeln!(
                output,
                "802.1X probe on {}: {}  completion: {}  stop: {}",
                options.interface.name().escape_debug(),
                status_name(report.status()),
                report_common::completion_name(outcome),
                report_common::stop_name(summary.stop_reason())
            )
            .map_err(Error::Output)?;
            InterfaceView::new(options.interface.name(), summary.interface(), vlan)
                .write_text(output)?;
            for item in report.observations() {
                writeln!(
                    output,
                    "EAP Request: source {}  destination {}  identifier {}  type {}",
                    format_mac(item.source_mac().bytes()),
                    destination(item.destination()),
                    item.identifier(),
                    item.request_type()
                )
                .map_err(Error::Output)?;
            }
            writeln!(
                output,
                "Malformed EAPOL frames: {}; unrelated packets: {}",
                report.malformed().len(),
                report.unrelated_packets()
            )
            .map_err(Error::Output)?;
            report_common::write_text_quality(summary, close_error, output)?;
            writeln!(output, "{LIMITATION}").map_err(Error::Output)?;
        }
        OutputFormat::Json => {
            let value = Report {
                operation: "dot1x_probe",
                status: status_name(report.status()),
                completion: report_common::completion_name(outcome),
                scope: Scope {
                    interface: InterfaceView::new(
                        options.interface.name(),
                        summary.interface(),
                        vlan,
                    ),
                    source_mac: format_mac(probe.source_mac().bytes()),
                    dedicated_interface_acknowledged: options.dedicated_interface,
                },
                limits: LimitsView::new(probe.limits()),
                quality: QualityView::new(summary, close_error),
                authenticated: false,
                requests: requests(report)?,
                malformed: malformed(report)?,
                unrelated_packets: report.unrelated_packets(),
                limitation: LIMITATION,
            };
            serde_json::to_writer(&mut *output, &value).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)?;
        }
    }
    Ok(outcome)
}

fn requests(report: &Dot1xReport) -> Result<Vec<Request>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    for item in report.observations() {
        let frame = item.frame();
        values.push(Request {
            source_mac: format_mac(item.source_mac().bytes()),
            destination: destination(item.destination()),
            eapol_version: item.version(),
            identifier: item.identifier(),
            kind: item.request_type(),
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: report_common::frame_hex(frame.bytes())?,
        });
    }
    Ok(values)
}

fn malformed(report: &Dot1xReport) -> Result<Vec<Malformed>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(report.malformed().len())
        .map_err(|_| Error::Allocation)?;
    for item in report.malformed() {
        let frame = item.frame();
        values.push(Malformed {
            reason: format!("{:?}", item.reason()),
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: report_common::frame_hex(frame.bytes())?,
        });
    }
    Ok(values)
}

const fn destination(value: Dot1xDestination) -> &'static str {
    match value {
        Dot1xDestination::SelectedInterface => "selected_interface",
        Dot1xDestination::PaeGroup => "pae_group",
    }
}

const fn status_name(value: Dot1xStatus) -> &'static str {
    match value {
        Dot1xStatus::Observed => "observed",
        Dot1xStatus::Inconclusive => "inconclusive",
    }
}
