//! Present observed DHCP offers with their original frame and collection quality

#[cfg(test)]
#[path = "../tests/cli/dhcp_output.rs"]
mod tests;

use std::{
    io::{self, Write},
    net::Ipv4Addr,
};

use l2_active::dhcp::{DhcpProbe, DhcpReport, DhcpStatus};
use serde::Serialize;

use super::{
    ActiveOutcome, DhcpProbeArgs, Error, OutputFormat,
    mac::format_mac,
    report_common::{self, Evidence, InterfaceView, LimitsView, QualityView, SendMode},
};

const LIMITATION: &str = "DHCP offers and server identifiers are unauthenticated claims; a matching offer does not establish freshness or protection, and silence is inconclusive";

#[derive(Serialize)]
struct Scope<'a> {
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    source_mac: String,
    transaction_id: u32,
    expected_servers: Option<&'a [Ipv4Addr]>,
}

#[derive(Serialize)]
struct Offer {
    server_identifier: Ipv4Addr,
    offered_address: Ipv4Addr,
    lease_seconds: u32,
    source_mac: String,
    source_ip: Ipv4Addr,
    relay_ip: Ipv4Addr,
    udp_checksum_present: bool,
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
    authenticated: bool,
    offers: Vec<Offer>,
    limitation: &'static str,
}

pub fn write(
    options: &DhcpProbeArgs,
    probe: &DhcpProbe,
    report: &DhcpReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let evidence = match report.status() {
        DhcpStatus::Observed => Evidence::Observed,
        DhcpStatus::UnexpectedServer => Evidence::Findings,
        DhcpStatus::Inconclusive => Evidence::Inconclusive,
    };
    let summary = report.summary();
    let outcome = report_common::outcome(summary, SendMode::Single, evidence, close_error);
    match format {
        OutputFormat::Text => {
            writeln!(
                output,
                "DHCP probe on {}: {}  completion: {}  stop: {}",
                options.interface.name().escape_debug(),
                status_name(report.status()),
                report_common::completion_name(outcome),
                report_common::stop_name(summary.stop_reason())
            )
            .map_err(Error::Output)?;
            for offer in report.observations() {
                writeln!(
                    output,
                    "Offer: server {}  address {}  lease {}s  expected: {}",
                    offer.server_identifier(),
                    offer.offered_address(),
                    offer.lease_seconds(),
                    match report.expected_match(offer.server_identifier()) {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "not specified",
                    }
                )
                .map_err(Error::Output)?;
            }
            report_common::write_text_quality(summary, close_error, output)?;
            writeln!(output, "{LIMITATION}").map_err(Error::Output)?;
        }
        OutputFormat::Json => {
            let mut offers = Vec::new();
            offers
                .try_reserve_exact(report.observations().len())
                .map_err(|_| Error::Allocation)?;
            for observation in report.observations() {
                let frame = observation.frame();
                offers.push(Offer {
                    server_identifier: observation.server_identifier(),
                    offered_address: observation.offered_address(),
                    lease_seconds: observation.lease_seconds(),
                    source_mac: format_mac(observation.source_mac().bytes()),
                    source_ip: observation.source_ip(),
                    relay_ip: observation.relay_ip(),
                    udp_checksum_present: observation.udp_checksum_present(),
                    matches_expected: report.expected_match(observation.server_identifier()),
                    captured_bytes: frame.captured_len(),
                    original_bytes: frame.metadata().original_len(),
                    frame_hex: report_common::frame_hex(frame.bytes())?,
                });
            }
            let value = Report {
                operation: "dhcp_probe",
                status: status_name(report.status()),
                completion: report_common::completion_name(outcome),
                scope: Scope {
                    interface: InterfaceView::new(&options.interface, summary),
                    source_mac: format_mac(probe.source_mac().bytes()),
                    transaction_id: probe.transaction().get(),
                    expected_servers: (!options.expected_server.is_empty())
                        .then_some(options.expected_server.as_slice()),
                },
                limits: LimitsView::new(probe.limits()),
                quality: QualityView::new(summary, close_error),
                authenticated: false,
                offers,
                limitation: LIMITATION,
            };
            serde_json::to_writer(&mut *output, &value).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)?;
        }
    }
    Ok(outcome)
}

const fn status_name(status: DhcpStatus) -> &'static str {
    match status {
        DhcpStatus::Observed => "observed",
        DhcpStatus::UnexpectedServer => "unexpected_server",
        DhcpStatus::Inconclusive => "inconclusive",
    }
}
