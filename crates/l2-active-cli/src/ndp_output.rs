//! Present actual neighbor advertisements and their collection quality

#[cfg(test)]
#[path = "../tests/cli/ndp_output.rs"]
mod tests;

use std::{
    io::{self, Write},
    net::Ipv6Addr,
};

use l2_active::{NdpProbe, NdpReport};
use l2_active_linux::VlanInfo;
use serde::Serialize;

use super::{
    ActiveOutcome, Error, NdpProbeArgs, OutputFormat,
    interface_view::InterfaceView,
    mac::format_mac,
    neighbor_output::{evidence, status_name},
    report_common::{self, LimitsView, QualityView, SendMode},
};

const LIMITATION: &str = "Neighbor advertisements are unauthenticated claims and cannot establish freshness or ownership; silence is inconclusive and link state is sampled";

#[derive(Serialize)]
struct Scope<'a> {
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    source_ip: Ipv6Addr,
    source_prefix_len: u8,
    source_mac: String,
    target: Ipv6Addr,
    expected_mac: Option<String>,
}

#[derive(Serialize)]
struct Reply {
    mac: String,
    source_ip: Ipv6Addr,
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
    unmatched_packets: u32,
    authenticated: bool,
    replies: Vec<Reply>,
    limitation: &'static str,
}

pub fn write(
    options: &NdpProbeArgs,
    vlan: Option<VlanInfo>,
    probe: &NdpProbe,
    report: &NdpReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let evidence = evidence(report.status(), report.has_conflicting_identities());
    let summary = report.summary();
    let outcome = report_common::outcome(summary, SendMode::Single, evidence, close_error);
    match format {
        OutputFormat::Text => {
            writeln!(
                output,
                "NDP probe: {} on {}  status: {}  completion: {}  stop: {}",
                probe.target(),
                options.interface.name().escape_debug(),
                status_name(report.status()),
                report_common::completion_name(outcome),
                report_common::stop_name(summary.stop_reason())
            )
            .map_err(Error::Output)?;
            InterfaceView::new(options.interface.name(), summary.interface(), vlan)
                .write_text(output)?;
            for observation in report.observations() {
                writeln!(
                    output,
                    "Reply: {} from {}  expected match: {}",
                    format_mac(observation.mac().bytes()),
                    observation.source_ip(),
                    match probe
                        .expected()
                        .map(|expected| expected == observation.mac())
                    {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "not specified",
                    }
                )
                .map_err(Error::Output)?;
            }
            writeln!(
                output,
                "Conflicting identities: {}; unmatched packets: {}",
                report.has_conflicting_identities(),
                report.unmatched_packets()
            )
            .map_err(Error::Output)?;
            report_common::write_text_quality(summary, close_error, output)?;
            writeln!(output, "{LIMITATION}").map_err(Error::Output)?;
        }
        OutputFormat::Json => {
            let replies = reply_views(probe, report)?;
            let value = Report {
                operation: "ndp_probe",
                status: status_name(report.status()),
                completion: report_common::completion_name(outcome),
                scope: Scope {
                    interface: InterfaceView::new(
                        options.interface.name(),
                        summary.interface(),
                        vlan,
                    ),
                    source_ip: probe.source_ip(),
                    source_prefix_len: probe.prefix_len(),
                    source_mac: format_mac(probe.source_mac().bytes()),
                    target: probe.target(),
                    expected_mac: probe.expected().map(|mac| format_mac(mac.bytes())),
                },
                limits: LimitsView::new(probe.limits()),
                quality: QualityView::new(summary, close_error),
                conflicting_identities: report.has_conflicting_identities(),
                unmatched_packets: report.unmatched_packets(),
                authenticated: false,
                replies,
                limitation: LIMITATION,
            };
            serde_json::to_writer(&mut *output, &value).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)?;
        }
    }
    Ok(outcome)
}

fn reply_views(probe: &NdpProbe, report: &NdpReport) -> Result<Vec<Reply>, Error> {
    let mut replies = Vec::new();
    replies
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    for observation in report.observations() {
        let frame = observation.frame();
        replies.push(Reply {
            mac: format_mac(observation.mac().bytes()),
            source_ip: observation.source_ip(),
            matches_expected: probe
                .expected()
                .map(|expected| expected == observation.mac()),
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: report_common::frame_hex(frame.bytes())?,
        });
    }
    Ok(replies)
}
