//! Preserve received LLDP and CDP identity bytes and hold times

use std::io::{self, Write};

use l2_active::{
    Limits,
    discovery::{DiscoveryDisposition, DiscoveryProtocol, DiscoveryReport, DiscoveryStatus},
};
use l2_active_linux::{InterfaceSelector, VlanInfo};
use serde::Serialize;

use super::collection::{Collection, FrameView, Operation};
use crate::{
    ActiveOutcome, Error, OutputFormat,
    mac::format_mac,
    report_common::{Evidence, frame_hex},
};

#[derive(Serialize)]
struct Observation {
    protocol: &'static str,
    source_mac: String,
    destination_mac: String,
    disposition: &'static str,
    advertised_hold_seconds: Option<u16>,
    device_hex: Option<String>,
    port_hex: Option<String>,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
struct Details {
    unmatched_packets: u32,
}

pub fn write(
    interface: &InterfaceSelector,
    vlan: Option<VlanInfo>,
    limits: Limits,
    report: &DiscoveryReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    for item in report.observations() {
        let identity = item.identity();
        observations.push(Observation {
            protocol: match item.protocol() {
                DiscoveryProtocol::Lldp => "lldp",
                DiscoveryProtocol::Cdp => "cdp",
            },
            source_mac: format_mac(item.source_mac()),
            destination_mac: format_mac(item.destination_mac()),
            disposition: match item.disposition() {
                DiscoveryDisposition::Advertisement => "advertisement",
                DiscoveryDisposition::Withdrawal => "withdrawal",
                DiscoveryDisposition::Malformed => "malformed",
                DiscoveryDisposition::LimitExceeded => "parser_limit",
            },
            advertised_hold_seconds: item.hold_seconds(),
            device_hex: identity
                .map(|identity| frame_hex(identity.device()))
                .transpose()?,
            port_hex: identity
                .map(|identity| frame_hex(identity.port()))
                .transpose()?,
            frame: FrameView::new(item.frame())?,
        });
    }
    let interpretation_complete = report.observations().iter().all(|item| {
        matches!(
            item.disposition(),
            DiscoveryDisposition::Advertisement | DiscoveryDisposition::Withdrawal
        )
    });
    let (status, evidence) = match report.status() {
        DiscoveryStatus::Observed => (
            "observed",
            if interpretation_complete {
                Evidence::Observed
            } else {
                Evidence::Inconclusive
            },
        ),
        DiscoveryStatus::Malformed => ("malformed", Evidence::Inconclusive),
        DiscoveryStatus::Inconclusive => ("inconclusive", Evidence::Inconclusive),
    };
    Collection {
        operation: Operation { name: "discovery_observe", status, evidence,
            limitation: "LLDP/CDP claims and hold times are unauthenticated; withdrawals do not prove absence, and silence does not prove isolation or physical multicast visibility" },
        interface, vlan, limits, summary: report.summary(), observations,
        details: Details { unmatched_packets: report.unmatched_packets() }, close_error,
    }.write(format, output)
}
