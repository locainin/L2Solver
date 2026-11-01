//! Present HSRP claims while keeping authentication bytes out of diagnostics

use std::{io::Write, net::Ipv4Addr};

use l2_active::first_hop::hsrp::{
    HsrpEvidence, HsrpMalformed, HsrpOpcode, HsrpReport, HsrpState, HsrpStatus,
};
use serde::Serialize;

use super::Context;
use crate::{
    ActiveOutcome, Error, OutputFormat,
    listen_output::collection::{Collection, Diagnostics, FrameView, Operation},
    mac::format_mac,
    report_common::Evidence,
};

#[derive(Serialize)]
struct Observation {
    #[serde(flatten)]
    evidence: Claim,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum Claim {
    Advertisement {
        source_mac: String,
        source_ip: Ipv4Addr,
        virtual_ip: Ipv4Addr,
        opcode: &'static str,
        state: &'static str,
        group: u8,
        priority: u8,
        hello_seconds: u8,
        hold_seconds: u8,
        udp_checksum_present: bool,
    },
    Malformed {
        reason: &'static str,
    },
    UnsupportedVersion {
        version: u8,
    },
}

#[derive(Serialize)]
struct Details {
    selected_group: Option<u8>,
    unmatched_packets: u32,
}

pub fn write(
    context: &Context<'_>,
    selected_group: Option<u8>,
    report: &HsrpReport,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    let mut interpreted = true;
    for item in report.observations() {
        let evidence = match item.evidence() {
            HsrpEvidence::Advertisement(claim) => Claim::Advertisement {
                source_mac: format_mac(claim.source_mac().bytes()),
                source_ip: claim.source_ip(),
                virtual_ip: claim.virtual_ip(),
                opcode: opcode(claim.opcode()),
                state: state(claim.state()),
                group: claim.group(),
                priority: claim.priority(),
                hello_seconds: claim.hello_seconds(),
                hold_seconds: claim.hold_seconds(),
                udp_checksum_present: claim.udp_checksum_present(),
            },
            HsrpEvidence::Malformed(reason) => {
                interpreted = false;
                Claim::Malformed {
                    reason: malformed(*reason),
                }
            }
            HsrpEvidence::UnsupportedVersion(version) => {
                interpreted = false;
                Claim::UnsupportedVersion { version: *version }
            }
        };
        observations.push(Observation {
            evidence,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    let observed = report.status() == HsrpStatus::Observed;
    Collection {
        operation: Operation {
            name: "hsrp_observe", status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "HSRP messages and role claims are unauthenticated; they do not prove sender identity, election, or forwarding, and silence is inconclusive",
        },
        interface: context.interface, vlan: context.vlan, limits: context.limits,
        summary: report.summary(), observations,
        details: Details { selected_group, unmatched_packets: report.unmatched_packets() },
        close_error: context.close_error, diagnostics: Diagnostics::CodesOnly,
    }.write(format, output)
}

const fn malformed(reason: HsrpMalformed) -> &'static str {
    match reason {
        HsrpMalformed::SourceMac => "source_mac",
        HsrpMalformed::Ipv4 => "ipv4",
        HsrpMalformed::Udp => "udp",
        HsrpMalformed::Protocol => "protocol",
    }
}

const fn opcode(value: HsrpOpcode) -> &'static str {
    match value {
        HsrpOpcode::Hello => "hello",
        HsrpOpcode::Coup => "coup",
        HsrpOpcode::Resign => "resign",
    }
}

const fn state(value: HsrpState) -> &'static str {
    match value {
        HsrpState::Initial => "initial",
        HsrpState::Learn => "learn",
        HsrpState::Listen => "listen",
        HsrpState::Speak => "speak",
        HsrpState::Standby => "standby",
        HsrpState::Active => "active",
    }
}
