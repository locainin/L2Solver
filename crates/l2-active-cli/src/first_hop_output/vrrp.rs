//! Present IPv4 VRRPv3 claims with opt-in original frames

use std::{io, io::Write, net::Ipv4Addr, num::NonZeroU8};

use l2_active::first_hop::vrrp::{VrrpEvidence, VrrpMalformed, VrrpReport, VrrpStatus};
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
        vrid: u8,
        priority: u8,
        interval_centiseconds: u16,
        addresses: Vec<Ipv4Addr>,
        source_matches_virtual_mac: bool,
        trailing_ip_bytes: usize,
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
    selected_vrid: Option<u8>,
    unrelated_packets: u32,
}

pub(crate) fn write(
    context: &Context<'_>,
    selected_vrid: Option<NonZeroU8>,
    report: &VrrpReport,
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
            VrrpEvidence::Advertisement(claim) => {
                let addresses = item.addresses().ok_or_else(|| {
                    Error::Encoding(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid retained VRRP address range",
                    ))
                })?;
                let mut retained = Vec::new();
                retained
                    .try_reserve_exact(addresses.size_hint().1.unwrap_or(255))
                    .map_err(|_| Error::Allocation)?;
                retained.extend(addresses);
                Claim::Advertisement {
                    source_mac: format_mac(claim.source_mac().bytes()),
                    source_ip: claim.source_ip(),
                    vrid: claim.vrid().get(),
                    priority: claim.priority(),
                    interval_centiseconds: claim.interval_centiseconds(),
                    addresses: retained,
                    source_matches_virtual_mac: claim.source_matches_virtual_mac(),
                    trailing_ip_bytes: claim.trailing_ip_bytes(),
                }
            }
            VrrpEvidence::Malformed(reason) => {
                interpreted = false;
                Claim::Malformed {
                    reason: malformed(*reason),
                }
            }
            VrrpEvidence::UnsupportedVersion(version) => {
                interpreted = false;
                Claim::UnsupportedVersion { version: *version }
            }
        };
        observations.push(Observation {
            evidence,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    let observed = report.status() == VrrpStatus::Observed;
    Collection {
        operation: Operation {
            name: "vrrp_observe", status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "VRRP advertisements are unauthenticated claims; they do not prove sender identity, election, failover, or forwarding, and silence is inconclusive",
        },
        interface: context.interface, vlan: context.vlan, limits: context.limits,
        summary: report.summary(), observations,
        details: Details { selected_vrid: selected_vrid.map(NonZeroU8::get), unrelated_packets: report.unrelated_packets() },
        close_error: context.close_error, diagnostics: Diagnostics::CodesOnly,
    }.write(format, output)
}

const fn malformed(reason: VrrpMalformed) -> &'static str {
    match reason {
        VrrpMalformed::SourceMac => "source_mac",
        VrrpMalformed::Ipv4Header => "ipv4_header",
        VrrpMalformed::Ipv4Checksum => "ipv4_checksum",
        VrrpMalformed::Fragmented => "fragmented",
        VrrpMalformed::Ttl => "ttl",
        VrrpMalformed::SourceIp => "source_ip",
        VrrpMalformed::Header => "header",
        VrrpMalformed::Truncated => "truncated",
        VrrpMalformed::Checksum => "checksum",
    }
}
