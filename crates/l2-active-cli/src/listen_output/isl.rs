//! Present ISL header claims without exposing encapsulated traffic by default

use std::io::Write;

use l2_active::isl::{IslEvidence, IslMalformed, IslReport, IslStatus};
use serde::Serialize;

use super::collection::{Collection, Context, Diagnostics, FrameView, Operation};
use crate::{
    ActiveOutcome, Error, OutputFormat,
    mac::format_mac,
    report_common::{Evidence, frame_hex},
};

#[cfg(test)]
#[path = "../../tests/switching/isl_renderer.rs"]
mod tests;

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
    Frame {
        destination_prefix_hex: String,
        source_mac: String,
        media_type: u8,
        user: u8,
        priority: u8,
        declared_length: u16,
        llc_hex: String,
        hsa_hex: String,
        vlan_id: u16,
        bpdu: bool,
        port_index: u16,
        reserved: u16,
        inner_frame_length: usize,
    },
    Malformed {
        reason: &'static str,
    },
    UnsupportedMedia {
        media_type: u8,
    },
    UnsupportedLength,
    ParserLimit,
}

#[derive(Serialize)]
struct Details {
    unmatched_packets: u32,
    admitted_media: &'static str,
    crc_validation: &'static str,
}

pub fn write(
    context: &Context<'_>,
    report: &IslReport,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    let mut interpreted = true;
    for item in report.observations() {
        // Header fields describe claims, not the encapsulated traffic
        let evidence = match item.evidence() {
            IslEvidence::Frame(header) => Claim::Frame {
                destination_prefix_hex: frame_hex(&header.destination_prefix())?,
                source_mac: format_mac(header.source_mac()),
                media_type: header.media_type(),
                user: header.user(),
                priority: header.priority(),
                declared_length: header.declared_length(),
                llc_hex: frame_hex(&header.llc())?,
                hsa_hex: frame_hex(&header.hsa())?,
                vlan_id: header.vlan_id(),
                bpdu: header.bpdu(),
                port_index: header.port_index(),
                reserved: header.reserved(),
                inner_frame_length: header.inner_frame_length(),
            },
            IslEvidence::Malformed(reason) => {
                interpreted = false;
                Claim::Malformed {
                    reason: malformed(*reason),
                }
            }
            IslEvidence::UnsupportedMedia(media_type) => {
                interpreted = false;
                Claim::UnsupportedMedia {
                    media_type: *media_type,
                }
            }
            IslEvidence::UnsupportedLength => {
                interpreted = false;
                Claim::UnsupportedLength
            }
            IslEvidence::LimitExceeded => {
                interpreted = false;
                Claim::ParserLimit
            }
        };
        // Only an explicit disclosure request copies complete captured bytes
        observations.push(Observation {
            evidence,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    // An observed frame cannot make other unsupported candidates complete
    let observed = report.status() == IslStatus::Observed;
    Collection {
        operation: Operation {
            name: "isl_observe", status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "ISL fields are unauthenticated claims; Ethernet media only is captured, neither CRC is checked, and VLAN or trunk enforcement cannot be inferred",
        },
        interface: context.interface, vlan: context.vlan, limits: context.limits,
        summary: report.summary(), observations,
        details: Details { unmatched_packets: report.unmatched_packets(), admitted_media: "ethernet_only", crc_validation: "not_performed" },
        close_error: context.close_error, diagnostics: Diagnostics::CodesOnly,
    }.write(format, output)
}

const fn malformed(reason: IslMalformed) -> &'static str {
    match reason {
        IslMalformed::Header => "header",
        IslMalformed::SourceMac => "source_mac",
        IslMalformed::Length => "length",
        IslMalformed::InnerEthernet => "inner_ethernet",
    }
}
