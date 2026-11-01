//! Present DTP and VTP claims without exposing raw frames by default

use std::{io::Write, net::Ipv4Addr};

use l2_active::switching::{
    dtp::{
        DtpAdministrativeStatus, DtpEvidence, DtpMalformed, DtpOperatingStatus, DtpReport,
        DtpTrunkEncapsulation,
    },
    vtp::{VtpEvidence, VtpMalformed, VtpMessageKind, VtpReport, VtpVlan},
};
use serde::Serialize;

use super::collection::{Collection, Context, Diagnostics, FrameView, Operation};
use crate::{
    ActiveOutcome, Error, OutputFormat,
    mac::format_mac,
    report_common::{Evidence, frame_hex},
};

#[cfg(test)]
#[path = "../../tests/switching/renderer.rs"]
mod tests;

#[derive(Serialize)]
struct Observation<T> {
    #[serde(flatten)]
    evidence: T,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum DtpClaim {
    Advertisement {
        source_mac: String,
        domain_hex: Option<String>,
        status_raw: Option<u8>,
        operating_status: Option<&'static str>,
        administrative_status: Option<&'static str>,
        trunk_type_raw: Option<u8>,
        operating_encapsulation: Option<&'static str>,
        administrative_encapsulation: Option<&'static str>,
        sender_id: Option<String>,
    },
    Malformed {
        reason: &'static str,
    },
    UnsupportedVersion {
        version: u8,
    },
    ParserLimit,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum VtpClaim {
    Message {
        source_mac: String,
        version: u8,
        domain_hex: String,
        #[serde(flatten)]
        message: VtpKind,
    },
    Malformed {
        reason: &'static str,
    },
    UnsupportedVersion {
        version: u8,
    },
    UnsupportedMessage {
        code: u8,
    },
    ParserLimit,
}

#[derive(Serialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
enum VtpKind {
    Summary {
        revision: u32,
        followers: u8,
        updater: Ipv4Addr,
    },
    Subset {
        revision: u32,
        sequence: u8,
        vlans: Vec<Vlan>,
    },
    Request {
        start_value: u16,
    },
}

#[derive(Serialize)]
struct Vlan {
    id: u16,
    status: u8,
    #[serde(rename = "vlan_type")]
    media_type: u8,
    mtu: u16,
    said: u32,
    name_hex: String,
}

#[derive(Serialize)]
struct Details {
    unmatched_packets: u32,
}

pub fn write_dtp(
    context: &Context<'_>,
    report: &DtpReport,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    let mut observed = false;
    let mut interpreted = true;
    for item in report.observations() {
        // Keep malformed or unsupported candidates visible without treating them as claims
        let evidence = match item.evidence() {
            DtpEvidence::Advertisement(claim) => {
                observed = true;
                let status = claim.status();
                let trunk_type = claim.trunk_type();
                DtpClaim::Advertisement {
                    source_mac: format_mac(claim.source_mac()),
                    // Hex preserves the exact advertised bytes without terminal controls
                    domain_hex: claim.domain().map(frame_hex).transpose()?,
                    status_raw: status.map(l2_active::switching::dtp::DtpStatus::raw),
                    operating_status: status.map(|value| operating_status(value.operating())),
                    administrative_status: status
                        .map(|value| administrative_status(value.administrative())),
                    trunk_type_raw: trunk_type.map(l2_active::switching::dtp::DtpTrunkType::raw),
                    operating_encapsulation: trunk_type
                        .map(|value| encapsulation(value.operating())),
                    administrative_encapsulation: trunk_type
                        .map(|value| encapsulation(value.administrative())),
                    sender_id: claim.sender_id().map(format_mac),
                }
            }
            DtpEvidence::Malformed(reason) => {
                interpreted = false;
                DtpClaim::Malformed {
                    reason: dtp_malformed(*reason),
                }
            }
            DtpEvidence::UnsupportedVersion(version) => {
                interpreted = false;
                DtpClaim::UnsupportedVersion { version: *version }
            }
            DtpEvidence::LimitExceeded => {
                interpreted = false;
                DtpClaim::ParserLimit
            }
        };
        observations.push(Observation {
            evidence,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    Collection {
        operation: Operation {
            name: "dtp_observe", status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "DTP fields are unauthenticated claims; they do not prove sender identity, actual trunk state, or access enforcement; silence is inconclusive",
        },
        interface: context.interface, vlan: context.vlan, limits: context.limits,
        summary: report.summary(), observations, details: Details { unmatched_packets: report.unmatched_packets() },
        close_error: context.close_error, diagnostics: Diagnostics::CodesOnly,
    }.write(format, output)
}

pub fn write_vtp(
    context: &Context<'_>,
    report: &VtpReport,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    let mut observed = false;
    let mut interpreted = true;
    for item in report.observations() {
        // Summary digest and unknown extensions remain outside structured output
        let evidence = match item.evidence() {
            VtpEvidence::Message(claim) => {
                observed = true;
                VtpClaim::Message {
                    source_mac: format_mac(claim.source_mac()),
                    version: claim.version(),
                    domain_hex: frame_hex(claim.domain())?,
                    message: vtp_kind(claim.kind())?,
                }
            }
            VtpEvidence::Malformed(reason) => {
                interpreted = false;
                VtpClaim::Malformed {
                    reason: vtp_malformed(*reason),
                }
            }
            VtpEvidence::UnsupportedVersion(version) => {
                interpreted = false;
                VtpClaim::UnsupportedVersion { version: *version }
            }
            VtpEvidence::UnsupportedMessage(code) => {
                interpreted = false;
                VtpClaim::UnsupportedMessage { code: *code }
            }
            VtpEvidence::LimitExceeded => {
                interpreted = false;
                VtpClaim::ParserLimit
            }
        };
        observations.push(Observation {
            evidence,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    Collection {
        operation: Operation {
            name: "vtp_observe", status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "VTP fields are unauthenticated claims; digest and summary extensions are not validated, and one subset does not prove a complete VLAN database or enforcement",
        },
        interface: context.interface, vlan: context.vlan, limits: context.limits,
        summary: report.summary(), observations, details: Details { unmatched_packets: report.unmatched_packets() },
        close_error: context.close_error, diagnostics: Diagnostics::CodesOnly,
    }.write(format, output)
}

fn vtp_kind(kind: &VtpMessageKind) -> Result<VtpKind, Error> {
    Ok(match kind {
        VtpMessageKind::Summary {
            revision,
            followers,
            updater,
        } => VtpKind::Summary {
            revision: *revision,
            followers: *followers,
            updater: *updater,
        },
        VtpMessageKind::Subset {
            revision,
            sequence,
            vlans,
        } => {
            // Report only VLAN records carried in this one subset message
            let mut items = Vec::new();
            items
                .try_reserve_exact(vlans.len())
                .map_err(|_| Error::Allocation)?;
            for vlan in vlans {
                items.push(vlan_view(vlan)?);
            }
            VtpKind::Subset {
                revision: *revision,
                sequence: *sequence,
                vlans: items,
            }
        }
        VtpMessageKind::Request { start_value } => VtpKind::Request {
            start_value: *start_value,
        },
    })
}

fn vlan_view(vlan: &VtpVlan) -> Result<Vlan, Error> {
    Ok(Vlan {
        id: vlan.id(),
        status: vlan.status(),
        media_type: vlan.vlan_type(),
        mtu: vlan.mtu(),
        said: vlan.said(),
        name_hex: frame_hex(vlan.name())?,
    })
}

const fn dtp_malformed(reason: DtpMalformed) -> &'static str {
    match reason {
        DtpMalformed::Ethernet => "ethernet",
        DtpMalformed::SourceMac => "source_mac",
        DtpMalformed::Protocol => "protocol",
    }
}

const fn vtp_malformed(reason: VtpMalformed) -> &'static str {
    match reason {
        VtpMalformed::Ethernet => "ethernet",
        VtpMalformed::SourceMac => "source_mac",
        VtpMalformed::Protocol => "protocol",
    }
}

const fn operating_status(value: DtpOperatingStatus) -> &'static str {
    match value {
        DtpOperatingStatus::Access => "access",
        DtpOperatingStatus::Trunk => "trunk",
    }
}

const fn administrative_status(value: DtpAdministrativeStatus) -> &'static str {
    match value {
        DtpAdministrativeStatus::On => "on",
        DtpAdministrativeStatus::Off => "off",
        DtpAdministrativeStatus::Desirable => "desirable",
        DtpAdministrativeStatus::Auto => "auto",
        DtpAdministrativeStatus::Other(_) => "other",
    }
}

const fn encapsulation(value: DtpTrunkEncapsulation) -> &'static str {
    match value {
        DtpTrunkEncapsulation::Negotiated => "negotiated",
        DtpTrunkEncapsulation::Native => "native",
        DtpTrunkEncapsulation::Isl => "isl",
        DtpTrunkEncapsulation::Dot1q => "dot1q",
        DtpTrunkEncapsulation::Other(_) => "other",
    }
}
