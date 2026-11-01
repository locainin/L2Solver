//! Preserve baseline STP and RSTP claims without inferring enforcement

use std::io::{self, Write};

use l2_active::{
    Limits,
    stp::{StpEvidence, StpReport},
};
use l2_active_linux::{InterfaceSelector, VlanInfo};
use serde::Serialize;

use super::collection::{Collection, Diagnostics, FrameView, Operation};
use crate::{ActiveOutcome, Error, OutputFormat, mac::format_mac, report_common::Evidence};

#[derive(Serialize)]
struct Bridge {
    priority_and_extension: u16,
    mac: String,
}

#[derive(Serialize)]
struct Timers {
    message_age_ticks: u16,
    max_age_ticks: u16,
    hello_ticks: u16,
    forward_delay_ticks: u16,
    ticks_per_second: u16,
}

#[derive(Serialize)]
struct Decoded {
    version: u8,
    bpdu_type: u8,
    root: Option<Bridge>,
    bridge: Option<Bridge>,
    port_id: Option<u16>,
    root_path_cost: Option<u32>,
    timers: Option<Timers>,
}

#[derive(Serialize)]
struct Observation {
    disposition: &'static str,
    detail: Option<String>,
    decoded: Option<Decoded>,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
struct Details {
    unrelated_packets: u32,
    sender_root_claim_changes: bool,
}

pub fn write(
    interface: &InterfaceSelector,
    vlan: Option<VlanInfo>,
    limits: Limits,
    report: &StpReport,
    close_error: Option<&io::Error>,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(report.observations().len())
        .map_err(|_| Error::Allocation)?;
    let mut decoded_count = 0;
    for item in report.observations() {
        let (disposition, detail) = match item.evidence() {
            StpEvidence::Decoded => {
                decoded_count += 1;
                ("decoded", None)
            }
            StpEvidence::Malformed(error) => ("malformed", Some(format!("{error:?}"))),
            StpEvidence::Unsupported(error) => ("unsupported", Some(error.to_string())),
        };
        let decoded = item.decoded().map(|decoded| Decoded {
            version: decoded.version_id,
            bpdu_type: decoded.type_id,
            root: decoded.root.map(|root| Bridge {
                priority_and_extension: root.wire_priority_and_extension(),
                mac: format_mac(root.mac),
            }),
            bridge: decoded.bridge.map(|bridge| Bridge {
                priority_and_extension: bridge.wire_priority_and_extension(),
                mac: format_mac(bridge.mac),
            }),
            port_id: decoded.port.map(|port| port.raw),
            root_path_cost: decoded.cost,
            timers: decoded.timers.map(|timers| Timers {
                message_age_ticks: timers.message_age,
                max_age_ticks: timers.max_age,
                hello_ticks: timers.hello_time,
                forward_delay_ticks: timers.forward_delay,
                ticks_per_second: 256,
            }),
        });
        observations.push(Observation {
            disposition,
            detail,
            decoded,
            frame: FrameView::new(item.frame())?,
        });
    }
    let observed = decoded_count != 0;
    let interpreted = decoded_count == report.observations().len();
    Collection {
        operation: Operation {
            name: "stp_observe",
            status: if observed { "observed" } else { "inconclusive" },
            evidence: if observed && interpreted { Evidence::Observed } else { Evidence::Inconclusive },
            limitation: "BPDUs and root claims are unauthenticated; changed claims do not establish a topology change, and silence does not prove BPDU guard or filtering",
        },
        interface,
        vlan,
        limits,
        summary: report.summary(),
        observations,
        details: Details {
            unrelated_packets: report.unrelated_packets(),
            sender_root_claim_changes: report.has_sender_root_changes(),
        },
        close_error,
        diagnostics: Diagnostics::Detailed,
    }
    .write(format, output)
}
