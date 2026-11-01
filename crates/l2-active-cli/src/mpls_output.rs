//! Present MPLS label observations with opt-in raw evidence

use std::io::Write;

use l2_active::mpls::{
    MplsEvidence, MplsLabel, MplsMalformed, MplsReport, MplsStatus, MplsUnsupported,
};
use serde::Serialize;

use crate::{
    ActiveOutcome, Error, OutputFormat,
    listen_output::collection::{Collection, Context, Diagnostics, FrameView, Operation},
    mac::format_mac,
    report_common::Evidence,
};

#[derive(Serialize)]
struct Label {
    value: u32,
    traffic_class: u8,
    bottom_of_stack: bool,
    ttl: u8,
}

impl From<MplsLabel> for Label {
    fn from(label: MplsLabel) -> Self {
        Self {
            value: label.value(),
            traffic_class: label.traffic_class(),
            bottom_of_stack: label.bottom_of_stack(),
            ttl: label.ttl(),
        }
    }
}

#[derive(Serialize)]
struct Observation {
    #[serde(flatten)]
    evidence: Claim,
    source_mac: Option<String>,
    labels: Vec<Label>,
    top_ttl_is_zero: Option<bool>,
    top_label_matches_expectation: Option<bool>,
    captured_bytes_after_stack: Option<usize>,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
enum Claim {
    Stack,
    Malformed {
        reason: &'static str,
    },
    Unsupported {
        reason: &'static str,
        special_purpose_label: Option<u32>,
    },
}

#[derive(Serialize)]
struct Details {
    expected_top_label: Option<u32>,
    unexpected_top_label: Option<bool>,
    unrelated_packets: u32,
}

pub fn write(
    context: &Context<'_>,
    report: &MplsReport,
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
            MplsEvidence::Stack => Claim::Stack,
            MplsEvidence::Malformed(reason) => {
                interpreted = false;
                Claim::Malformed {
                    reason: malformed(reason),
                }
            }
            MplsEvidence::Unsupported(reason) => {
                interpreted = false;
                let (reason, special_purpose_label) = unsupported(reason);
                Claim::Unsupported {
                    reason,
                    special_purpose_label,
                }
            }
        };
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(item.labels().size_hint().1.unwrap_or(16))
            .map_err(|_| Error::Allocation)?;
        labels.extend(item.labels().map(Label::from));
        let top = labels.first();
        let top_label_matches_expectation =
            match (item.evidence(), report.expected_top_label(), top) {
                (MplsEvidence::Stack, Some(expected), Some(label)) => Some(label.value == expected),
                _ => None,
            };
        observations.push(Observation {
            evidence,
            source_mac: item.source_mac().map(|mac| format_mac(mac.bytes())),
            top_ttl_is_zero: top.map(|label| label.ttl == 0),
            top_label_matches_expectation,
            captured_bytes_after_stack: item.captured_bytes_after_stack(),
            labels,
            frame: FrameView::for_disclosure(item.frame(), context.disclosure)?,
        });
    }
    let observed = report.status() == MplsStatus::Observed;
    let unexpected = report.has_unexpected_top_label();
    // Uninterpreted candidates cannot establish a negative comparison
    let comparison =
        (report.expected_top_label().is_some() && observed && (interpreted || unexpected))
            .then_some(unexpected);
    let evidence = if !observed || !interpreted {
        Evidence::Inconclusive
    } else if unexpected {
        Evidence::Findings
    } else {
        Evidence::Observed
    };
    Collection {
        operation: Operation {
            name: "mpls_observe",
            status: if observed { "observed" } else { "inconclusive" },
            evidence,
            limitation: "MPLS entries are unauthenticated wire fields; a label mismatch does not prove an LSP, forwarding, isolation, or cause. Custom indicators can make later words data, and captured bytes after the stack may include padding or FCS",
        },
        interface: context.interface,
        vlan: context.vlan,
        limits: context.limits,
        summary: report.summary(),
        observations,
        details: Details {
            expected_top_label: report.expected_top_label(),
            unexpected_top_label: comparison,
            unrelated_packets: report.unrelated_packets(),
        },
        close_error: context.close_error,
        diagnostics: Diagnostics::CodesOnly,
    }
    .write(format, output)
}

const fn malformed(reason: MplsMalformed) -> &'static str {
    match reason {
        MplsMalformed::SourceMac => "source_mac",
        MplsMalformed::TruncatedStack => "truncated_stack",
        MplsMalformed::MissingPayload => "missing_payload",
        MplsMalformed::SpecialPurposeLabel => "special_purpose_label",
    }
}

const fn unsupported(reason: MplsUnsupported) -> (&'static str, Option<u32>) {
    match reason {
        MplsUnsupported::StackDepthLimit => ("stack_depth_limit", None),
        MplsUnsupported::SpecialPurposeLabel(value) => ("special_purpose_label", Some(value)),
    }
}
