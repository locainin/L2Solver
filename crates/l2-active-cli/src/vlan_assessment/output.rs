//! Render the three retained observations and their collection quality

use std::{
    io::{self, Write},
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
};

use l2_active::{Limits, StopReason};
use l2_active_linux::VlanInfo;
use l2_capture::LinuxInterfaceIdentity;
use l2_onpath::MacAddress;
use serde::Serialize;
use serde_json::ser::{CompactFormatter, PrettyFormatter};

use crate::{
    ActiveOutcome, Error, OutputFormat,
    diagnostic::io_error_code,
    interface_view::InterfaceView,
    listen_output::collection::{Disclosure, FrameView},
    mac::format_mac,
    report_common::{self, LimitsView, QualityView, SendMode},
    safe_json::write_json as write_safe_json,
};

use super::{
    decision::{self, Claim},
    engine::{Assessment, Attempt, FailureStage, SkipReason, Step},
};

#[cfg(test)]
#[path = "../../tests/vlan_assessment/output.rs"]
mod tests;

const LIMITATION: &str = "ARP claims are unauthenticated and may be replayed or proxied; the canary's placement is operator asserted, VLAN and link state are sampled, and silence never proves isolation";

pub(super) struct Endpoint<'a> {
    pub name: &'a str,
    pub identity: LinuxInterfaceIdentity,
    pub vlan: Option<VlanInfo>,
    pub source_ip: Ipv4Addr,
    pub source_mac: MacAddress,
}

pub(super) struct Context<'a> {
    pub control: Endpoint<'a>,
    pub test: Endpoint<'a>,
    pub target: Ipv4Addr,
    pub expected: MacAddress,
    pub budget: Limits,
    pub disclosure: Disclosure,
}

#[derive(Serialize)]
struct EndpointView<'a> {
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    segment_status: &'static str,
    source_ip: Ipv4Addr,
    source_mac: String,
}

impl<'a> EndpointView<'a> {
    fn new(endpoint: &'a Endpoint<'a>) -> Self {
        Self {
            interface: InterfaceView::new(endpoint.name, endpoint.identity, endpoint.vlan),
            segment_status: if endpoint.vlan.is_some() {
                "kernel_vlan_metadata"
            } else {
                "unknown"
            },
            source_ip: endpoint.source_ip,
            source_mac: format_mac(endpoint.source_mac.bytes()),
        }
    }
}

#[derive(Serialize)]
struct ScopeView<'a> {
    control: EndpointView<'a>,
    test: EndpointView<'a>,
    target: Ipv4Addr,
    expected_mac: String,
    canary_placement: &'static str,
}

#[derive(Serialize)]
struct ReplyView {
    mac: String,
    matches_expected: Option<bool>,
    #[serde(flatten)]
    frame: FrameView,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "three bounded phase views avoid extra heap allocations"
)]
enum StepView {
    Collected {
        limits: LimitsView,
        #[serde(flatten)]
        quality: QualityView,
        expected_claim_observed: bool,
        conflicting_identities: bool,
        replies: Vec<ReplyView>,
    },
    Failed {
        limits: LimitsView,
        stage: &'static str,
        code: &'static str,
        cleanup: &'static str,
        cleanup_error: Option<&'static str>,
    },
    Skipped {
        reason: &'static str,
    },
}

#[derive(Serialize)]
struct Report<'a> {
    operation: &'static str,
    status: &'static str,
    completion: &'static str,
    scope: ScopeView<'a>,
    per_interface_budget: LimitsView,
    control_claims_observed: bool,
    authenticated: bool,
    control_before: StepView,
    test: StepView,
    control_after: StepView,
    limitation: &'static str,
}

pub(super) fn write(
    context: &Context<'_>,
    result: &Assessment,
    cancelled: &AtomicBool,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let outcome = outcome(result, cancelled);
    match format {
        OutputFormat::Text => write_text(context, result, outcome, output)?,
        OutputFormat::Json => write_json(context, result, outcome, output)?,
    }
    Ok(outcome)
}

fn outcome(result: &Assessment, cancelled: &AtomicBool) -> ActiveOutcome {
    let steps = [&result.before, &result.test, &result.after];
    if cancelled.load(Ordering::Acquire) || steps.iter().any(|step| is_cancelled(step)) {
        return ActiveOutcome::Cancelled;
    }
    if decision::test_claim(result) == Claim::ExpectedObserved
        && decision::controls_observed(result)
        && steps.iter().all(|step| complete(step))
    {
        ActiveOutcome::Findings
    } else {
        ActiveOutcome::Incomplete
    }
}

fn complete(step: &Step) -> bool {
    match step {
        Step::Attempted {
            outcome:
                Attempt::Report {
                    report,
                    close_error,
                },
            ..
        } => report_common::complete(report.summary(), SendMode::Single, close_error.as_ref()),
        _ => false,
    }
}

fn is_cancelled(step: &Step) -> bool {
    match step {
        Step::Skipped(SkipReason::Cancelled) => true,
        Step::Attempted {
            outcome: Attempt::Report { report, .. },
            ..
        } => report.summary().stop_reason() == StopReason::Cancelled,
        _ => false,
    }
}

fn status(result: &Assessment) -> &'static str {
    match decision::test_claim(result) {
        Claim::ExpectedObserved => "expected_claim_observed",
        Claim::Inconclusive => "inconclusive",
    }
}

fn step_view(step: &Step, disclosure: Disclosure) -> Result<StepView, Error> {
    match step {
        Step::Skipped(reason) => Ok(StepView::Skipped {
            reason: skip_name(*reason),
        }),
        Step::Attempted {
            limits,
            outcome:
                Attempt::Failure {
                    stage,
                    error,
                    close_error,
                },
        } => Ok(StepView::Failed {
            limits: LimitsView::new(*limits),
            stage: failure_name(*stage),
            code: io_error_code(error),
            cleanup: cleanup_name(*stage, close_error.as_ref()),
            cleanup_error: close_error.as_ref().map(io_error_code),
        }),
        Step::Attempted {
            limits,
            outcome:
                Attempt::Report {
                    report,
                    close_error,
                },
        } => {
            let mut replies = Vec::new();
            replies
                .try_reserve_exact(report.observations().len())
                .map_err(|_| Error::Allocation)?;
            for item in report.observations() {
                let frame = item.frame();
                replies.push(ReplyView {
                    mac: format_mac(item.mac().bytes()),
                    matches_expected: report.expected_match(item.mac()),
                    frame: FrameView::for_disclosure(frame, disclosure)?,
                });
            }
            Ok(StepView::Collected {
                limits: LimitsView::new(*limits),
                quality: QualityView::codes_only(report.summary(), close_error.as_ref()),
                expected_claim_observed: decision::expected_claim(step),
                conflicting_identities: report.has_conflicting_identities(),
                replies,
            })
        }
    }
}

fn write_json(
    context: &Context<'_>,
    result: &Assessment,
    outcome: ActiveOutcome,
    output: &mut impl Write,
) -> Result<(), Error> {
    let report = Report {
        operation: "vlan_assessment",
        status: status(result),
        completion: report_common::completion_name(outcome),
        scope: ScopeView {
            control: EndpointView::new(&context.control),
            test: EndpointView::new(&context.test),
            target: context.target,
            expected_mac: format_mac(context.expected.bytes()),
            canary_placement: "operator_asserted",
        },
        per_interface_budget: LimitsView::new(context.budget),
        control_claims_observed: decision::controls_observed(result),
        authenticated: false,
        control_before: step_view(&result.before, context.disclosure)?,
        test: step_view(&result.test, context.disclosure)?,
        control_after: step_view(&result.after, context.disclosure)?,
        limitation: LIMITATION,
    };
    write_safe_json(&mut *output, &report, CompactFormatter).map_err(Error::Json)?;
    writeln!(output).map_err(Error::Output)
}

fn write_text(
    context: &Context<'_>,
    result: &Assessment,
    outcome: ActiveOutcome,
    output: &mut impl Write,
) -> Result<(), Error> {
    writeln!(
        output,
        "VLAN canary assessment: {} expected {}",
        context.target,
        format_mac(context.expected.bytes())
    )
    .map_err(Error::Output)?;
    writeln!(
        output,
        "Deadline: {} ms; per-interface receive budget: {} packets, {} bytes",
        context.budget.timeout().as_millis(),
        context.budget.max_received_packets(),
        context.budget.max_received_bytes()
    )
    .map_err(Error::Output)?;
    for (label, endpoint) in [("Control", &context.control), ("Test", &context.test)] {
        writeln!(
            output,
            "{label} interface: {}  source: {} ({})",
            endpoint.name.escape_debug(),
            endpoint.source_ip,
            format_mac(endpoint.source_mac.bytes())
        )
        .map_err(Error::Output)?;
        InterfaceView::new(endpoint.name, endpoint.identity, endpoint.vlan).write_text(output)?;
        if endpoint.vlan.is_none() {
            writeln!(output, "Segment: unknown").map_err(Error::Output)?;
        }
    }
    writeln!(
        output,
        "Status: {}  completion: {}  control claims observed: {}",
        status(result),
        report_common::completion_name(outcome),
        decision::controls_observed(result)
    )
    .map_err(Error::Output)?;
    for (label, step) in [
        ("Control before", &result.before),
        ("Test", &result.test),
        ("Control after", &result.after),
    ] {
        write_step(label, step, context.disclosure, output)?;
    }
    writeln!(output, "{LIMITATION}").map_err(Error::Output)
}

fn write_step(
    label: &str,
    step: &Step,
    disclosure: Disclosure,
    output: &mut impl Write,
) -> Result<(), Error> {
    writeln!(output, "{label}:").map_err(Error::Output)?;
    write_safe_json(
        &mut *output,
        &step_view(step, disclosure)?,
        PrettyFormatter::new(),
    )
    .map_err(Error::Json)?;
    writeln!(output).map_err(Error::Output)
}

#[derive(Serialize)]
struct PreflightScope<'a> {
    control_interface: &'a str,
    test_interface: &'a str,
    target: Ipv4Addr,
    expected_mac: String,
}

#[derive(Serialize)]
struct PreflightTransmit {
    attempted: bool,
    accepted_packets: u32,
    delivery_confirmed: bool,
}

#[derive(Serialize)]
struct PreflightReport<'a> {
    operation: &'static str,
    status: &'static str,
    completion: &'static str,
    stop_reason: &'static str,
    scope: PreflightScope<'a>,
    tx: PreflightTransmit,
    cleanup: &'static str,
}

pub(super) fn write_stopped(
    control: &str,
    test: &str,
    target: Ipv4Addr,
    expected: MacAddress,
    reason: SkipReason,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    let outcome = if reason == SkipReason::Cancelled {
        ActiveOutcome::Cancelled
    } else {
        ActiveOutcome::Incomplete
    };
    match format {
        OutputFormat::Text => writeln!(
            output,
            "VLAN canary assessment stopped before transmission: {} (control {}, test {})",
            skip_name(reason),
            control.escape_debug(),
            test.escape_debug()
        )
        .map_err(Error::Output)?,
        OutputFormat::Json => {
            let report = PreflightReport {
                operation: "vlan_assessment",
                status: "inconclusive",
                completion: report_common::completion_name(outcome),
                stop_reason: skip_name(reason),
                scope: PreflightScope {
                    control_interface: control,
                    test_interface: test,
                    target,
                    expected_mac: format_mac(expected.bytes()),
                },
                tx: PreflightTransmit {
                    attempted: false,
                    accepted_packets: 0,
                    delivery_confirmed: false,
                },
                cleanup: "not_started",
            };
            write_safe_json(&mut *output, &report, CompactFormatter).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)?;
        }
    }
    Ok(outcome)
}

const fn skip_name(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::Cancelled => "cancelled",
        SkipReason::Deadline => "deadline",
        SkipReason::Budget => "budget",
        SkipReason::PreviousFailure => "previous_failure",
    }
}

const fn failure_name(stage: FailureStage) -> &'static str {
    match stage {
        FailureStage::Prepare => "prepare",
        FailureStage::Open => "helper_open",
        FailureStage::Run => "run",
    }
}

const fn cleanup_name(stage: FailureStage, error: Option<&io::Error>) -> &'static str {
    match stage {
        FailureStage::Prepare => "not_started",
        FailureStage::Run if error.is_none() => "confirmed",
        FailureStage::Open | FailureStage::Run => "unconfirmed",
    }
}
