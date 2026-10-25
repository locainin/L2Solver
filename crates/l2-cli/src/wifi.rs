//! Passive wireless survey output selected by checked capture link types

use crate::{
    arguments::{ColorChoice, OutputFormat, ReportOptions, SurveyInput, WifiOptions},
    bounded_json, html_report, input,
    outcome::AssessmentOutcome,
    wifi_report::{Summary, collection_complete, count_status, render, render_json},
};
use l2_capture::{CapturedFrame, LinkType};
use l2_io::{LinkIo, ReplayLink};
use std::{error::Error, io::Write, path::Path};
use wifi_discovery::{ObservationContext, Survey, SurveyLimits, WirelessInput};

const MAX_POLICY_BYTES: u64 = 65_536;

pub fn run(
    options: &WifiOptions,
    output: &mut impl Write,
) -> Result<AssessmentOutcome, Box<dyn Error>> {
    // File and live inputs share one assessment path after capture selection
    let policy = read_policy(options.policy.as_deref())?;
    let source = source_label(&options.input);
    match &options.input {
        SurveyInput::File(path) => {
            let mut link = ReplayLink::new(input::capture(path)?)?;
            survey(
                &mut link,
                &policy,
                options.format,
                &options.report,
                &source,
                output,
            )
        }
        SurveyInput::Live { interface, limit } => live(
            interface,
            *limit,
            &policy,
            options.format,
            &options.report,
            output,
        ),
    }
}

fn source_label(input: &SurveyInput) -> String {
    match input {
        SurveyInput::File(path) => path.to_string_lossy().into_owned(),
        SurveyInput::Live { interface, .. } => interface.clone(),
    }
}

pub fn read_policy(path: Option<&Path>) -> Result<wifi_audit::WirelessPolicy, Box<dyn Error>> {
    match path {
        Some(path) => bounded_json::read(input::regular(path)?, MAX_POLICY_BYTES),
        None => Ok(wifi_audit::WirelessPolicy::default()),
    }
}

pub fn survey<L: LinkIo>(
    link: &mut L,
    policy: &wifi_audit::WirelessPolicy,
    format: OutputFormat,
    report_options: &ReportOptions,
    source: &str,
    output: &mut impl Write,
) -> Result<AssessmentOutcome, Box<dyn Error>> {
    let (inventory, summary) = collect(link)?;
    finish(
        &inventory,
        &summary,
        &FinishOptions {
            policy,
            format,
            report_options,
            source,
        },
        output,
    )
}

fn collect<L: LinkIo>(link: &mut L) -> Result<(Survey, Summary), Box<dyn Error>> {
    let mut inventory = Survey::new(SurveyLimits::default())?;
    let mut summary = Summary::default();
    // Capture metadata selects the decoder so interface names never imply a link type
    while let Some(frame) = link.recv()? {
        summary.frames = summary
            .frames
            .checked_add(1)
            .ok_or("wireless frame sequence overflow")?;
        summary.truncated = summary
            .truncated
            .checked_add(u64::from(frame.is_truncated()))
            .ok_or("wireless truncation count overflow")?;
        let input = match wireless_input(&frame) {
            SelectedInput::Supported(input) => input,
            SelectedInput::Unsupported => {
                summary.unsupported_link = summary
                    .unsupported_link
                    .checked_add(1)
                    .ok_or("unsupported link count overflow")?;
                continue;
            }
        };
        let context = ObservationContext::without_time(summary.frames)
            .with_capture_truncated(frame.is_truncated());
        let status = inventory.observe(input, context);
        count_status(&mut summary, status)?;
    }
    summary.source_collection = link.collection_summary();
    Ok((inventory, summary))
}

struct FinishOptions<'a> {
    policy: &'a wifi_audit::WirelessPolicy,
    format: OutputFormat,
    report_options: &'a ReportOptions,
    source: &'a str,
}

fn finish(
    inventory: &Survey,
    summary: &Summary,
    options: &FinishOptions<'_>,
    output: &mut impl Write,
) -> Result<AssessmentOutcome, Box<dyn Error>> {
    // Policy evaluation begins only after passive collection has reached a terminal state
    let assessment = wifi_audit::assess(inventory, options.policy, &[])?;
    let passive_tested = assessment
        .coverage("WIFI-PASSIVE-SURVEY")
        .is_some_and(|coverage| coverage.status() == wifi_audit::CoverageStatus::Tested);
    let complete = collection_complete(summary, inventory, passive_tested);
    let outcome = AssessmentOutcome {
        complete,
        failed_findings: assessment
            .findings()
            .iter()
            .any(|finding| finding.verdict() == wifi_audit::Verdict::Fail),
    };
    // Semantic status is fixed before a downstream reader can close the output pipe
    (|| -> Result<(), Box<dyn Error>> {
        match options.format {
            OutputFormat::Text => render(
                output,
                summary,
                inventory,
                &assessment,
                options.report_options,
                options.source,
                complete,
            ),
            OutputFormat::Json => render_json(output, summary, inventory, &assessment),
            OutputFormat::Html => {
                // Terminal color sequences must never enter the HTML source
                let mut text = Vec::new();
                let mut html_options = options.report_options.clone();
                html_options.color = ColorChoice::Never;
                render(
                    &mut text,
                    summary,
                    inventory,
                    &assessment,
                    &html_options,
                    options.source,
                    complete,
                )?;
                html_report::write(output, &String::from_utf8(text)?)?;
                Ok(())
            }
        }
    })()?;
    Ok(outcome)
}

#[cfg(feature = "live")]
fn live(
    interface: &str,
    limit: crate::arguments::LiveLimit,
    policy: &wifi_audit::WirelessPolicy,
    format: OutputFormat,
    report_options: &ReportOptions,
    output: &mut impl Write,
) -> Result<AssessmentOutcome, Box<dyn Error>> {
    let packets = limit.packet_ceiling();
    let duration = limit.duration_ceiling();
    let mut link = l2_live::LiveLink::open_with_limits(interface, packets, duration)?;
    // An Ethernet-like station interface is not raw 802.11 evidence
    if !link.link_type().is_wireless() {
        return Err(format!(
            "wireless assessment requires IEEE 802.11 or radiotap; {} provides {}",
            interface.escape_debug(),
            link.link_type().name()
        )
        .into());
    }
    writeln!(
        std::io::stderr().lock(),
        "Assessing raw wireless frames on {} (receive-only; at most {packets} frames / {} seconds)",
        interface.escape_debug(),
        duration.as_secs()
    )?;
    let (inventory, mut summary) = collect(&mut link)?;
    let reason = link.stop_reason();
    let statistics = link.statistics()?;
    summary.live = Some(crate::completion::LiveCaptureQuality::from_libpcap(
        reason,
        limit.duration_is_goal(),
        statistics,
    ));
    finish(
        &inventory,
        &summary,
        &FinishOptions {
            policy,
            format,
            report_options,
            source: interface,
        },
        output,
    )
}

#[cfg(not(feature = "live"))]
fn live(
    _interface: &str,
    _limit: crate::arguments::LiveLimit,
    _policy: &wifi_audit::WirelessPolicy,
    _format: OutputFormat,
    _report_options: &ReportOptions,
    _output: &mut impl Write,
) -> Result<AssessmentOutcome, Box<dyn Error>> {
    Err(
        "live wireless assessment is optional; build with cargo build -p l2-cli --features live"
            .into(),
    )
}

enum SelectedInput<'a> {
    Supported(WirelessInput<'a>),
    Unsupported,
}

fn wireless_input(frame: &CapturedFrame) -> SelectedInput<'_> {
    // PCAP and PCAPNG link metadata is authoritative for byte interpretation
    match frame.metadata().link_type() {
        LinkType::Ieee80211 => SelectedInput::Supported(WirelessInput::Ieee80211(frame.bytes())),
        LinkType::Ieee80211Radiotap => {
            SelectedInput::Supported(WirelessInput::Radiotap(frame.bytes()))
        }
        LinkType::Ethernet | LinkType::Unknown(_) => SelectedInput::Unsupported,
    }
}
