//! Survey orchestration only consumes receive-side events

#[cfg(feature = "live")]
use crate::survey_stats;
use crate::{
    arguments::{ColorChoice, OutputFormat, SurveyInput, SurveyOptions},
    bounded_json, html_report, input,
    outcome::AssessmentOutcome,
    output as output_limits, survey_report,
};
use l2_audit::{AssessmentProfile, Policy, Report, SourceLabelMap, Survey, Verdict};
use l2_io::{LinkEvent, LinkIo, ReplayLink};
use std::{error::Error, io::Write, path::Path};

pub struct PreparedAssessment {
    pub report: Report,
    pub source_label: String,
    pub interface: Option<String>,
    pub outcome: AssessmentOutcome,
}

pub fn from_file(path: &Path, policy: &Policy) -> Result<Report, Box<dyn Error>> {
    from_file_with_profile(path, policy, AssessmentProfile::Opportunistic)
}

fn from_file_with_profile(
    path: &Path,
    policy: &Policy,
    profile: AssessmentProfile,
) -> Result<Report, Box<dyn Error>> {
    // Replay uses the same receive event model as a live source
    let mut link = ReplayLink::new(input::capture(path)?)?;
    collect(&mut link)?
        .finish_with_profile(policy, profile)
        .map_err(Into::into)
}

fn from_file_with_profile_and_source_labels(
    path: &Path,
    policy: &Policy,
    profile: AssessmentProfile,
    labels: &SourceLabelMap,
) -> Result<Report, Box<dyn Error>> {
    // Stable labels replace capture ordinals before policy evaluation
    let mut link = ReplayLink::new(input::capture(path)?)?;
    collect(&mut link)?
        .finish_with_profile_and_source_labels(policy, profile, labels)
        .map_err(Into::into)
}

fn collect<L: LinkIo>(link: &mut L) -> Result<Survey, Box<dyn Error>> {
    let mut survey = Survey::new();
    loop {
        match link.next_event()? {
            Some(LinkEvent::Frame(packet)) => survey.observe(&packet)?,
            Some(LinkEvent::CaptureGap(gap)) => survey.record_quality(gap.dropped, false)?,
            Some(LinkEvent::InterfaceDown(_)) => survey.record_quality(0, true)?,
            Some(LinkEvent::InterfaceUp(_)) => {}
            Some(LinkEvent::Shutdown) => {
                survey.record_quality(0, true)?;
                return Ok(survey);
            }
            None => {
                let quality = link.collection_summary();
                let drops = quality
                    .capture_dropped
                    .checked_add(quality.interface_dropped)
                    .and_then(|total| total.checked_add(quality.packet_block_packets_dropped))
                    .ok_or("source loss counters exceed survey accounting range")?;
                survey.record_quality(
                    drops,
                    l2_workbench::capture_collection::reports_incomplete_collection(quality),
                )?;
                return Ok(survey);
            }
        }
    }
}

pub fn assess(options: &SurveyOptions) -> Result<PreparedAssessment, Box<dyn Error>> {
    let source = options.display_source();
    let labels = options.source_labels()?;
    // Policy input is bounded before deserialization and validated before capture
    let policy: Policy = match &options.policy {
        Some(path) => bounded_json::read(input::regular(path)?, 65_536)?,
        None => Policy::default(),
    };
    policy.validate()?;
    let report = match &options.input {
        SurveyInput::File(path) => {
            from_file_with_profile_and_source_labels(path, &policy, options.profile, &labels)?
        }
        SurveyInput::Live { interface, limit } => {
            live(interface, *limit, &policy, options.profile, &labels)?
        }
    };

    let outcome = AssessmentOutcome {
        complete: report.collection_complete(),
        failed_findings: report
            .findings
            .iter()
            .any(|finding| finding.verdict == Verdict::Fail),
    };
    Ok(PreparedAssessment {
        report,
        source_label: source.label,
        interface: source.interface,
        outcome,
    })
}

pub fn render(
    options: &SurveyOptions,
    assessment: &PreparedAssessment,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    // Every output format is derived from one completed report
    match options.format {
        OutputFormat::Text => {
            survey_report::text_with_interface(
                &assessment.report,
                &options.report,
                &assessment.source_label,
                assessment.interface.as_deref(),
                output,
            )?;
        }
        OutputFormat::Json => {
            output_limits::write_json(
                &assessment.report,
                output,
                output_limits::MAX_SURVEY_JSON_BYTES,
            )?;
        }
        OutputFormat::Html => {
            let mut text = Vec::new();
            let mut report_options = options.report.clone();
            report_options.color = ColorChoice::Never;
            survey_report::text_with_interface(
                &assessment.report,
                &report_options,
                &assessment.source_label,
                assessment.interface.as_deref(),
                &mut text,
            )?;
            html_report::write(output, &String::from_utf8(text)?)?;
        }
    }
    Ok(())
}

fn live(
    interface: &str,
    limit: crate::arguments::LiveLimit,
    policy: &Policy,
    profile: AssessmentProfile,
    labels: &SourceLabelMap,
) -> Result<Report, Box<dyn Error>> {
    #[cfg(feature = "live")]
    {
        let packets = limit.packet_ceiling();
        let duration = limit.duration_ceiling();
        // Live capture stays bounded and receive-only in the backend
        let mut link = l2_live::LiveLink::open_with_limits(interface, packets, duration)?;
        writeln!(
            std::io::stderr().lock(),
            "Surveying {} (receive-only, inbound filter requested, non-promiscuous; at most {packets} frames / {} seconds)",
            interface.escape_debug(),
            duration.as_secs()
        )?;
        let mut survey = collect(&mut link)?;
        let stats = link.statistics()?;
        let quality = crate::completion::LiveCaptureQuality::from_libpcap(
            link.stop_reason(),
            limit.duration_is_goal(),
            stats,
        );
        // Deadline completion and packet-limit interruption have different meanings
        let incomplete = !quality.supports_complete_collection();
        survey.record_quality(
            survey_stats::total_drops(stats.capture_dropped(), stats.interface_dropped()),
            incomplete,
        )?;
        survey
            .finish_with_profile_and_source_labels(policy, profile, labels)
            .map_err(Into::into)
    }

    #[cfg(not(feature = "live"))]
    {
        let _ = (interface, limit, policy, profile, labels);
        Err("live survey is optional; build with cargo build -p l2-cli --features live".into())
    }
}
