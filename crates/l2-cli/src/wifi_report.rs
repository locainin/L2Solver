//! Wireless assessment presentation and collection summary

#[cfg(feature = "live")]
use crate::completion::LiveCaptureQuality;
use crate::{arguments::ReportOptions, output as output_limits, presentation::Presentation};
use serde::Serialize;
use std::{error::Error, io::Write};
use wifi_discovery::{ObservationStatus, Survey};

#[cfg(test)]
#[path = "../tests/wifi_report/live_quality.rs"]
mod live_quality_tests;

#[derive(Default, Serialize)]
pub struct Summary {
    pub frames: u64,
    pub malformed: u64,
    pub noncanonical: u64,
    pub unsupported: u64,
    pub unsupported_link: u64,
    pub resource_limited: u64,
    pub truncated: u64,
    pub incomplete: u64,
    pub protected: u64,
    #[serde(serialize_with = "l2_workbench::capture_collection::serialize")]
    pub source_collection: l2_pcap::CollectionSummary,
    // Offline reports omit this field because no live backend can populate it
    #[cfg(feature = "live")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<LiveCaptureQuality>,
}

pub const fn collection_complete(
    summary: &Summary,
    inventory: &Survey,
    passive_tested: bool,
) -> bool {
    #[cfg(feature = "live")]
    if let Some(quality) = summary.live
        && !quality.supports_complete_collection()
    {
        return false;
    }
    // Every lossy or unsupported path prevents an authoritative complete result
    summary.malformed == 0
        && summary.noncanonical == 0
        && summary.unsupported == 0
        && summary.unsupported_link == 0
        && summary.resource_limited == 0
        && summary.truncated == 0
        && summary.incomplete == 0
        && !inventory.inventory_incomplete()
        && passive_tested
        && !l2_workbench::capture_collection::reports_incomplete_collection(
            summary.source_collection,
        )
}

pub fn render_json(
    output: &mut impl Write,
    summary: &Summary,
    inventory: &Survey,
    assessment: &wifi_audit::Assessment,
) -> Result<(), Box<dyn Error>> {
    #[derive(Serialize)]
    struct WirelessReport<'a> {
        summary: &'a Summary,
        access_points: Vec<&'a wifi_discovery::AccessPoint>,
        stations: Vec<&'a wifi_discovery::Station>,
        diagnostics: &'a [wifi_discovery::Diagnostic],
        assessment: &'a wifi_audit::Assessment,
    }

    let report = WirelessReport {
        summary,
        access_points: inventory.access_points().collect(),
        stations: inventory.stations().collect(),
        diagnostics: inventory.diagnostics(),
        assessment,
    };
    // JSON uses the same all-or-error byte ceiling as the wired report
    output_limits::write_json(&report, output, output_limits::MAX_SURVEY_JSON_BYTES)
}

pub fn count_status(summary: &mut Summary, status: ObservationStatus) -> Result<(), &'static str> {
    // Successfully observed frames need no quality counter
    let counter = match status {
        ObservationStatus::Malformed => &mut summary.malformed,
        ObservationStatus::NonCanonical => &mut summary.noncanonical,
        ObservationStatus::Unsupported => &mut summary.unsupported,
        ObservationStatus::ResourceLimited => &mut summary.resource_limited,
        ObservationStatus::Incomplete => &mut summary.incomplete,
        ObservationStatus::Protected => &mut summary.protected,
        ObservationStatus::Observed => return Ok(()),
    };
    *counter = counter
        .checked_add(1)
        .ok_or("wireless status count overflow")?;
    Ok(())
}

pub fn render(
    output: &mut impl Write,
    summary: &Summary,
    inventory: &Survey,
    assessment: &wifi_audit::Assessment,
    options: &ReportOptions,
    source: &str,
    complete: bool,
) -> Result<(), Box<dyn Error>> {
    let presentation = Presentation::new(options.color);
    // Findings and attack surface stay ahead of diagnostic inventory
    write_summary(
        output,
        summary,
        inventory,
        assessment,
        source,
        complete,
        presentation,
    )?;
    write_findings(output, assessment, options, presentation)?;
    write_attack_surface(output, inventory, assessment, options, presentation)?;
    write_not_tested(output, assessment, presentation)?;

    if options.verbosity > 0 {
        write_inventory(output, summary, inventory, assessment)?;
    }
    if options.verbosity > 1 {
        write_quality(output, summary, inventory)?;
    }
    if options.evidence {
        write_evidence(output, assessment, presentation)?;
    } else {
        writeln!(
            output,
            "\nUse -v for inventory; add --evidence for packet references"
        )?;
    }
    Ok(())
}

fn write_summary(
    output: &mut impl Write,
    summary: &Summary,
    inventory: &Survey,
    assessment: &wifi_audit::Assessment,
    source: &str,
    complete: bool,
    presentation: Presentation,
) -> Result<(), Box<dyn Error>> {
    presentation.title("L2Solver wireless assessment", output)?;
    writeln!(output, "Source        {}", source.escape_debug())?;
    writeln!(
        output,
        "Capture       {} ({} frames)",
        if complete { "COMPLETE" } else { "INCOMPLETE" },
        summary.frames
    )?;
    #[cfg(feature = "live")]
    if let Some(live) = summary.live {
        writeln!(
            output,
            "  live_stop={:?} live_goal={:?} received={} capture_dropped={} interface_dropped={} loss_counters_authoritative={}",
            live.stop_reason(),
            live.goal(),
            live.received(),
            live.capture_dropped(),
            live.interface_dropped(),
            live.loss_counters_authoritative()
        )?;
    }
    writeln!(output, "Access points {}", inventory.access_points().len())?;
    writeln!(output, "Stations      {}", inventory.stations().len())?;
    let applicable = assessment
        .coverage_entries()
        .iter()
        .filter(|entry| entry.status() != wifi_audit::CoverageStatus::NotApplicable)
        .count();
    let tested = assessment
        .coverage_entries()
        .iter()
        .filter(|entry| entry.status() == wifi_audit::CoverageStatus::Tested)
        .count();
    writeln!(
        output,
        "Coverage      {tested} / {applicable} applicable checks"
    )?;
    writeln!(
        output,
        "Findings      {} policy, {} exposures",
        assessment.findings().len(),
        assessment.exposures().len()
    )?;
    Ok(())
}

fn write_findings(
    output: &mut impl Write,
    assessment: &wifi_audit::Assessment,
    options: &ReportOptions,
    presentation: Presentation,
) -> Result<(), Box<dyn Error>> {
    presentation.section("Findings", output)?;
    if assessment.findings().is_empty() {
        writeln!(output, "  No confirmed policy failures")?;
    }
    for finding in assessment.findings() {
        writeln!(
            output,
            "{:8} {}  {}",
            format!("{:?}", finding.severity()).to_uppercase(),
            finding.id(),
            finding.title().escape_debug()
        )?;
        writeln!(output, "         Verdict    {:?}", finding.verdict())?;
        writeln!(
            output,
            "         Expected  {}",
            finding.expected().escape_debug()
        )?;
        writeln!(
            output,
            "         Observed  {}",
            finding.observed().escape_debug()
        )?;
        writeln!(
            output,
            "         BSSID     {}",
            display_mac(finding.bssid().octets())
        )?;
        if options.evidence {
            writeln!(
                output,
                "         Evidence  packets {:?}",
                finding.evidence_sequences()
            )?;
        }
    }
    Ok(())
}

fn write_attack_surface(
    output: &mut impl Write,
    inventory: &Survey,
    assessment: &wifi_audit::Assessment,
    options: &ReportOptions,
    presentation: Presentation,
) -> Result<(), Box<dyn Error>> {
    presentation.section("Attack surface", output)?;
    for access_point in inventory.access_points() {
        writeln!(
            output,
            "AP {}  SSID {}  channel {:?}  security {:?}",
            display_mac(access_point.bssid().octets()),
            display_bytes(access_point.ssid().unwrap_or_default()),
            access_point.channel(),
            access_point.security()
        )?;
    }
    if inventory.access_points().len() == 0 {
        writeln!(output, "  No access points identified")?;
    }
    for exposure in assessment.exposures() {
        writeln!(
            output,
            "INFO     {}  {}",
            exposure.id(),
            exposure.title().escape_debug()
        )?;
        if options.evidence {
            writeln!(
                output,
                "         Evidence  packets {:?}",
                exposure.evidence_sequences()
            )?;
        }
    }
    Ok(())
}

fn write_not_tested(
    output: &mut impl Write,
    assessment: &wifi_audit::Assessment,
    presentation: Presentation,
) -> Result<(), Box<dyn Error>> {
    presentation.section("Not tested", output)?;
    let mut unavailable = 0_usize;
    for coverage in assessment.coverage_entries().iter().filter(|entry| {
        matches!(
            entry.status(),
            wifi_audit::CoverageStatus::NotTested | wifi_audit::CoverageStatus::Incomplete
        )
    }) {
        unavailable = unavailable.saturating_add(1);
        writeln!(
            output,
            "  {}  {:?} — {}",
            coverage.id(),
            coverage.status(),
            coverage.reason().escape_debug()
        )?;
    }
    if unavailable == 0 {
        writeln!(output, "  None among applicable checks")?;
    }
    Ok(())
}

fn write_inventory(
    output: &mut impl Write,
    summary: &Summary,
    inventory: &Survey,
    assessment: &wifi_audit::Assessment,
) -> Result<(), Box<dyn Error>> {
    writeln!(output, "\nInventory")?;
    writeln!(
        output,
        "  frames={} access_points={} stations={}",
        summary.frames,
        inventory.access_points().len(),
        inventory.stations().len()
    )?;
    for access_point in inventory.access_points() {
        writeln!(
            output,
            "ap={} ssid={} ssid_conflict={} ssid_inconsistent={} channel={:?} channel_changed={} security={:?} security_inconsistent={} pmf_capable={} pmf_required={} wps={}",
            display_mac(access_point.bssid().octets()),
            display_bytes(access_point.ssid().unwrap_or_default()),
            access_point
                .ssid_conflict()
                .map_or_else(|| "-".into(), display_bytes),
            access_point.ssid_inconsistent(),
            access_point.channel(),
            access_point.channel_changed(),
            access_point.security(),
            access_point.security_inconsistent(),
            access_point.pmf_capable(),
            access_point.pmf_required(),
            access_point.wps()
        )?;
    }
    for station in inventory.stations() {
        writeln!(
            output,
            "station={} associated_bssid={} association_changed={} frames={}",
            display_mac(station.address().octets()),
            station.associated_bssid().map_or_else(
                || String::from("-"),
                |address| display_mac(address.octets()),
            ),
            station.association_changed(),
            station.frames()
        )?;
    }
    writeln!(output, "\nCoverage")?;
    for coverage in assessment.coverage_entries() {
        writeln!(
            output,
            "coverage={} status={:?} reason={}",
            coverage.id(),
            coverage.status(),
            coverage.reason().escape_debug()
        )?;
    }
    Ok(())
}

fn write_quality(
    output: &mut impl Write,
    summary: &Summary,
    inventory: &Survey,
) -> Result<(), Box<dyn Error>> {
    writeln!(output, "\nCapture quality")?;
    crate::source_collection::text(summary.source_collection, output)?;
    writeln!(
        output,
        "  malformed={} noncanonical={} unsupported={} unsupported_link={} resource_limited={} truncated={} incomplete={} protected={}",
        summary.malformed,
        summary.noncanonical,
        summary.unsupported,
        summary.unsupported_link,
        summary.resource_limited,
        summary.truncated,
        summary.incomplete,
        summary.protected
    )?;
    for diagnostic in inventory.diagnostics() {
        writeln!(
            output,
            "diagnostic={} kind={:?} message={}",
            diagnostic.sequence(),
            diagnostic.kind(),
            diagnostic.message().escape_debug()
        )?;
    }
    Ok(())
}

fn write_evidence(
    output: &mut impl Write,
    assessment: &wifi_audit::Assessment,
    presentation: Presentation,
) -> Result<(), Box<dyn Error>> {
    presentation.section("Evidence index", output)?;
    let mut rows = 0_usize;
    for finding in assessment.findings() {
        rows = rows.saturating_add(1);
        writeln!(
            output,
            "  {} BSSID={} packets={:?}",
            finding.id(),
            display_mac(finding.bssid().octets()),
            finding.evidence_sequences()
        )?;
    }
    for exposure in assessment.exposures() {
        rows = rows.saturating_add(1);
        writeln!(
            output,
            "  {} BSSID={} packets={:?}",
            exposure.id(),
            display_mac(exposure.bssid().octets()),
            exposure.evidence_sequences()
        )?;
    }
    if rows == 0 {
        writeln!(output, "  No finding or exposure references")?;
    }
    writeln!(
        output,
        "  Keep the original capture as authoritative packet evidence"
    )?;
    Ok(())
}

fn display_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();
    // ASCII escaping blocks terminal control sequences from wireless identifiers
    for byte in bytes {
        for escaped in std::ascii::escape_default(*byte) {
            output.push(char::from(escaped));
        }
    }
    output
}

fn display_mac(octets: [u8; 6]) -> String {
    let [first, second, third, fourth, fifth, sixth] = octets;
    format!("{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}")
}
