//! Human survey output escapes all source-provided text and byte strings

use crate::{forensic_report, presentation::Presentation, render};
use l2_audit::{CoverageStatus, Report, Severity, Vid};
use l2_cli::arguments::ReportOptions;
use std::{
    collections::BTreeSet,
    io::{self, Write},
};

pub fn text_with_interface(
    report: &Report,
    options: &ReportOptions,
    source_label: &str,
    interface: Option<&str>,
    output: &mut impl Write,
) -> io::Result<()> {
    let presentation = Presentation::new(options.color);
    // Keep the first screen focused on decisions an operator can act on
    write_overview(report, source_label, interface, presentation, output)?;
    write_findings_compact(report, options.evidence, presentation, output)?;
    write_attack_surface(report, options.evidence, presentation, output)?;
    forensic_report::write(report, options, output)?;
    write_not_tested(report, presentation, output)?;

    // Detailed inventory is opt-in so large captures remain readable
    if options.verbosity > 0 {
        write_inventory(report, output)?;
        write_port_roles(report, output)?;
        write_coverage_summary(report, output)?;
        write_coverage(report, output)?;
        write_recommendations(report, output)?;
    }
    if options.verbosity > 1 {
        write_quality(report, output)?;
        write_network_model(report, output)?;
    }
    // Packet references remain separate from the concise finding summary
    if options.evidence {
        write_evidence(report, presentation, output)?;
    } else {
        writeln!(
            output,
            "\nUse -v for inventory and packet references; add --evidence for the evidence index"
        )?;
    }
    Ok(())
}

fn write_overview(
    report: &Report,
    source_label: &str,
    interface: Option<&str>,
    presentation: Presentation,
    output: &mut impl Write,
) -> io::Result<()> {
    presentation.title("L2Solver assessment", output)?;
    let role = match report.port_roles.as_slice() {
        [role] => role.role.to_string().to_lowercase(),
        [] => String::from("unknown (no interface observations)"),
        roles => format!("{} capture sources", roles.len()),
    };
    // Not-applicable checks do not dilute the displayed coverage ratio
    let applicable = report
        .coverage
        .iter()
        .filter(|entry| entry.status != CoverageStatus::NotApplicable)
        .count();
    let tested = report
        .coverage
        .iter()
        .filter(|entry| entry.status == CoverageStatus::Tested)
        .count();
    let (high, medium, low, info) = severity_counts(report);
    writeln!(output, "Source label {}", source_label.escape_debug())?;
    if let Some(interface) = interface {
        writeln!(output, "Interface    {}", interface.escape_debug())?;
    }
    writeln!(output, "Role         {role}")?;
    writeln!(
        output,
        "Capture      {} ({} frames)",
        if report.collection_complete() {
            "COMPLETE"
        } else {
            "INCOMPLETE"
        },
        report.quality.frames
    )?;
    writeln!(
        output,
        "Coverage     {tested} / {applicable} applicable checks"
    )?;
    writeln!(
        output,
        "Findings     {high} high, {medium} medium, {low} low, {info} info"
    )
}

fn severity_counts(report: &Report) -> (usize, usize, usize, usize) {
    // Passive exposures are informational until policy makes them findings
    let mut counts = (0, 0, 0, report.exposures.len());
    for finding in &report.findings {
        match finding.severity {
            Severity::High => counts.0 += 1,
            Severity::Medium => counts.1 += 1,
            Severity::Low => counts.2 += 1,
            Severity::Info => counts.3 += 1,
        }
    }
    counts
}

fn write_findings_compact(
    report: &Report,
    include_evidence: bool,
    presentation: Presentation,
    output: &mut impl Write,
) -> io::Result<()> {
    presentation.section("Findings", output)?;
    if report.findings.is_empty() {
        writeln!(output, "  No confirmed policy failures")?;
    }
    for finding in &report.findings {
        writeln!(
            output,
            "{:5} {}  {}",
            format!("{:?}", finding.severity).to_uppercase(),
            finding.check_id.escape_debug(),
            finding.title.escape_debug()
        )?;
        writeln!(
            output,
            "      Expected  {}",
            finding.expected.escape_debug()
        )?;
        writeln!(
            output,
            "      Observed  {}",
            finding.observed.escape_debug()
        )?;
        if include_evidence {
            writeln!(
                output,
                "      Evidence  packets {:?}",
                finding.evidence_packets
            )?;
        }
    }
    Ok(())
}

fn write_attack_surface(
    report: &Report,
    include_evidence: bool,
    presentation: Presentation,
    output: &mut impl Write,
) -> io::Result<()> {
    presentation.section("Attack surface", output)?;
    let mut vlans = BTreeSet::new();
    let mut protocols = BTreeSet::new();
    let mut neighbors = 0_usize;
    let mut has_stp = false;
    let mut untagged = false;
    // The attack surface combines every capture source without losing evidence scope
    for interface in &report.interfaces {
        untagged |= interface.untagged_packet.is_some();
        neighbors = neighbors.saturating_add(interface.neighbors.len());
        has_stp |= interface.stp_frames > 0;
        for vlan in &interface.vlans {
            for vid in vlan.vids() {
                match vid {
                    Vid::PriorityTagged => {
                        vlans.insert(String::from("priority-tagged"));
                    }
                    Vid::Vlan(id) => {
                        vlans.insert(id.get().to_string());
                    }
                    Vid::Reserved => {
                        vlans.insert(String::from("reserved-4095"));
                    }
                }
            }
        }
        protocols.extend(
            interface
                .protocols
                .iter()
                .map(|item| item.protocol.to_string()),
        );
    }
    if untagged {
        vlans.insert(String::from("untagged"));
    }
    writeln!(
        output,
        "VLANs        {}",
        if vlans.is_empty() {
            String::from("none observed")
        } else {
            vlans.into_iter().collect::<Vec<_>>().join(", ")
        }
    )?;
    writeln!(output, "Neighbors    {neighbors} LLDP")?;
    writeln!(
        output,
        "STP          {}",
        if has_stp { "observed" } else { "not observed" }
    )?;
    writeln!(
        output,
        "Protocols    {}",
        if protocols.is_empty() {
            String::from("none fingerprinted")
        } else {
            protocols.into_iter().collect::<Vec<_>>().join(", ")
        }
    )?;
    for exposure in &report.exposures {
        writeln!(
            output,
            "INFO  {}  {}",
            exposure.check_id.escape_debug(),
            exposure.title.escape_debug()
        )?;
        if include_evidence {
            writeln!(
                output,
                "      Evidence  packets {:?}",
                exposure.evidence_packets
            )?;
        }
    }
    Ok(())
}

fn write_not_tested(
    report: &Report,
    presentation: Presentation,
    output: &mut impl Write,
) -> io::Result<()> {
    presentation.section("Not tested", output)?;
    let mut count = 0_usize;
    // Bound the default list while verbose output retains every coverage row
    for entry in report
        .coverage
        .iter()
        .filter(|entry| entry.status == CoverageStatus::NotTested)
    {
        count = count.saturating_add(1);
        if count <= 8 {
            writeln!(
                output,
                "  {}  {}",
                entry.check_id.escape_debug(),
                entry.reason.escape_debug()
            )?;
        }
    }
    if count == 0 {
        writeln!(output, "  None among applicable checks")?;
    } else if count > 8 {
        writeln!(
            output,
            "  … and {} more; use -v for full coverage",
            count - 8
        )?;
    }
    Ok(())
}

fn write_network_model(report: &Report, output: &mut impl Write) -> io::Result<()> {
    // Correlation detail appears only at the diagnostic verbosity level
    writeln!(output, "\nNetwork correlations")?;
    writeln!(
        output,
        "  {} source-scoped nodes, {} infrastructure groups, {} address conflicts{}",
        report.network_model.nodes.len(),
        report.network_model.infrastructure.len(),
        report.network_model.address_conflicts.len(),
        if report.network_model.truncated {
            " (summary abbreviated)"
        } else {
            ""
        }
    )?;
    for conflict in &report.network_model.address_conflicts {
        writeln!(
            output,
            "  ARP conflict {}:{} address={} vlan_ids={:?} vlan_aux={:?} claimed_mac={:?} evidence={:?}",
            conflict.section,
            conflict.interface,
            conflict.address,
            conflict.vlan_tags,
            conflict.vlan_aux,
            conflict.claimed_macs,
            conflict.evidence_packets
        )?;
    }
    Ok(())
}

fn write_quality(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nCapture quality")?;
    writeln!(
        output,
        "  assessment_profile={}",
        report.assessment_profile.as_str()
    )?;
    writeln!(
        output,
        "  {}",
        if report.collection_complete() {
            "PASS — no parser, truncation, loss, or inventory-limit issue reported"
        } else {
            "INCOMPLETE — review the counters and reached resource limits"
        }
    )?;
    writeln!(
        output,
        "  frames={} malformed={} invalid={} truncated={} dropped={} incomplete={}",
        report.quality.frames,
        report.quality.malformed,
        report.quality.invalid,
        report.quality.truncated,
        report.quality.dropped,
        report.quality.incomplete
    )?;
    writeln!(
        output,
        "  unsupported_stp={} unsupported_fingerprints={} unsupported_link_types={}",
        report.quality.unsupported_stp,
        report.quality.unsupported_fingerprints,
        report.quality.unsupported_link_types
    )?;
    if !report.resource_limits.reached().is_empty() {
        writeln!(
            output,
            "  reached_limits={:?}",
            report.resource_limits.reached()
        )?;
    }
    Ok(())
}

fn write_inventory(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nInventory")?;
    for interface in &report.interfaces {
        write_interface(interface, output)?;
    }
    Ok(())
}

fn write_port_roles(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nPort classification")?;
    for inference in &report.port_roles {
        writeln!(
            output,
            "  {}:{}  {}",
            inference.section, inference.interface, inference.role
        )?;
        for reason in &inference.reasons {
            writeln!(output, "    {}", reason.escape_debug())?;
        }
        writeln!(
            output,
            "    Evidence packets: {:?}",
            inference.evidence_packets
        )?;
    }
    Ok(())
}

fn write_coverage_summary(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nAssessment coverage")?;
    for metric in &report.coverage_summary {
        let applicable = metric.tested + metric.not_tested;
        match metric.percent {
            Some(percent) => writeln!(
                output,
                "  {:<20} {percent:>3}% ({}/{} applicable checks; {} N/A)",
                metric.category, metric.tested, applicable, metric.not_applicable
            )?,
            None => writeln!(
                output,
                "  {:<20} N/A (0 applicable checks; {} N/A)",
                metric.category, metric.not_applicable
            )?,
        }
    }
    Ok(())
}

fn write_coverage(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nCoverage")?;
    for entry in report
        .coverage
        .iter()
        .filter(|entry| entry.status != CoverageStatus::NotApplicable)
    {
        let status = match entry.status {
            CoverageStatus::Tested => "TESTED",
            CoverageStatus::NotTested => "NOT TESTED",
            // The iterator removes these rows while JSON retains full detail
            CoverageStatus::NotApplicable => continue,
        };
        writeln!(
            output,
            "  {status:<14} {} — {}",
            entry.check_id.escape_debug(),
            entry.reason.escape_debug()
        )?;
    }
    let omitted = report
        .coverage
        .iter()
        .filter(|entry| entry.status == CoverageStatus::NotApplicable)
        .count();
    if omitted > 0 {
        writeln!(
            output,
            "  {omitted} not applicable checks omitted; JSON retains prerequisite details"
        )?;
    }
    Ok(())
}

fn write_recommendations(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "\nRecommended next tests")?;
    if report.plan.recommendations.is_empty() {
        writeln!(output, "  None for the observed protocol surface")?;
    }
    for (index, recommendation) in report.plan.recommendations.iter().enumerate() {
        writeln!(
            output,
            "  {}. {} — {} ({:?})",
            index + 1,
            recommendation.check_id.escape_debug(),
            recommendation.title.escape_debug(),
            recommendation.risk
        )?;
    }
    Ok(())
}

fn write_evidence(
    report: &Report,
    presentation: Presentation,
    output: &mut impl Write,
) -> io::Result<()> {
    presentation.section("Evidence index", output)?;
    // References point back to the authoritative capture instead of cloning all bytes
    for evidence in &report.evidence_refs {
        writeln!(
            output,
            "  packet={} source={}:{} captured={} original={} sha256={}",
            evidence.sequence,
            evidence.section,
            evidence.interface,
            evidence.captured_len,
            evidence.original_len,
            evidence.sha256
        )?;
    }
    writeln!(
        output,
        "  Indexed {} representative packets; embedded {} raw packets. Keep the original capture for complete evidence.",
        report.evidence_refs.len(),
        report.evidence.len()
    )
}

fn write_interface(
    interface: &l2_audit::InterfaceObservation,
    output: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        output,
        "\nInterface {}:{} — {} frames",
        interface.section, interface.index, interface.frames
    )?;
    write!(output, "  Tagged VLANs:")?;
    if interface.vlans.is_empty() {
        write!(output, " none observed")?;
    }
    for vlan in &interface.vlans {
        write!(
            output,
            " {:?} (TPID, TCI; VID meanings {:?}; packet {})",
            vlan.tags,
            vlan.vids().collect::<Vec<_>>(),
            vlan.packet
        )?;
    }
    writeln!(
        output,
        "\n  Untagged: {}",
        if interface.untagged_packet.is_some() {
            "observed"
        } else {
            "not observed"
        }
    )?;
    writeln!(
        output,
        "  Source MACs: {}",
        interface.macs.join(", ").escape_debug()
    )?;
    write_neighbors(interface, output)?;
    write_protocols(interface, output)?;
    write_identities(interface, output)?;
    write_stp_summary(interface, output)
}

fn write_neighbors(
    interface: &l2_audit::InterfaceObservation,
    output: &mut impl Write,
) -> io::Result<()> {
    for neighbor in &interface.neighbors {
        // LLDP fields are hostile byte strings and must pass through the byte renderer
        write!(output, "  LLDP name: ")?;
        render::bytes(output, &neighbor.system_name)?;
        write!(output, " | port: ")?;
        render::bytes(output, &neighbor.port_id)?;
        writeln!(output, " | packet {}", neighbor.packet)?;
    }
    Ok(())
}

fn write_protocols(
    interface: &l2_audit::InterfaceObservation,
    output: &mut impl Write,
) -> io::Result<()> {
    if interface.protocols.is_empty() {
        writeln!(output, "  Control-plane fingerprints: none observed")?;
    } else {
        writeln!(output, "  Control-plane fingerprints:")?;
        for protocol in &interface.protocols {
            writeln!(
                output,
                "    {:<12} {:<11} frames={} evidence={}",
                protocol.protocol, protocol.status, protocol.frames, protocol.packet
            )?;
        }
    }
    Ok(())
}

fn write_identities(
    interface: &l2_audit::InterfaceObservation,
    output: &mut impl Write,
) -> io::Result<()> {
    if !interface.identities.is_empty() {
        writeln!(output, "  Protocol identities and claims:")?;
        for identity in &interface.identities {
            write!(
                output,
                "    {} {} source={}",
                identity.protocol,
                identity.role,
                identity.source_mac.escape_debug()
            )?;
            if let Some(claimed) = &identity.claimed_mac {
                write!(output, " claimed={}", claimed.escape_debug())?;
            }
            if let Some(address) = identity.address {
                write!(output, " address={address}")?;
            }
            writeln!(
                output,
                " vlan_tags={:?} vlan_aux={:?} frames={} evidence={}",
                identity.vlan_tags, identity.vlan_aux, identity.frames, identity.packet
            )?;
        }
    }
    Ok(())
}

fn write_stp_summary(
    interface: &l2_audit::InterfaceObservation,
    output: &mut impl Write,
) -> io::Result<()> {
    // The last retained advertisement is the current source-scoped observation
    if let Some(stp) = interface.stp.last() {
        writeln!(
            output,
            "  Untagged STP root: {} priority={} system-id-extension={} protocol={} advertisement changes={} (packet {})",
            stp.root.mac.escape_debug(),
            stp.root.priority,
            stp.root.system_id_extension,
            stp.version.escape_debug(),
            interface.stp.len() - 1,
            stp.packet
        )?;
    }
    writeln!(
        output,
        "  Supported STP advertisements: {}",
        interface.stp_frames
    )?;
    Ok(())
}
