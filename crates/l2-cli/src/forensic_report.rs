//! Render literal forensic records alongside their scope and supporting packets

#[path = "survey_report/dns.rs"]
mod dns;

use l2_audit::{ForensicReport, ForensicScope, Report, ResourceLimit};
use l2_cli::arguments::ReportOptions;
use std::io::{self, Write};

pub fn write(report: &Report, options: &ReportOptions, output: &mut impl Write) -> io::Result<()> {
    summary(report, output)?;
    if options.verbosity == 0 {
        return Ok(());
    }
    let facts = &report.forensics;
    for limitation in facts.limitations.iter().skip(1) {
        writeln!(output, "  {}", limitation.escape_debug())?;
    }
    communications(facts, output)?;
    changes(facts, output)?;
    trailers(facts, output)?;
    dns::details(facts, options.verbosity, output)?;
    if options.verbosity > 1 {
        arp(facts, output)?;
    }
    Ok(())
}

fn summary(report: &Report, output: &mut impl Write) -> io::Result<()> {
    let facts = &report.forensics;
    let completed = facts
        .arp_changes
        .iter()
        .filter(|change| change.followup_packet.is_some())
        .count();
    writeln!(output, "\nForensic observations")?;
    writeln!(
        output,
        "IP headers   {} / {} complete decoded IP frames parsed; {} directional header relationships",
        facts.ip_frames_parsed,
        facts.ip_frames_seen,
        facts.communications.len()
    )?;
    writeln!(
        output,
        "ARP          {} distinct observations, {} claim changes, {completed} with later addressed traffic",
        facts.arp_observations.len(),
        facts.arp_changes.len()
    )?;
    writeln!(
        output,
        "Byte ranges  {} nonzero trailing ranges; {} unchecked because FCS was not declared absent",
        facts.trailing_data.len(),
        facts.trailer_frames_unchecked
    )?;
    writeln!(
        output,
        "DNS wire     {} / {} UDP candidates decoded; {} response association records; {} later address co-occurrences",
        facts.dns_messages_parsed,
        facts.dns_candidates_seen,
        facts.dns_matches.len(),
        facts.dns_address_uses.len()
    )?;
    if let Some(limitation) = facts.limitations.first() {
        writeln!(output, "{}", limitation.escape_debug())?;
    }
    if report
        .resource_limits
        .is_reached(ResourceLimit::ForensicRecords)
        || report
            .resource_limits
            .is_reached(ResourceLimit::EvidenceReferences)
    {
        writeln!(
            output,
            "Forensic retention limit reached (record or evidence reference budget); later relationships and chains were not collected"
        )?;
    }
    if report
        .resource_limits
        .is_reached(ResourceLimit::DnsMessages)
    {
        writeln!(
            output,
            "DNS message retention limit reached; later DNS relationships were not collected"
        )?;
    }
    Ok(())
}

fn communications(facts: &ForensicReport, output: &mut impl Write) -> io::Result<()> {
    for communication in &facts.communications {
        scope(&communication.scope, output)?;
        write!(
            output,
            "  IP {} [{}] -> {} [{}] protocol={}",
            communication.source,
            communication.source_mac.escape_debug(),
            communication.destination,
            communication.destination_mac.escape_debug(),
            communication.protocol
        )?;
        if let Some((source, destination)) = communication.ports {
            write!(output, " ports={source}->{destination}")?;
        }
        writeln!(
            output,
            " fragmented={} frames={} packet={}",
            communication.fragmented, communication.frames, communication.packet
        )?;
    }
    Ok(())
}

fn changes(facts: &ForensicReport, output: &mut impl Write) -> io::Result<()> {
    for change in &facts.arp_changes {
        scope(&change.scope, output)?;
        write!(
            output,
            "  ARP {} claim {} -> {}; packets {} -> {}",
            change.address,
            change.previous_mac.escape_debug(),
            change.claimed_mac.escape_debug(),
            change.previous_packet,
            change.packet
        )?;
        if let Some(packet) = change.followup_packet {
            writeln!(
                output,
                " -> {packet} (matching later IP and Ethernet destinations)"
            )?;
        } else {
            writeln!(
                output,
                " (no matching later traffic retained before another observed claim or collection end)"
            )?;
        }
    }
    Ok(())
}

fn trailers(facts: &ForensicReport, output: &mut impl Write) -> io::Result<()> {
    for trailer in &facts.trailing_data {
        scope(&trailer.scope, output)?;
        writeln!(
            output,
            "  {:?} bytes after declared length: offset={} length={} nonzero={} packet={} (padding may explain this range)",
            trailer.protocol, trailer.offset, trailer.length, trailer.nonzero_bytes, trailer.packet
        )?;
    }
    Ok(())
}

fn arp(facts: &ForensicReport, output: &mut impl Write) -> io::Result<()> {
    for arp in &facts.arp_observations {
        scope(&arp.scope, output)?;
        writeln!(
            output,
            "  ARP operation={} Ethernet-source={} sender={} [{}] target={} [{}] frames={} packet={}",
            arp.operation,
            arp.source_mac.escape_debug(),
            arp.sender_address,
            arp.sender_mac.escape_debug(),
            arp.target_address,
            arp.target_mac.escape_debug(),
            arp.frames,
            arp.packet
        )?;
    }
    Ok(())
}

fn scope(scope: &ForensicScope, output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "  source={}:{} vlan_ids={:?} vlan_aux={:?}",
        scope.section, scope.interface, scope.vlan_ids, scope.vlan_aux
    )
}
