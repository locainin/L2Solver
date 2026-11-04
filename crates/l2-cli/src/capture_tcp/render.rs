use super::model::CaptureTcpReport;
use l2_capture::LinkType;
use std::io::{self, Write};

pub(super) fn text(report: &CaptureTcpReport, output: &mut impl Write) -> io::Result<()> {
    summary(report, output)?;
    for span in &report.range.spans {
        writeln!(
            output,
            "Span byte {} length {}: {:?}, omitted observation={}",
            span.offset, span.length, span.status, span.omitted_observation
        )?;
        if let Some(bytes) = &span.bytes {
            hex_line(bytes, output)?;
        }
    }
    for (observation, source) in report.range.observations.iter().zip(&report.sources) {
        writeln!(
            output,
            "Source packet {} captured={} original={} seq={} flags=0x{:02x} frame byte {} range byte {} length {}",
            observation.packet_index,
            source.captured_length,
            source.original_length,
            observation.sequence,
            observation.flags,
            observation.payload_frame_offset,
            observation.range_offset,
            observation.bytes.len()
        )?;
        // Conflicting alternatives can be reproduced from their separate source ranges
        if !observation.bytes.is_empty() {
            hex_line(&observation.bytes, output)?;
        }
    }
    for unresolved in &report.unresolved_sources {
        writeln!(
            output,
            "Unresolved source packet {} reason={}",
            unresolved.source.packet_index,
            serde_json::to_string(&unresolved.reason).map_err(io::Error::other)?
        )?;
    }
    writeln!(
        output,
        "Unresolved source references retained: {} of {}",
        report.unresolved_sources.len(),
        report.unresolved_packets
    )?;
    for limitation in &report.limitations {
        writeln!(output, "{limitation}")?;
    }
    Ok(())
}

fn hex_line(bytes: &[u8], output: &mut impl Write) -> io::Result<()> {
    write!(output, "  hex=")?;
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    writeln!(output)
}

fn summary(report: &CaptureTcpReport, output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "TCP payload sequence range: {}",
        if report.complete {
            "COMPLETE"
        } else {
            "INCOMPLETE"
        }
    )?;
    writeln!(
        output,
        "Packets {}..={} of {}; matched {}; unresolved {}",
        report.first_packet,
        report.last_packet,
        report.capture_packets,
        report.matching_packets,
        report.unresolved_packets
    )?;
    write!(
        output,
        "Scope {}:{}",
        report.flow.scope.section, report.flow.scope.interface
    )?;
    if let Some(ifindex) = report.flow.scope.cooked_ifindex {
        write!(output, " cooked ifindex {ifindex}")?;
    }
    if matches!(
        report.flow.link_type,
        LinkType::LinuxSll | LinkType::LinuxSll2
    ) {
        write!(output, " VLAN membership unavailable")?;
    } else {
        write!(output, " VLAN {:?}", report.flow.scope.vlan_ids)?;
    }
    writeln!(
        output,
        " auxiliary {:?}; {}:{} -> {}:{}",
        report.flow.scope.vlan_aux,
        report.flow.source,
        report.flow.ports.0,
        report.flow.destination,
        report.flow.ports.1
    )?;
    writeln!(
        output,
        "Sequence {} length {}: {} with one retained value, {} without a retained value, {} conflicting; {} positions affected by {} omitted observations",
        report.range.start_sequence,
        report.range.length,
        report.range.observed_bytes,
        report.range.missing_bytes,
        report.range.conflicting_bytes,
        report.range.omitted_bytes,
        report.range.omitted_observations
    )?;
    Ok(())
}
