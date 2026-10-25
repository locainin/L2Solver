//! Offline runner for explicit captured-byte range comparisons

use crate::{
    arguments::{CaptureCompareOptions, OutputFormat},
    input, output,
};
use l2_capture::{CapturedFrame, InterfaceId, LinkType};
use l2_cli::byte_compare::{self, ByteComparison, CompareOptions};
use l2_pcap::CaptureSource;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt::Write as FmtWrite, io::Write};

const MAX_COMPARISON_REPORT_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
struct InterfaceReport {
    section: u32,
    index: u32,
}

#[derive(Serialize)]
struct LinkTypeReport {
    name: &'static str,
    raw: u16,
}

#[derive(Serialize)]
struct PacketSelectionReport {
    packet_index: u32,
    interface: InterfaceReport,
    link_type: LinkTypeReport,
    captured_length: usize,
    original_length: u32,
    /// Whether the capture record retained fewer bytes than the original frame length
    truncated: bool,
    /// SHA-256 over the complete retained frame before range selection
    captured_sha256: String,
    captured_frame_offset: usize,
    selected_length: usize,
}

#[derive(Serialize)]
struct CaptureCompareReport {
    schema_version: u32,
    tool_version: &'static str,
    left: PacketSelectionReport,
    right: PacketSelectionReport,
    comparison: ByteComparison,
    /// Present only when a repeating XOR key was supplied by the operator
    #[serde(skip_serializing_if = "Option::is_none")]
    supplied_xor_key_hex: Option<String>,
    interpretation: &'static str,
}

/// Read a complete bounded capture, compare its explicit packet ranges, then render once
///
/// Selected frame bytes are the only packet data retained. Parsing continues through clean
/// end-of-file before either text or JSON is written, so a malformed tail cannot leave an
/// apparently complete comparison in the output stream
///
/// # Errors
/// Returns an input, capture-format, packet-selection, range, or output error
pub fn run(options: &CaptureCompareOptions, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let (left_packet, right_packet) = read_selected_packets(options)?;
    let comparison = byte_compare::compare(
        left_packet.bytes(),
        right_packet.bytes(),
        CompareOptions {
            left_offset: options.left_offset,
            right_offset: options.right_offset,
            length: options.length,
            xor_key: options.xor_key.as_deref(),
        },
    )?;
    // The compared prefix plus each separate tail recovers its selected length
    let left_selected_length = comparison.compared_length + comparison.left_tail_length;
    let right_selected_length = comparison.compared_length + comparison.right_tail_length;
    let supplied_xor_key_hex = options.xor_key.as_deref().map(hex_encode).transpose()?;

    let report = CaptureCompareReport {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION"),
        left: selection_report(
            options.left_packet,
            &left_packet,
            options.left_offset,
            left_selected_length,
        )?,
        right: selection_report(
            options.right_packet,
            &right_packet,
            options.right_offset,
            right_selected_length,
        )?,
        comparison,
        supplied_xor_key_hex,
        interpretation: "This report describes selected captured bytes only; it does not infer encryption, concealment, or intent",
    };

    let mut document = Vec::new();
    {
        let mut bounded = output::BoundedWriter::named(
            &mut document,
            MAX_COMPARISON_REPORT_BYTES,
            "capture comparison report",
        );
        match options.format {
            OutputFormat::Text => write_text(&report, &mut bounded)?,
            OutputFormat::Json => {
                serde_json::to_writer(&mut bounded, &report)?;
                bounded.write_all(b"\n")?;
            }
            OutputFormat::Html => {
                return Err("capture comparison format must be text or json".into());
            }
        }
        bounded.flush()?;
    }
    output.write_all(&document)?;
    Ok(())
}

fn read_selected_packets(
    options: &CaptureCompareOptions,
) -> Result<(CapturedFrame, CapturedFrame), Box<dyn Error>> {
    let reader = input::capture(&options.capture)?;
    let mut capture = CaptureSource::new(reader)?;
    let mut packet_index = 0_u32;
    let mut left = None;
    let mut right = None;

    while let Some(packet) = capture.next_packet()? {
        packet_index = packet_index
            .checked_add(1)
            .ok_or("capture packet index overflow")?;
        if packet_index == options.left_packet {
            left = Some(packet.clone());
        }
        if packet_index == options.right_packet {
            right = Some(packet);
        }
    }

    let left =
        left.ok_or_else(|| format!("capture does not contain packet {}", options.left_packet))?;
    let right =
        right.ok_or_else(|| format!("capture does not contain packet {}", options.right_packet))?;
    Ok((left, right))
}

fn selection_report(
    packet_index: u32,
    packet: &CapturedFrame,
    offset: usize,
    selected_length: usize,
) -> Result<PacketSelectionReport, std::fmt::Error> {
    let metadata = packet.metadata();
    let interface: InterfaceId = metadata.interface();
    let link_type: LinkType = metadata.link_type();
    Ok(PacketSelectionReport {
        packet_index,
        interface: InterfaceReport {
            section: interface.section,
            index: interface.index,
        },
        link_type: LinkTypeReport {
            name: link_type.name(),
            raw: link_type.raw(),
        },
        captured_length: packet.captured_len(),
        original_length: metadata.original_len(),
        truncated: packet.is_truncated(),
        captured_sha256: sha256_hex(packet.bytes())?,
        captured_frame_offset: offset,
        selected_length,
    })
}

fn sha256_hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn write_text(report: &CaptureCompareReport, output: &mut impl Write) -> std::io::Result<()> {
    writeln!(output, "Capture byte comparison")?;
    write_selection("left", &report.left, output)?;
    write_selection("right", &report.right, output)?;
    writeln!(
        output,
        "Compared {} byte position(s); {} unequal value(s) in the common range",
        report.comparison.compared_length, report.comparison.differing_bytes
    )?;
    writeln!(
        output,
        "Unequal tails: left starts at byte {} ({} byte(s)); right starts at byte {} ({} byte(s))",
        report.left.captured_frame_offset + report.comparison.compared_length,
        report.comparison.left_tail_length,
        report.right.captured_frame_offset + report.comparison.compared_length,
        report.comparison.right_tail_length
    )?;
    for span in &report.comparison.spans {
        writeln!(
            output,
            "Unequal span: left byte {} / right byte {}, length {}",
            report.left.captured_frame_offset + span.offset,
            report.right.captured_frame_offset + span.offset,
            span.length
        )?;
    }
    if report.comparison.spans_truncated {
        writeln!(
            output,
            "Additional unequal spans were omitted after the {} span limit",
            byte_compare::MAX_REPORTED_SPANS
        )?;
    }
    if let Some(key_hex) = &report.supplied_xor_key_hex {
        writeln!(output, "Supplied XOR key (hex): {key_hex}")?;
    }
    match report.comparison.xor_verification {
        None => writeln!(output, "XOR key check: not requested")?,
        Some(byte_compare::XorStatus::Verified) => writeln!(
            output,
            "XOR key check: supplied relation matched every selected byte"
        )?,
        Some(byte_compare::XorStatus::Mismatch { differing_bytes }) => writeln!(
            output,
            "XOR key check: supplied relation differed at {differing_bytes} byte position(s)"
        )?,
        Some(byte_compare::XorStatus::NotComparable) => writeln!(
            output,
            "XOR key check: selected ranges are unequal in length or empty"
        )?,
    }
    writeln!(output, "{}", report.interpretation)
}

fn write_selection(
    side: &str,
    selection: &PacketSelectionReport,
    output: &mut impl Write,
) -> std::io::Result<()> {
    writeln!(
        output,
        "{side}: packet={} interface={}:{} link_type={} ({}) captured={} original={} truncated={} offset={} selected={}",
        selection.packet_index,
        selection.interface.section,
        selection.interface.index,
        selection.link_type.name,
        selection.link_type.raw,
        selection.captured_length,
        selection.original_length,
        selection.truncated,
        selection.captured_frame_offset,
        selection.selected_length
    )
}
