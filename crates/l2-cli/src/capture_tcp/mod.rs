//! Offline TCP byte-range reconstruction with explicit selection and evidence bounds

mod classify;
mod model;
mod render;
mod selection;

use crate::{
    arguments::{CaptureTcpOptions, OutputFormat},
    input, output,
};
use l2_pcap::CaptureSource;
use model::CaptureTcpReport;
use selection::Selection;
use std::{error::Error, io::Write};

const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;

/// Scan to clean EOF before publishing a bounded range report
///
/// # Errors
/// Returns capture, selection, source-range, or output errors
pub fn run(options: &CaptureTcpOptions, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let report = collect(options)?;
    let mut document = Vec::new();
    {
        let mut bounded =
            output::BoundedWriter::named(&mut document, MAX_REPORT_BYTES, "TCP range report");
        match options.format {
            OutputFormat::Json => {
                serde_json::to_writer(&mut bounded, &report)?;
                bounded.write_all(b"\n")?;
            }
            OutputFormat::Text => render::text(&report, &mut bounded)?,
            OutputFormat::Html => return Err("TCP range format must be text or json".into()),
        }
        bounded.flush()?;
    }
    output.write_all(&document)?;
    Ok(report.complete)
}

fn collect(options: &CaptureTcpOptions) -> Result<CaptureTcpReport, Box<dyn Error>> {
    let mut capture = CaptureSource::new(input::capture(&options.capture)?)?;
    let mut packet_index = 0_u32;
    let mut selection = None;
    while let Some(packet) = capture.next_packet()? {
        packet_index += 1;
        if packet_index < options.packet
            || options.last_packet.is_some_and(|last| packet_index > last)
        {
            continue;
        }
        if packet_index == options.packet {
            selection = Some(Selection::new(&packet, options)?);
        }
        if let Some(selection) = &mut selection {
            selection.observe(&packet, packet_index)?;
        }
    }
    // Even an explicit end record cannot hide malformed capture framing after it
    if options.last_packet.is_some_and(|last| last > packet_index) {
        return Err("capture does not contain the selected last packet".into());
    }
    let selection =
        selection.ok_or_else(|| format!("capture does not contain packet {}", options.packet))?;
    Ok(selection.finish(
        options.packet,
        options.last_packet.unwrap_or(packet_index),
        packet_index,
    ))
}
