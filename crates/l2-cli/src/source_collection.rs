//! Report source collection declarations without treating absent reports as zero loss

use l2_pcap::CollectionSummary;
use std::io::{self, Write};

/// Write source declarations and report whether they identify incomplete collection
///
/// # Errors
/// Returns the output error
pub fn text(summary: CollectionSummary, output: &mut impl Write) -> io::Result<bool> {
    if has_reported_quality(summary) {
        writeln!(
            output,
            "source_collection sections={} reported_sections={} incomplete_sections={} capture_dropped={} interface_dropped={} packet_block_packets_dropped={} packet_blocks_with_unavailable_drop_count={} authority=source-declared",
            summary.sections,
            summary.reported_sections,
            summary.incomplete_sections,
            summary.capture_dropped,
            summary.interface_dropped,
            summary.packet_block_packets_dropped,
            summary.packet_blocks_with_unavailable_drop_count,
        )?;
    }
    Ok(!l2_workbench::capture_collection::reports_incomplete_collection(summary))
}

/// Write a typed NDJSON summary when the source includes a collection declaration
///
/// # Errors
/// Returns the serialization or output error
pub fn json(summary: CollectionSummary, output: &mut impl Write) -> io::Result<()> {
    if has_reported_quality(summary) {
        let value = l2_workbench::capture_collection::to_value(summary)?;
        serde_json::to_writer(
            &mut *output,
            &serde_json::json!({
                "record_type": "source_collection", "authority": "source_declared",
                "source_collection": value,
            }),
        )?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

const fn has_reported_quality(summary: CollectionSummary) -> bool {
    summary.reported_sections != 0
        || summary.packet_block_packets_dropped != 0
        || summary.packet_blocks_with_unavailable_drop_count != 0
}
