//! Report source collection declarations without treating absent reports as zero loss

use l2_pcap::CollectionSummary;
use std::io::{self, Write};

#[derive(serde::Serialize)]
pub struct AcquisitionQuality {
    status: &'static str,
    pub authority: &'static str,
}

impl AcquisitionQuality {
    #[must_use]
    pub const fn unverified(authority: l2_capture::CollectionAuthority) -> Self {
        Self {
            status: "unverified",
            authority: authority.as_str(),
        }
    }
}

/// Write source declarations and report whether they identify incomplete collection
///
/// # Errors
/// Returns the output error
pub fn text(summary: CollectionSummary, output: &mut impl Write) -> io::Result<bool> {
    writeln!(
        output,
        "source_collection sections={} reported_sections={} incomplete_sections={} capture_dropped={} interface_dropped={} packet_block_packets_dropped={} packet_blocks_with_unavailable_drop_count={} enhanced_packet_packets_dropped={} interface_statistics_interface_dropped={} interface_statistics_os_dropped={} authority={} acquisition_quality=unverified",
        summary.sections,
        summary.reported_sections,
        summary.incomplete_sections,
        summary.capture_dropped,
        summary.interface_dropped,
        summary.packet_block_packets_dropped,
        summary.packet_blocks_with_unavailable_drop_count,
        optional_count(summary.enhanced_packet_packets_dropped),
        optional_count(summary.interface_statistics_interface_dropped),
        optional_count(summary.interface_statistics_os_dropped),
        summary.authority().as_str(),
    )?;
    Ok(!l2_workbench::capture_collection::reports_incomplete_collection(summary))
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |count| count.to_string())
}

/// Write a typed NDJSON summary for source acquisition conditions
///
/// # Errors
/// Returns the serialization or output error
pub fn json(summary: CollectionSummary, output: &mut impl Write) -> io::Result<()> {
    let value = l2_workbench::capture_collection::to_value(summary)?;
    serde_json::to_writer(
        &mut *output,
        &serde_json::json!({
            "record_type": "source_collection", "authority": summary.authority().as_str(),
            "acquisition_quality": "unverified",
            "source_collection": value,
        }),
    )?;
    output.write_all(b"\n")?;
    Ok(())
}
