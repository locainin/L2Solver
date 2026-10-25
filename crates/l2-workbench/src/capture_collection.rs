//! Canonical JSON conversion for source-reported capture collection conditions

use crate::evidence::EvidenceError;
use l2_pcap::CollectionSummary;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Error, Value};
use std::error::Error as StdError;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SummaryJson {
    sections: u64,
    reported_sections: u64,
    incomplete_sections: u64,
    capture_dropped: u64,
    interface_dropped: u64,
    #[serde(default)]
    packet_block_packets_dropped: u64,
    #[serde(default)]
    packet_blocks_with_unavailable_drop_count: u64,
}

impl From<CollectionSummary> for SummaryJson {
    fn from(summary: CollectionSummary) -> Self {
        Self {
            sections: summary.sections,
            reported_sections: summary.reported_sections,
            incomplete_sections: summary.incomplete_sections,
            capture_dropped: summary.capture_dropped,
            interface_dropped: summary.interface_dropped,
            packet_block_packets_dropped: summary.packet_block_packets_dropped,
            packet_blocks_with_unavailable_drop_count: summary
                .packet_blocks_with_unavailable_drop_count,
        }
    }
}

impl TryFrom<SummaryJson> for CollectionSummary {
    type Error = &'static str;

    fn try_from(value: SummaryJson) -> Result<Self, Self::Error> {
        if value.reported_sections > value.sections
            || value.incomplete_sections > value.reported_sections
        {
            return Err("collection summary counters are inconsistent");
        }
        Ok(Self {
            sections: value.sections,
            reported_sections: value.reported_sections,
            incomplete_sections: value.incomplete_sections,
            capture_dropped: value.capture_dropped,
            interface_dropped: value.interface_dropped,
            packet_block_packets_dropped: value.packet_block_packets_dropped,
            packet_blocks_with_unavailable_drop_count: value
                .packet_blocks_with_unavailable_drop_count,
        })
    }
}

/// Encode collection counters with the canonical public field names
///
/// # Errors
/// Returns a JSON serialization error
pub fn to_json(summary: CollectionSummary) -> Result<String, Error> {
    serde_json::to_string(&SummaryJson::from(summary))
}

/// Decode and validate the canonical collection summary representation
///
/// # Errors
/// Rejects malformed JSON, unknown fields, and inconsistent counters
pub fn from_json(value: &str) -> Result<CollectionSummary, Error> {
    let value: SummaryJson = serde_json::from_str(value)?;
    CollectionSummary::try_from(value).map_err(serde::de::Error::custom)
}

/// Deserialize and validate collection summary fields inside a report type
///
/// # Errors
/// Rejects malformed fields and inconsistent counters
pub fn deserialize<'de, D>(deserializer: D) -> Result<CollectionSummary, D::Error>
where
    D: Deserializer<'de>,
{
    let value = SummaryJson::deserialize(deserializer)?;
    CollectionSummary::try_from(value).map_err(serde::de::Error::custom)
}

/// Convert the same canonical representation for bounded evidence details
///
/// # Errors
/// Returns a JSON serialization error
pub fn to_value(summary: CollectionSummary) -> Result<Value, Error> {
    serde_json::to_value(SummaryJson::from(summary))
}

/// Return whether any collection section lacks a source declaration
#[must_use]
pub const fn has_unknown_quality(summary: CollectionSummary) -> bool {
    summary.reported_sections == 0 || summary.sections > summary.reported_sections
}

/// Return whether a source declaration reports incomplete collection
#[must_use]
pub const fn reports_incomplete_collection(summary: CollectionSummary) -> bool {
    summary.incomplete_sections > 0
        || summary.packet_block_packets_dropped > 0
        || summary.packet_blocks_with_unavailable_drop_count > 0
}

/// Add source-reported collection quality to an analysis Case
///
/// Unknown reports add a limitation while leaving analysis coverage unchanged. A
/// reported incomplete section marks both the Case and its analysis result incomplete
/// A full detail budget retains the valid partial case with an explicit missing-summary limitation
///
/// # Errors
/// Returns other summary errors or an error when the Case cannot retain a limitation
pub fn apply_to_case(
    result: &mut crate::investigation::BuildResult,
    source_id: &str,
    summary: CollectionSummary,
) -> Result<(), Box<dyn StdError>> {
    let retained = result.case.add_node(
        "capture_collection_summary",
        None,
        Vec::new(),
        serde_json::json!({
            "source_id": source_id,
            "summary": to_value(summary)?,
        }),
    );
    match retained {
        Ok(_) => {}
        Err(error @ EvidenceError::TotalDetailsTooLarge { .. }) => {
            // Analysis may have filled the details budget before source quality is attached
            result.case.mark_incomplete(&format!(
                "Mandatory capture_collection_summary for source {source_id} was omitted after the evidence detail budget ({error}); source collection quality is unresolved"
            ))?;
            result.complete = false;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    if has_unknown_quality(summary) {
        result.case.add_limitation(&format!(
            "Source {source_id} has unknown collection quality for one or more sections; analysis is scoped to captured bytes"
        ))?;
    }
    if summary.incomplete_sections > 0 {
        result.case.add_limitation(&format!(
            "Source {source_id} reports {} incomplete collection sections; analysis is scoped to the packets present",
            summary.incomplete_sections
        ))?;
    }
    if summary.packet_block_packets_dropped > 0 {
        result.case.add_limitation(&format!(
            "Source {source_id} reports {} packets dropped between packets in obsolete Packet Blocks; analysis is scoped to the packets present",
            summary.packet_block_packets_dropped
        ))?;
    }
    if summary.packet_blocks_with_unavailable_drop_count > 0 {
        result.case.add_limitation(&format!(
            "Source {source_id} has {} obsolete Packet Blocks with an unavailable drop count; analysis is scoped to the packets present",
            summary.packet_blocks_with_unavailable_drop_count
        ))?;
    }
    if reports_incomplete_collection(summary) {
        result.case.mark_incomplete(
            "A source-reported collection condition identifies incomplete acquisition",
        )?;
        result.complete = false;
    }
    Ok(())
}

/// Serialize the summary for fields in workbench report types
///
/// # Errors
/// Returns an error from the selected serializer
pub fn serialize<S>(summary: &CollectionSummary, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    SummaryJson::from(*summary).serialize(serializer)
}
