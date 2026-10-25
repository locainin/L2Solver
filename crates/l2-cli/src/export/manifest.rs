//! Write the machine-readable artifact and coverage manifest

use super::{coverage::tshark_is_complete, evidence, summary::Summary};
use crate::workbench;
use serde::Serialize;
use std::{error::Error, fs::File, io::Write, path::Path};

#[derive(Serialize)]
struct TsharkManifest {
    status: &'static str,
    required: bool,
    objects_exported: u64,
    imf_objects_exported: u64,
    duplicate_objects_skipped: u64,
    objects_skipped: u64,
    unsafe_entries_skipped: u64,
    issues: Vec<String>,
    provenance_note: &'static str,
    temporary_output_policy: &'static str,
    object_export_status: Option<workbench::ObjectExportStatus>,
    object_export_budget: Option<workbench::ObjectExportBudget>,
    object_export_usage: Option<workbench::ObjectExportUsage>,
    object_scan_entries: u64,
}

pub(super) fn write_manifest(
    directory: &Path,
    summary: &mut Summary<'_>,
) -> Result<(), Box<dyn Error>> {
    let tshark_complete = tshark_is_complete(summary.tshark, summary.tshark_error);
    let mut issues = summary.tshark.issues.clone();
    if let Some(error) = summary.tshark_error {
        issues.push(error.to_owned());
    }
    let mut output = File::options()
        .write(true)
        .create_new(true)
        .open(directory.join("manifest.json"))?;
    output.write_all(b"{\"schema_version\":1,\"export_status\":")?;
    serde_json::to_writer(
        &mut output,
        if summary.completion.complete {
            "complete"
        } else {
            "partial"
        },
    )?;
    output.write_all(b",\"incomplete_components\":")?;
    serde_json::to_writer(&mut output, &summary.completion.incomplete_components)?;
    output.write_all(b",\"capture\":")?;
    serde_json::to_writer(&mut output, &summary.capture.to_string_lossy())?;
    output.write_all(b",\"full_source_coverage\":")?;
    serde_json::to_writer(&mut output, summary.coverage)?;
    output.write_all(b",\"discovery_coverage\":")?;
    serde_json::to_writer(&mut output, &summary.discovery)?;
    output.write_all(b",\"evidence\":{\"file\":")?;
    serde_json::to_writer(&mut output, evidence::SIDECAR_FILE_NAME)?;
    output.write_all(b",\"coverage\":")?;
    serde_json::to_writer(&mut output, &summary.evidence)?;
    output.write_all(b"}")?;
    output.write_all(b",\"artifacts\":[")?;
    summary.artifacts.write_manifest_artifacts(&mut output)?;
    output.write_all(b"],\"omitted_artifact_references\":")?;
    summary.artifacts.write_manifest_omissions(&mut output)?;
    output.write_all(b",\"tshark\":")?;
    serde_json::to_writer(
        &mut output,
        &TsharkManifest {
            status: if tshark_complete {
                "complete"
            } else {
                "partial"
            },
            required: summary.completion.tshark_required,
            objects_exported: summary.tshark.objects_exported,
            imf_objects_exported: summary.tshark.imf_objects_exported,
            duplicate_objects_skipped: summary.tshark.duplicates,
            objects_skipped: summary.tshark.skipped,
            unsafe_entries_skipped: summary.tshark.unsafe_entries_skipped,
            issues,
            provenance_note: "Native origins use direct packet ranges and explicit node references; graph edges are not traversed. TShark origins identify protocol export only and do not report packet provenance",
            temporary_output_policy: "Temporary bytes and files are polled every 50 ms and may overshoot before process-group termination; each tree walk stops at temporary_files plus the known protocol-directory count, and the collector pass reports its first over-budget entry",
            object_export_status: summary.tshark.export_status,
            object_export_budget: summary.tshark.export_budget,
            object_export_usage: summary.tshark.export_usage,
            object_scan_entries: summary.tshark.scan_entries,
        },
    )?;
    output.write_all(b"}\n")?;
    output.sync_all()?;
    Ok(())
}
