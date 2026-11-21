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
    containment: Option<l2_workbench::tshark::ScopeReceipt>,
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
    output.write_all(b",\"encoding\":\"gzip\",\"coverage\":")?;
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
            temporary_output_policy: "Object data blocks are bounded by a private, page-rounded tmpfs; child memory and tasks are cgroup-limited. Logical lengths, file counts and tree entries are polled and may overshoot between scans. Only verified regular files are copied to trusted storage after the child scope stops",
            object_export_status: summary.tshark.export_status,
            object_export_budget: summary.tshark.export_budget,
            object_export_usage: summary.tshark.export_usage,
            containment: summary.tshark.containment,
            object_scan_entries: summary.tshark.scan_entries,
        },
    )?;
    output.write_all(b"}\n")?;
    output.sync_all()?;
    Ok(())
}
