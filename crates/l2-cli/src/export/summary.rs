//! Render artifact descriptions and extraction coverage for terminal readers

use super::{
    artifact_collection::{ArtifactCollection, ArtifactProvenance},
    coverage::{
        DiscoveryCoverage, ExportCompletion, PerCaseBudgetRange, RecoveryCoverage,
        RecoveryResourceCoverage, cohort_analysis_complete, flow_analysis_complete,
        flow_reconstruction_coverage, tshark_is_complete,
    },
    evidence,
    evidence::EvidenceCoverage,
    limitations::LimitationSpool,
    tshark_objects,
};
use crate::workbench;
use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    fs::File,
    io,
    io::Write,
    path::Path,
};

pub(super) struct Summary<'a> {
    pub(super) capture: &'a Path,
    pub(super) completion: &'a ExportCompletion,
    pub(super) coverage: &'a workbench::full_source::FullSourceCoverage,
    pub(super) discovery: DiscoveryCoverage,
    pub(super) artifacts: &'a mut ArtifactCollection,
    pub(super) evidence: EvidenceCoverage,
    pub(super) tshark: &'a tshark_objects::Collection,
    pub(super) tshark_error: Option<&'a str>,
    pub(super) limitations: &'a mut LimitationSpool,
}

pub(super) fn write_summary(
    directory: &Path,
    summary: &mut Summary<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut output = File::create_new(directory.join("summary.txt"))?;
    writeln!(output, "L2Solver capture export")?;
    write_summary_status(&mut output, summary)?;
    write_artifact_contents(&mut output, summary.artifacts)?;
    write_tshark_contents(&mut output, summary)?;
    if summary.limitations.count != 0
        || summary.discovery.artifacts.references_omitted != 0
        || summary.evidence.omitted_cases != 0
        || summary.coverage.analysis.incomplete_flows != 0
        || summary.coverage.analysis.range_omission_flows != 0
        || summary.coverage.analysis.reconstruction_omission_flows != 0
        || summary
            .coverage
            .analysis
            .supplementary_pages
            .reconstruction_omissions
            .cases_with_omissions
            != 0
        || summary.coverage.cohort_reconstruction.cases_with_omissions != 0
        || !summary.discovery.recovery.is_complete()
        || !cohort_analysis_complete(summary.coverage)
    {
        writeln!(output, "Additional limitations: see limitations.txt")?;
    }
    output.sync_all()?;
    Ok(())
}

fn write_summary_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    write_export_completion(output, summary.completion)?;
    write_source_status(output, summary)?;
    write_recovery_status(output, &summary.discovery.recovery)?;
    write_evidence_status(output, summary.evidence)?;
    write_artifact_status(output, summary)?;
    write_tshark_status(output, summary)
}

fn write_evidence_status(output: &mut File, evidence: EvidenceCoverage) -> io::Result<()> {
    writeln!(
        output,
        "Evidence sidecar: {}; {} Cases retained ({} compressed bytes; {} logical JSONL bytes), {} omitted ({} compressed bytes; {} logical JSONL bytes), {} byte aggregate storage budget",
        evidence::SIDECAR_FILE_NAME,
        evidence.retained_cases,
        evidence.retained_bytes,
        evidence.raw_retained_bytes,
        evidence.omitted_cases,
        evidence.omitted_bytes,
        evidence.raw_omitted_bytes,
        evidence.budget_bytes
    )
}

fn write_export_completion(output: &mut File, completion: &ExportCompletion) -> io::Result<()> {
    let (status, exit_status) = if completion.complete {
        ("complete", 0)
    } else {
        ("partial", 3)
    };
    writeln!(
        output,
        "Overall export: {status} (exit status {exit_status})"
    )?;
    if !completion.incomplete_components.is_empty() {
        writeln!(output, "Incomplete components:")?;
        for item in &completion.incomplete_components {
            writeln!(
                output,
                "- {}: {}",
                item.component,
                summary_text(&item.reason)
            )?;
        }
    }
    Ok(())
}

fn write_source_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    write_source_identity(output, summary)?;
    write_flow_status(output, summary)?;
    write_cohort_status(output, summary)
}

fn write_source_identity(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    writeln!(
        output,
        "Capture: {}",
        summary_text(&summary.capture.to_string_lossy())
    )?;
    writeln!(output, "Full-source ingest: complete to EOF")?;
    writeln!(
        output,
        "Source bytes read: {}",
        summary.coverage.source.bytes
    )?;
    writeln!(
        output,
        "Source packet records: {}",
        summary.coverage.source.packet_records
    )?;
    writeln!(
        output,
        "Supported transport records: {}",
        summary.coverage.source.supported_transport_records
    )?;
    writeln!(
        output,
        "Packets without supported transport: {}",
        summary.coverage.source.packets_without_supported_transport
    )?;
    if summary.coverage.source.packet_records != 0
        && summary.coverage.source.supported_transport_records == 0
    {
        writeln!(
            output,
            "Native transport analysis: not performed; no source records had a supported transport envelope"
        )?;
    }
    Ok(())
}

fn write_flow_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    let analysis_complete = flow_analysis_complete(summary.coverage);
    writeln!(
        output,
        "Per-flow analysis: {}",
        if analysis_complete {
            "complete"
        } else {
            "partial"
        }
    )?;
    writeln!(
        output,
        "Per-flow native analysis: {}",
        if analysis_complete {
            "complete"
        } else {
            "partial"
        }
    )?;
    writeln!(
        output,
        "Flow Cases visited: {} ({} complete, {} incomplete)",
        summary.coverage.analysis.flows,
        summary.coverage.analysis.complete_flows,
        summary.coverage.analysis.incomplete_flows
    )?;
    writeln!(
        output,
        "Flow records selected: {}; retained: {}; omitted: {}",
        summary.coverage.analysis.selected_flow_records,
        summary.coverage.analysis.retained_flow_records,
        summary.coverage.analysis.omitted_flow_records
    )?;
    let pages = summary.coverage.analysis.supplementary_pages;
    writeln!(
        output,
        "Supplementary flow pages: {} across {} flows; selected records: {}; retained records: {}; omitted records: {}",
        pages.pages,
        pages.flows,
        pages.selected_records,
        pages.retained_records,
        pages.omitted_records
    )?;
    if pages.pages != 0 {
        write_reconstruction_omissions(
            output,
            "Supplementary page",
            pages.reconstruction_omissions,
            true,
        )?;
    }
    writeln!(
        output,
        "Flow retention limits: {} prefix-truncated; {} frame-limited; {} byte-limited; {} unit-limited",
        summary.coverage.analysis.selection_truncated_flows,
        summary.coverage.analysis.frame_limited_flows,
        summary.coverage.analysis.byte_limited_flows,
        summary.coverage.analysis.unit_limited_flows
    )?;
    writeln!(
        output,
        "Sequence range omissions affect {} flows",
        summary.coverage.analysis.range_omission_flows
    )?;
    write_reconstruction_omissions(
        output,
        "Flow",
        flow_reconstruction_coverage(summary.coverage),
        true,
    )?;
    Ok(())
}

fn write_cohort_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    writeln!(
        output,
        "Unordered source/scope/IP-pair cohorts: {}",
        if cohort_analysis_complete(summary.coverage) {
            "complete"
        } else {
            "partial"
        }
    )?;
    if let Some(cohorts) = summary.coverage.cohort_analysis {
        writeln!(
            output,
            "Cohort groups: {} multi-flow ({} complete, {} incomplete), {} split; chunks: {} ({} complete, {} incomplete)",
            cohorts.multi_flow_groups,
            cohorts.complete_groups,
            cohorts.incomplete_groups,
            cohorts.split_groups,
            cohorts.analysis_chunks,
            cohorts.complete_chunks,
            cohorts.incomplete_chunks
        )?;
        writeln!(
            output,
            "Cohort records selected: {}; retained: {}; omitted: {}; flows reanalyzed: {}; singleton chunks skipped: {}; oversized flows skipped: {}",
            cohorts.selected_records,
            cohorts.retained_records,
            cohorts.omitted_records,
            cohorts.reanalyzed_flows,
            cohorts.singleton_chunks_skipped,
            cohorts.oversized_flows_skipped
        )?;
    }
    write_reconstruction_omissions(
        output,
        "Cohort",
        summary.coverage.cohort_reconstruction,
        true,
    )?;
    Ok(())
}

pub(super) fn write_reconstruction_omissions(
    output: &mut File,
    scope: &str,
    coverage: workbench::full_source::ReconstructionOmissionCoverage,
    include_zero: bool,
) -> io::Result<()> {
    if include_zero || coverage.cases_with_omissions != 0 {
        let case_label = if coverage.cases == 1 { "Case" } else { "Cases" };
        writeln!(
            output,
            "{scope} reconstruction omissions: {} TCP records, {} fragments, {} ranges, {} TCP byte positions affected by omitted observations or rejected ranges, {} TCP observations, {} fragment byte positions affected by omitted observations or rejected ranges, {} fragment observations, {} state observations, {} unmeasured ranges (in {} of {} {case_label})",
            coverage.omitted_tcp_records,
            coverage.omitted_fragments,
            coverage.omitted_sequence_ranges,
            coverage.omitted_tcp_bytes,
            coverage.omitted_tcp_observations,
            coverage.omitted_fragment_bytes,
            coverage.omitted_fragment_observations,
            coverage.omitted_state_observations,
            coverage.unmeasured_omitted_ranges,
            coverage.cases_with_omissions,
            coverage.cases
        )?;
    }
    Ok(())
}

pub(super) fn write_recovery_status(
    output: &mut File,
    recovery: &RecoveryCoverage,
) -> io::Result<()> {
    write_recovery_evidence_status(output, recovery)?;
    write_recovery_input_status(output, recovery)?;
    write_recovery_search_status(output, recovery)?;
    write_recovery_report_status(output, recovery)?;
    write_recovery_result_counts(output, recovery)?;
    write_recovery_resource_status(output, &recovery.resources)
}

fn write_recovery_evidence_status(
    output: &mut File,
    recovery: &RecoveryCoverage,
) -> io::Result<()> {
    let (flow_status, cohort_status) = recovery_case_status_pair(
        recovery,
        recovery.flow_cases_with_incomplete_case_evidence_collection,
        recovery.cohort_cases_with_incomplete_case_evidence_collection,
        ("complete", "incomplete"),
    )?;
    writeln!(
        output,
        "Default recovery Case evidence collection: {flow_status}; {cohort_status}"
    )
}

fn write_recovery_input_status(output: &mut File, recovery: &RecoveryCoverage) -> io::Result<()> {
    let (flow_status, cohort_status) = recovery_case_status_pair(
        recovery,
        recovery.flow_cases_with_incomplete_discovery_input_coverage,
        recovery.cohort_cases_with_incomplete_discovery_input_coverage,
        ("complete", "incomplete"),
    )?;
    writeln!(
        output,
        "Default recovery discovery input coverage: {flow_status}; {cohort_status}; {} framing input runs and {} record input frames omitted; {} eligible record frame hypotheses excluded from bounded learning samples and retained for schema application",
        recovery.omitted_framing_input_runs,
        recovery.omitted_record_input_frames,
        recovery.record_learning_frames_not_sampled,
    )
}

fn write_recovery_search_status(output: &mut File, recovery: &RecoveryCoverage) -> io::Result<()> {
    let (flow_status, cohort_status) = recovery_case_status_pair(
        recovery,
        recovery.flow_cases_with_non_exhaustive_search,
        recovery.cohort_cases_with_non_exhaustive_search,
        ("exhaustive", "non-exhaustive"),
    )?;
    writeln!(
        output,
        "Default recovery search exhaustiveness within the declared plan: {flow_status}; {cohort_status}"
    )
}

fn write_recovery_report_status(output: &mut File, recovery: &RecoveryCoverage) -> io::Result<()> {
    let (flow_status, cohort_status) = recovery_case_status_pair(
        recovery,
        recovery.flow_cases_with_incomplete_report_details,
        recovery.cohort_cases_with_incomplete_report_details,
        ("complete", "incomplete"),
    )?;
    writeln!(
        output,
        "Default recovery report details: {flow_status}; {cohort_status}"
    )
}

fn write_recovery_result_counts(output: &mut File, recovery: &RecoveryCoverage) -> io::Result<()> {
    writeln!(
        output,
        "Recovery candidates evaluated: {}",
        recovery.candidates
    )?;
    writeln!(
        output,
        "Complete negative transform searches: {}",
        recovery.complete_negative_transform_searches
    )?;
    writeln!(
        output,
        "Structurally validated recovery artifacts: {}",
        recovery.validated_artifacts
    )?;
    writeln!(
        output,
        "Recovery omission entries: {} (one entry may cover multiple omitted inputs or report details)",
        recovery.omissions
    )?;
    writeln!(output, "Recovery cycle skips: {}", recovery.cycle_skips)?;
    Ok(())
}

fn recovery_case_status_pair(
    recovery: &RecoveryCoverage,
    flow_incomplete: u64,
    cohort_incomplete: u64,
    labels: (&str, &str),
) -> io::Result<(String, String)> {
    Ok((
        recovery_case_status(
            recovery.flow_cases,
            flow_incomplete,
            "flow",
            labels.0,
            labels.1,
        )?,
        recovery_case_status(
            recovery.cohort_cases,
            cohort_incomplete,
            "cohort",
            labels.0,
            labels.1,
        )?,
    ))
}

fn recovery_case_status(
    total: u64,
    incomplete: u64,
    case_kind: &str,
    complete_label: &str,
    incomplete_label: &str,
) -> io::Result<String> {
    let complete = complete_status_count(total, incomplete)?;
    if total == 0 {
        return Ok(format!("not applicable (no {case_kind} Cases)"));
    }

    Ok(format!(
        "{complete} {complete_label}, {incomplete} {incomplete_label} {case_kind} Cases"
    ))
}

fn complete_status_count(total: u64, incomplete: u64) -> io::Result<u64> {
    total.checked_sub(incomplete).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery status count exceeds the number of Cases",
        )
    })
}

fn write_recovery_resource_status(
    output: &mut File,
    resources: &RecoveryResourceCoverage,
) -> io::Result<()> {
    writeln!(
        output,
        "Recovery resource Cases: {}",
        resources.recovery_cases
    )?;
    write_recovery_resource_budgets(output, resources)?;
    write_recovery_resource_totals(output, resources)
}

fn write_recovery_resource_budgets(
    output: &mut File,
    resources: &RecoveryResourceCoverage,
) -> io::Result<()> {
    write_budget_range(
        output,
        "input-byte ceiling per input item",
        resources.input_bytes_per_item_by_case,
    )?;
    write_budget_range(
        output,
        "output-byte ceiling per candidate result",
        resources.output_bytes_per_candidate_by_case,
    )?;
    write_budget_range(
        output,
        "work-byte ceiling per Case",
        resources.work_bytes_per_case,
    )?;
    write_budget_range(
        output,
        "candidate task-identity byte ceiling per Case",
        resources.candidate_task_identity_bytes_per_case,
    )?;
    write_budget_range(
        output,
        "transform-proposal identity byte ceiling per Case",
        resources.transform_proposal_identity_bytes_per_case,
    )?;
    write_budget_range(
        output,
        "transform-proposal association ceiling per Case",
        resources.transform_proposal_associations_per_case,
    )?;
    write_budget_range(
        output,
        "parent-link ceiling per Case",
        resources.parent_links_per_case,
    )?;
    write_budget_range(
        output,
        "lineage-work ceiling per Case",
        resources.lineage_work_per_case,
    )?;
    write_budget_range(
        output,
        "record-discovery work ceiling per Case",
        resources.record_phase_work_per_case,
    )?;
    write_budget_range(
        output,
        "context-alias ceiling per Case",
        resources.context_aliases_per_case,
    )?;
    write_budget_range(
        output,
        "pending-origin-link ceiling per Case",
        resources.pending_origin_links_per_case,
    )?;
    write_budget_range(
        output,
        "recursion depth cap per Case",
        resources.depth_limit_per_case,
    )?;
    Ok(())
}

fn write_recovery_resource_totals(
    output: &mut File,
    resources: &RecoveryResourceCoverage,
) -> io::Result<()> {
    writeln!(
        output,
        "Recovery work across independent Cases: {} bytes charged, {} bytes remaining",
        resources.work_bytes_charged_total, resources.work_bytes_remaining_total
    )?;
    writeln!(
        output,
        "Recovery retained-index work across independent Cases: {} units charged, {} units remaining",
        resources.case_index_work_units_charged_total,
        resources.case_index_work_units_remaining_total
    )?;
    writeln!(
        output,
        "Recovery record-discovery work across independent Cases: {} operations charged, {} operations remaining",
        resources.record_phase_work_charged_total, resources.record_phase_work_remaining_total
    )?;
    writeln!(
        output,
        "Recovery candidate task-identity bytes across independent Cases: {} charged, {} remaining",
        resources.candidate_task_identity_bytes_charged_total,
        resources.candidate_task_identity_bytes_remaining_total
    )?;
    writeln!(
        output,
        "Recovery transform-proposal identity bytes across independent Cases: {} charged, {} remaining",
        resources.transform_proposal_identity_bytes_charged_total,
        resources.transform_proposal_identity_bytes_remaining_total
    )?;
    writeln!(
        output,
        "Recovery transform-proposal associations across independent Cases: {} charged, {} remaining",
        resources.transform_proposal_associations_charged_total,
        resources.transform_proposal_associations_remaining_total
    )?;
    writeln!(
        output,
        "Recovery parent links across independent Cases: {} retained, {} remaining",
        resources.parent_links_retained_total, resources.parent_links_remaining_total
    )?;
    writeln!(
        output,
        "Recovery lineage work across independent Cases: {} operations charged, {} operations remaining",
        resources.lineage_work_charged_total, resources.lineage_work_remaining_total
    )?;
    writeln!(
        output,
        "Recovery context aliases across independent Cases: {} retained, {} remaining",
        resources.context_aliases_retained_total, resources.context_aliases_remaining_total
    )?;
    writeln!(
        output,
        "Recovery pending origin links across independent Cases: {} retained, {} remaining",
        resources.pending_origin_links_retained_total,
        resources.pending_origin_links_remaining_total
    )?;
    Ok(())
}

fn write_budget_range(output: &mut File, name: &str, range: PerCaseBudgetRange) -> io::Result<()> {
    match (range.minimum, range.maximum) {
        (Some(minimum), Some(maximum)) if minimum == maximum => {
            writeln!(output, "Recovery {name}: {minimum}")
        }
        (Some(minimum), Some(maximum)) => {
            writeln!(
                output,
                "Recovery {name}: {minimum} to {maximum} (varies by Case)"
            )
        }
        _ => writeln!(output, "Recovery {name}: not applicable (0 Cases)"),
    }
}

fn write_artifact_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    write_artifact_counts(output, summary)?;
    write_artifact_categories(output, summary)?;
    write_artifact_scope(output, summary)
}

fn write_artifact_counts(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    let artifacts = summary.discovery.artifacts;
    writeln!(
        output,
        "Artifact discovery within retained supported-transport flow Cases, bounded unordered source/scope/IP-pair cohorts, and known TShark object types: {}",
        summary.discovery.status
    )?;
    writeln!(
        output,
        "Artifact references selected: {}; retained: {}; omitted: {}; same-origin references suppressed: {}",
        artifacts.references_selected,
        artifacts.references_retained,
        artifacts.references_omitted,
        artifacts.same_origin_references_suppressed
    )?;
    writeln!(
        output,
        "Unique artifact files retained: {}",
        artifacts.unique_artifacts_retained
    )?;
    writeln!(
        output,
        "Unique artifact bytes retained: {}",
        artifacts.artifact_bytes_retained
    )?;
    writeln!(
        output,
        "Provenance bytes retained: {}",
        artifacts.provenance_bytes_retained
    )?;
    writeln!(
        output,
        "Candidate bytes omitted: {}",
        artifacts.candidate_bytes_omitted
    )?;
    writeln!(
        output,
        "Duplicate exact-byte references grouped: {}",
        artifacts.duplicate_byte_references_grouped
    )
}

fn write_artifact_categories(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    let artifacts = summary.discovery.artifacts;
    writeln!(
        output,
        "Native complete HTTP bodies: {}",
        artifacts.native_http_body_references_retained
    )?;
    writeln!(
        output,
        "FTP transfer candidates: {}",
        artifacts.native_ftp_candidate_references_retained
    )?;
    writeln!(
        output,
        "Recovered artifact references retained: {}",
        artifacts.recovered_artifact_references_retained
    )?;
    writeln!(
        output,
        "Exported artifacts: {}",
        summary.discovery.artifacts.unique_artifacts_retained
    )
}

fn write_artifact_scope(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    writeln!(
        output,
        "Coverage: native objects selected within retained supported-transport flow Cases and bounded unordered source/scope/IP-pair cohorts, plus available TShark object types"
    )?;
    writeln!(
        output,
        "FTP candidates are labeled as candidates because TCP connection boundaries do not prove file boundaries"
    )?;
    writeln!(
        output,
        "Cohorts group unordered source/scope/IP pairs; other cross-flow relationships are not tested"
    )?;
    writeln!(output, "TShark packet provenance is not reported")?;
    writeln!(
        output,
        "Native origins use direct packet ranges and explicit evidence references; graph edges are not traversed"
    )?;
    writeln!(
        output,
        "Artifact policy: at most {} files, {} artifact bytes, {} provenance entries, and {} provenance bytes",
        summary.discovery.limits.artifacts,
        summary.discovery.limits.artifact_bytes,
        summary.discovery.limits.provenance_entries,
        summary.discovery.limits.provenance_bytes
    )?;
    Ok(())
}

fn write_tshark_status(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    let tshark_complete = tshark_is_complete(summary.tshark, summary.tshark_error);
    writeln!(
        output,
        "TShark completion policy: {}",
        if summary.completion.tshark_required {
            "required"
        } else {
            "optional enrichment"
        }
    )?;
    writeln!(
        output,
        "TShark export: {}",
        if tshark_complete {
            "complete"
        } else {
            "partial"
        }
    )?;
    writeln!(
        output,
        "TShark objects exported: {}",
        summary.tshark.objects_exported
    )?;
    writeln!(
        output,
        "TShark duplicate objects skipped: {}",
        summary.tshark.duplicates
    )?;
    writeln!(output, "TShark objects skipped: {}", summary.tshark.skipped)?;
    writeln!(
        output,
        "TShark unsafe entries skipped: {}",
        summary.tshark.unsafe_entries_skipped
    )?;
    if let Some(budget) = summary.tshark.export_budget {
        writeln!(
            output,
            "TShark temporary-object budget: {} bytes and {} files; the 50 ms polling scan may overshoot before stopping the process group",
            budget.temporary_bytes, budget.temporary_files
        )?;
        writeln!(
            output,
            "TShark object-directory scan: {} entries inspected against the {}-file ceiling; the first over-budget entry is counted",
            summary.tshark.scan_entries, budget.temporary_files
        )?;
        if let Some(usage) = summary.tshark.export_usage {
            writeln!(
                output,
                "TShark temporary output observed: {} bytes and {} files; latest scan complete: {}",
                usage.temporary_bytes_peak,
                usage.temporary_files_peak,
                usage.temporary_scan_complete
            )?;
            writeln!(
                output,
                "TShark temporary tree entries observed: {} of {} allowed (file ceiling plus {} protocol directories)",
                usage.temporary_tree_entries_peak,
                budget.temporary_files + usage.protocol_directory_count,
                usage.protocol_directory_count
            )?;
        }
    } else {
        writeln!(output, "TShark temporary-object budget: not run")?;
    }
    if let Some(error) = summary.tshark_error {
        writeln!(output, "TShark issue: {}", summary_text(error))?;
    }
    for issue in &summary.tshark.issues {
        writeln!(output, "TShark issue: {}", summary_text(issue))?;
    }
    Ok(())
}

fn write_artifact_contents(
    output: &mut File,
    collection: &mut ArtifactCollection,
) -> Result<(), Box<dyn Error>> {
    if collection.coverage().native_http_body_references_retained == 0 {
        writeln!(output, "\nNo complete HTTP bodies were recovered")?;
    }
    let mut artifact_files_by_node = HashMap::<(String, u64), String>::new();
    collection.visit_artifact_origins(|file_name, _, provenance| {
        if let (Some(case_id), Some(node)) = (&provenance.case_id, &provenance.node) {
            artifact_files_by_node
                .entry((case_id.clone(), node.id))
                .or_insert_with(|| file_name.to_owned());
        }
        Ok(())
    })?;
    let mut last_file = None::<String>;
    collection.visit_artifact_origins(|file_name, byte_length, provenance| {
        if provenance.category == "tshark_object" {
            return Ok(());
        }
        if last_file.as_deref() != Some(file_name) {
            writeln!(output, "  {file_name}  {byte_length} bytes")?;
            last_file = Some(file_name.to_owned());
        }
        let kind = provenance
            .description
            .as_deref()
            .or_else(|| provenance.node.as_ref().map(|node| node.kind.as_str()))
            .unwrap_or("recovered artifact");
        writeln!(output, "    Type: {}", summary_text(kind))?;
        if provenance.category == "recovered_artifact" {
            writeln!(output, "    Category: recovered artifact")?;
            write_archive_context(output, provenance, &artifact_files_by_node)?;
            let validation = provenance
                .selection
                .as_ref()
                .and_then(|selection| selection.get("validated_as"))
                .and_then(serde_json::Value::as_str);
            if let Some(validation) = validation {
                writeln!(
                    output,
                    "    Structural validation: validated as {}",
                    summary_text(validation)
                )?;
            } else {
                writeln!(output, "    Structural validation: not recorded")?;
            }
        }
        if !provenance.signature_candidates.is_empty() {
            writeln!(
                output,
                "    Signature candidates retained: {}; details in manifest.json",
                provenance.signature_candidates.len()
            )?;
        }
        write_artifact_flow_tuples(output, provenance)?;
        let (packet_label, packets) = artifact_packet_summary(provenance);
        writeln!(output, "    {packet_label}: {packets}")?;
        Ok(())
    })?;
    Ok(())
}

fn write_archive_context(
    output: &mut File,
    provenance: &ArtifactProvenance,
    artifact_files_by_node: &HashMap<(String, u64), String>,
) -> io::Result<()> {
    let Some(selection) = provenance.selection.as_ref() else {
        return Ok(());
    };
    let Some(archive_path) = selection
        .get("archive_path")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };

    writeln!(
        output,
        "    Archive member path: {}",
        summary_text(archive_path)
    )?;
    let Some(parent) = selection
        .get("archive_parent")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let parent_id = parent.get("node_id").and_then(serde_json::Value::as_u64);
    let published_parent = if let (Some(parent_id), Some(case_id)) =
        (parent_id, provenance.case_id.as_ref())
        && let Some(artifact_name) = artifact_files_by_node.get(&(case_id.clone(), parent_id))
    {
        writeln!(
            output,
            "    Parent archive artifact: {} (node {parent_id})",
            summary_text(artifact_name.as_str())
        )?;
        true
    } else {
        false
    };
    if !published_parent
        && let (Some(parent_id), Some(kind)) = (
            parent_id,
            parent.get("kind").and_then(serde_json::Value::as_str),
        )
    {
        writeln!(
            output,
            "    Parent archive: {} node {parent_id}",
            summary_text(kind)
        )?;
    }
    // A nested archive has both a published filename and its own path in the outer archive
    if let (Some(parent_id), Some(member_path)) = (
        parent_id,
        parent
            .get("member_path")
            .and_then(serde_json::Value::as_str),
    ) {
        writeln!(
            output,
            "    Parent archive member: {} (node {parent_id})",
            summary_text(member_path)
        )?;
    }
    Ok(())
}

fn write_artifact_flow_tuples(
    output: &mut File,
    provenance: &ArtifactProvenance,
) -> io::Result<()> {
    let flows = provenance
        .flow
        .as_ref()
        .map_or(provenance.supporting_flows.as_slice(), std::slice::from_ref);
    if flows.is_empty() {
        return Ok(());
    }

    writeln!(
        output,
        "    Capture-level indexed flow tuples; no MAC/device or application-session attribution:"
    )?;
    for flow in flows {
        let flow_label = flow
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .map_or_else(
                || "Flow index not recorded".to_owned(),
                |id| format!("Flow {id}"),
            );
        let protocol = match flow.get("protocol").and_then(serde_json::Value::as_u64) {
            Some(6) => "TCP".to_owned(),
            Some(17) => "UDP".to_owned(),
            Some(protocol) => format!("IP protocol {protocol}"),
            None => "IP protocol not recorded".to_owned(),
        };
        let endpoint_a = flow
            .get("endpoint_a")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not recorded");
        let port_a = flow
            .get("port_a")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "not recorded".to_owned(), |port| port.to_string());
        let endpoint_b = flow
            .get("endpoint_b")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not recorded");
        let port_b = flow
            .get("port_b")
            .and_then(serde_json::Value::as_u64)
            .map_or_else(|| "not recorded".to_owned(), |port| port.to_string());
        writeln!(
            output,
            "      {flow_label}: {protocol} {endpoint_a}:{port_a} ↔ {endpoint_b}:{port_b}"
        )?;
    }
    Ok(())
}

pub(super) fn write_tshark_contents(
    output: &mut File,
    summary: &mut Summary<'_>,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "TShark email messages (IMF): {}",
        summary.tshark.imf_objects_exported
    )?;
    if summary
        .discovery
        .artifacts
        .tshark_object_references_retained
        != 0
    {
        writeln!(
            output,
            "\nTShark object observations (including exact-byte duplicates linked to existing artifacts):"
        )?;
        summary
            .artifacts
            .visit_artifact_origins(|file_name, byte_length, provenance| {
                if provenance.category != "tshark_object" {
                    return Ok(());
                }
                let protocol = provenance
                    .selection
                    .as_ref()
                    .and_then(|selection| selection.get("protocol"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                writeln!(output, "  {file_name}  {byte_length} bytes")?;
                writeln!(output, "    Protocol: {protocol}")?;
                Ok(())
            })?;
    }
    Ok(())
}

pub(super) fn summary_text(value: &str) -> String {
    const MAXIMUM_BYTES: usize = 512;

    let mut safe = String::new();
    for character in value.chars() {
        for encoded in character.escape_default() {
            if safe.len() + encoded.len_utf8() > MAXIMUM_BYTES {
                while safe.len() + '…'.len_utf8() > MAXIMUM_BYTES {
                    safe.pop();
                }
                safe.push('…');
                return safe;
            }
            safe.push(encoded);
        }
    }
    safe
}

pub(super) fn artifact_packet_summary(provenance: &ArtifactProvenance) -> (&'static str, String) {
    if let Some(ranges) = provenance
        .selection
        .as_ref()
        .and_then(|selection| selection.get("source_ranges"))
        .and_then(serde_json::Value::as_array)
    {
        let packets = ranges
            .iter()
            .filter_map(|range| range.get("packet"))
            .filter_map(serde_json::Value::as_u64)
            .collect::<BTreeSet<_>>();
        return (
            "Packets for exact selected bytes",
            format_packet_ranges(packets),
        );
    }

    let packets = provenance.node.as_ref().map_or_else(BTreeSet::new, |node| {
        node.ranges
            .iter()
            .filter_map(|range| range.packet)
            .collect()
    });
    ("Packets", format_packet_ranges(packets))
}

fn format_packet_ranges(packets: BTreeSet<u64>) -> String {
    if packets.is_empty() {
        return String::from("not recorded");
    }

    let mut ranges = Vec::new();
    let mut iterator = packets.into_iter();
    let Some(mut start) = iterator.next() else {
        return String::from("not recorded");
    };
    let mut end = start;
    for packet in iterator {
        if end.checked_add(1) == Some(packet) {
            end = packet;
            continue;
        }
        ranges.push(packet_range(start, end));
        start = packet;
        end = packet;
    }
    ranges.push(packet_range(start, end));
    ranges.join(", ")
}

fn packet_range(start: u64, end: u64) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}
