use super::{
    ArtifactCoverage, ArtifactLimits, DiscoveryCoverage, ExportCompletionInputs, RecoveryCaseKind,
    RecoveryCoverage, discovery_coverage, export_completion, flow_analysis_complete,
    tshark_objects, write_reconstruction_omissions, write_recovery_status,
};
use crate::workbench::{
    RecoveryOmission, RecoveryResourceSummary, RecoveryRunSummary,
    full_source::{
        FlowAnalysisCoverage, FullSourceCoverage, ReconstructionOmissionCoverage, SourceCoverage,
        SupplementaryPageCoverage,
    },
};
use std::{collections::BTreeMap, error::Error, fs::File};

const INPUT_COVERAGE_INCOMPLETE: [bool; 3] = [false, true, true];
const SEARCH_NON_EXHAUSTIVE: [bool; 3] = [true, false, true];
const REPORT_DETAILS_INCOMPLETE: [bool; 3] = [true, true, false];
const INPUT_AND_SEARCH_INCOMPLETE: [bool; 3] = [false, false, true];
const ALL_DISCOVERY_STATUS_COMPLETE: [bool; 3] = [true, true, true];

#[test]
fn writes_exact_tcp_fragment_and_unmeasured_range_omission_totals() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("summary.txt");
    let coverage = ReconstructionOmissionCoverage {
        cases: 5,
        cases_with_omissions: 2,
        omitted_tcp_records: 3,
        omitted_fragments: 2,
        omitted_sequence_ranges: 5,
        omitted_tcp_bytes: 23,
        omitted_tcp_observations: 11,
        omitted_fragment_bytes: 13,
        omitted_fragment_observations: 2,
        omitted_state_observations: 7,
        unmeasured_omitted_ranges: 4,
    };
    let mut output = File::create(&path)?;

    write_reconstruction_omissions(&mut output, "Flow", coverage, true)?;

    let summary = std::fs::read_to_string(path)?;
    assert_eq!(
        summary.trim_end(),
        "Flow reconstruction omissions: 3 TCP records, 2 fragments, 5 ranges, 23 TCP byte positions affected by omitted observations or rejected ranges, 11 TCP observations, 13 fragment byte positions affected by omitted observations or rejected ranges, 2 fragment observations, 7 state observations, 4 unmeasured ranges (in 2 of 5 Cases)"
    );
    Ok(())
}

#[test]
fn supplementary_reconstruction_omissions_make_flow_analysis_incomplete() {
    let mut coverage = FullSourceCoverage {
        source: SourceCoverage {
            source_id: String::new(),
            bytes: 0,
            packet_records: 0,
            supported_transport_records: 0,
            packets_without_supported_transport: 0,
            collection_summary: l2_pcap::CollectionSummary::default(),
        },
        analysis: FlowAnalysisCoverage {
            supplementary_pages: SupplementaryPageCoverage {
                pages: 1,
                reconstruction_omissions: ReconstructionOmissionCoverage {
                    cases: 1,
                    cases_with_omissions: 1,
                    omitted_sequence_ranges: 1,
                    omitted_tcp_bytes: 1,
                    omitted_tcp_observations: 1,
                    ..ReconstructionOmissionCoverage::default()
                },
                ..SupplementaryPageCoverage::default()
            },
            ..FlowAnalysisCoverage::default()
        },
        cohort_reconstruction: ReconstructionOmissionCoverage::default(),
        cohort_analysis: None,
    };

    assert!(!flow_analysis_complete(&coverage));

    coverage
        .analysis
        .supplementary_pages
        .reconstruction_omissions = ReconstructionOmissionCoverage {
        cases: 1,
        ..ReconstructionOmissionCoverage::default()
    };
    assert!(flow_analysis_complete(&coverage));
}

#[test]
fn packets_outside_transport_discovery_do_not_fail_requested_extraction() {
    let mut coverage = clean_full_source_coverage();
    coverage.source.packets_without_supported_transport = 1;

    let completion = export_completion(&ExportCompletionInputs {
        coverage: &coverage,
        artifacts: ArtifactCoverage::default(),
        recovery: &RecoveryCoverage::default(),
        tshark_required: false,
        tshark: &tshark_objects::Collection::default(),
        tshark_error: None,
        blocking_limitations: 0,
        evidence: super::EvidenceCoverage::default(),
    });

    assert!(completion.complete);
    assert!(completion.incomplete_components.is_empty());
}

#[test]
fn optional_tshark_failure_keeps_native_completion_successful() {
    let coverage = clean_full_source_coverage();
    let completion = export_completion(&ExportCompletionInputs {
        coverage: &coverage,
        artifacts: ArtifactCoverage::default(),
        recovery: &RecoveryCoverage::default(),
        tshark_required: false,
        tshark: &tshark_objects::Collection::default(),
        tshark_error: Some("TShark executable not found: tshark"),
        blocking_limitations: 0,
        evidence: super::EvidenceCoverage::default(),
    });

    assert!(completion.complete);
    assert!(completion.incomplete_components.is_empty());
}

#[test]
fn required_tshark_failure_reports_an_incomplete_component() {
    let coverage = clean_full_source_coverage();
    let completion = export_completion(&ExportCompletionInputs {
        coverage: &coverage,
        artifacts: ArtifactCoverage::default(),
        recovery: &RecoveryCoverage::default(),
        tshark_required: true,
        tshark: &tshark_objects::Collection::default(),
        tshark_error: Some("TShark executable not found: tshark"),
        blocking_limitations: 0,
        evidence: super::EvidenceCoverage::default(),
    });

    assert!(!completion.complete);
    assert!(completion.incomplete_components.iter().any(|component| {
        component.component == "tshark_export" && component.reason.contains("not found")
    }));
}

#[test]
fn required_tshark_success_allows_native_completion() {
    let coverage = clean_full_source_coverage();
    let collection = tshark_objects::Collection {
        export_status: Some(crate::workbench::ObjectExportStatus::Complete),
        ..tshark_objects::Collection::default()
    };
    let completion = export_completion(&ExportCompletionInputs {
        coverage: &coverage,
        artifacts: ArtifactCoverage::default(),
        recovery: &RecoveryCoverage::default(),
        tshark_required: true,
        tshark: &collection,
        tshark_error: None,
        blocking_limitations: 0,
        evidence: super::EvidenceCoverage::default(),
    });

    assert!(completion.complete);
    assert!(completion.incomplete_components.is_empty());
}

#[test]
fn recovery_coverage_preserves_input_search_and_report_detail_statuses()
-> Result<(), Box<dyn Error>> {
    let coverage = recovery_status_coverage()?;
    assert_recovery_status_counts(&coverage);
    let manifest = serde_json::to_value(coverage)?;
    assert_serialized_flow_and_cohort_statuses(&manifest);
    assert_json_u64(&manifest, "omitted_framing_input_runs", 2);
    assert_json_u64(&manifest, "omitted_record_input_frames", 3);
    assert_json_u64(&manifest, "validated_artifacts", 3);
    assert!(manifest.get("reconstruction_complete").is_none());
    Ok(())
}

fn recovery_status_coverage() -> Result<RecoveryCoverage, Box<dyn Error>> {
    let mut coverage = RecoveryCoverage::default();
    let mut input_partial =
        recovery_run_summary(INPUT_COVERAGE_INCOMPLETE, 3, 1, 0, &flow_resource_totals())?;
    input_partial.omissions = vec![
        RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some("source".to_owned()),
            omitted_runs: 2,
            reason_counts: BTreeMap::default(),
        },
        RecoveryOmission::RecordDiscoveryInputs {
            source_id: Some("source".to_owned()),
            omitted_frames: 3,
            reason_counts: BTreeMap::default(),
            examples: Vec::new(),
        },
    ];
    coverage.record(&input_partial, RecoveryCaseKind::Flow)?;

    let mut search_partial =
        recovery_run_summary(SEARCH_NON_EXHAUSTIVE, 2, 1, 0, &flow_resource_totals())?;
    search_partial
        .omissions
        .push(RecoveryOmission::FramingDiscoveryAnalysis {
            source_id: "source".to_owned(),
            search_exhaustive_within_plan: false,
            report_details_complete: true,
            omitted_candidates: 1,
            omitted_hypothesis_details: 0,
            omitted_candidate_details: 0,
            omitted_alias_candidates: 0,
            detail_incomplete_runs: 0,
            omitted_frame_examples: 0,
        });
    coverage.record(&search_partial, RecoveryCaseKind::Flow)?;

    let mut details_partial = recovery_run_summary(
        REPORT_DETAILS_INCOMPLETE,
        1,
        1,
        0,
        &cohort_resource_totals(),
    )?;
    details_partial
        .omissions
        .push(RecoveryOmission::RecordDiscoveryAnalysis {
            source_id: "source".to_owned(),
            search_exhaustive_within_plan: true,
            report_details_complete: false,
            omitted_candidates: Some(0),
            omitted_survivors: 0,
            omitted_falsification_examples: 1,
            omitted_field_checks: 0,
            omitted_pair_checks: 0,
            omitted_length_checks: 0,
        });
    coverage.record(&details_partial, RecoveryCaseKind::Cohort)?;
    Ok(coverage)
}

fn assert_recovery_status_counts(coverage: &RecoveryCoverage) {
    assert_eq!((coverage.flow_cases, coverage.cohort_cases), (2, 1));
    assert_eq!(
        coverage.flow_cases_with_incomplete_discovery_input_coverage,
        1
    );
    assert_eq!(coverage.flow_cases_with_non_exhaustive_search, 1);
    assert_eq!(coverage.flow_cases_with_incomplete_report_details, 0);
    assert_eq!(
        coverage.cohort_cases_with_incomplete_discovery_input_coverage,
        0
    );
    assert_eq!(coverage.cohort_cases_with_non_exhaustive_search, 0);
    assert_eq!(coverage.cohort_cases_with_incomplete_report_details, 1);
    assert_eq!(
        (
            coverage.omitted_framing_input_runs,
            coverage.omitted_record_input_frames,
            coverage.validated_artifacts
        ),
        (2, 3, 3)
    );
}

#[test]
fn writes_parent_and_lineage_resource_totals() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("summary.txt");
    let mut coverage = RecoveryCoverage::default();
    let mut outcome = recovery_run_summary(
        INPUT_AND_SEARCH_INCOMPLETE,
        3,
        1,
        1,
        &flow_resource_totals(),
    )?;
    outcome.omissions = vec![
        RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some("source".to_owned()),
            omitted_runs: 1,
            reason_counts: BTreeMap::default(),
        },
        RecoveryOmission::FramingDiscoveryAnalysis {
            source_id: "source".to_owned(),
            search_exhaustive_within_plan: false,
            report_details_complete: true,
            omitted_candidates: 1,
            omitted_hypothesis_details: 0,
            omitted_candidate_details: 0,
            omitted_alias_candidates: 0,
            detail_incomplete_runs: 0,
            omitted_frame_examples: 0,
        },
    ];
    let expected_omission_count = u64::try_from(outcome.omissions.len())?;
    coverage.record(&outcome, RecoveryCaseKind::Flow)?;
    assert_eq!(coverage.omissions, expected_omission_count);
    let mut output = File::create(&path)?;

    write_recovery_status(&mut output, &coverage)?;

    let summary = std::fs::read_to_string(path)?;
    assert!(summary.contains("Default recovery Case evidence collection: 1 complete, 0 incomplete flow Cases; not applicable (no cohort Cases)"));
    assert!(summary.contains("Recovery parent-link ceiling per Case: 40"));
    assert!(summary.contains("Default recovery discovery input coverage: 0 complete, 1 incomplete flow Cases; not applicable (no cohort Cases); 1 framing input runs and 0 record input frames omitted"));
    assert!(summary.contains("Default recovery search exhaustiveness within the declared plan: 0 exhaustive, 1 non-exhaustive flow Cases; not applicable (no cohort Cases)"));
    assert!(summary.contains("Default recovery report details: 1 complete, 0 incomplete flow Cases; not applicable (no cohort Cases)"));
    assert!(summary.contains("Structurally validated recovery artifacts: 1"));
    assert!(summary.contains(&format!(
        "Recovery omission entries: {expected_omission_count} (one entry may cover multiple omitted inputs or report details)"
    )));
    assert!(summary.contains("Recovery transform-proposal association ceiling per Case: 55"));
    assert!(summary.contains(
        "Recovery transform-proposal associations across independent Cases: 9 charged, 46 remaining"
    ));
    assert!(
        summary
            .contains("Recovery parent links across independent Cases: 7 retained, 33 remaining")
    );
    assert!(summary.contains("Recovery lineage-work ceiling per Case: 50"));
    assert!(summary.contains(
        "Recovery lineage work across independent Cases: 9 operations charged, 41 operations remaining"
    ));
    assert!(summary.contains("Recovery context-alias ceiling per Case: 60"));
    assert!(
        summary.contains(
            "Recovery context aliases across independent Cases: 10 retained, 50 remaining"
        )
    );
    assert!(summary.contains("Recovery pending-origin-link ceiling per Case: 70"));
    assert!(summary.contains(
        "Recovery pending origin links across independent Cases: 11 retained, 59 remaining"
    ));
    assert!(summary.contains("Recovery record-discovery work ceiling per Case: 19"));
    assert!(summary.contains(
        "Recovery record-discovery work across independent Cases: 7 operations charged, 12 operations remaining"
    ));
    Ok(())
}

#[test]
fn writes_complete_negative_transform_search_count() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("summary.txt");
    let mut coverage = RecoveryCoverage::default();
    let mut outcome = recovery_run_summary(
        ALL_DISCOVERY_STATUS_COMPLETE,
        0,
        0,
        0,
        &flow_resource_totals(),
    )?;
    outcome.complete_negative_transform_searches = 4;
    coverage.record(&outcome, RecoveryCaseKind::Flow)?;
    let mut output = File::create(&path)?;

    write_recovery_status(&mut output, &coverage)?;

    let summary = std::fs::read_to_string(path)?;
    assert!(summary.contains("Complete negative transform searches: 4"));
    Ok(())
}

#[test]
fn serializes_per_case_and_aggregate_recovery_resource_totals_in_discovery_manifest()
-> Result<(), Box<dyn Error>> {
    let discovery = DiscoveryCoverage {
        scope: "test_scope",
        status: "partial",
        flow_cases_processed: 1,
        limits: ArtifactLimits::default(),
        artifacts: ArtifactCoverage::default(),
        recovery: recovery_with_flow_and_cohort_totals()?,
        evidence: super::EvidenceCoverage::default(),
    };
    // DiscoveryCoverage is the exact payload serialized under this manifest key
    let manifest = serde_json::json!({"discovery_coverage": discovery});
    let recovery = manifest
        .pointer("/discovery_coverage/recovery")
        .ok_or("discovery recovery status is missing")?;
    assert_serialized_flow_recovery_statuses(recovery);
    assert_json_u64(recovery, "complete_negative_transform_searches", 12);
    let resources = manifest
        .pointer("/discovery_coverage/recovery/resources")
        .ok_or("discovery recovery resources are missing")?;

    assert_discovery_resource_totals(resources);
    Ok(())
}

#[test]
fn incomplete_case_evidence_collection_keeps_discovery_axes_independent()
-> Result<(), Box<dyn Error>> {
    let mut case = l2_workbench::evidence::Case::new();
    case.mark_incomplete("A prior collection result was incomplete")?;
    let summary = crate::workbench::recover_case(&mut case)?;

    assert!(!summary.case_evidence_collection_complete);
    assert!(summary.discovery.input_coverage_complete);
    assert!(summary.discovery.search_exhaustive_within_plan);
    assert!(summary.discovery.report_details_complete);
    assert!(summary.omissions.is_empty());

    let mut coverage = RecoveryCoverage::default();
    coverage.record(&summary, RecoveryCaseKind::Flow)?;

    assert!(!coverage.is_complete());
    assert_eq!(
        coverage.flow_cases_with_incomplete_case_evidence_collection,
        1
    );
    assert_eq!(
        coverage.flow_cases_with_incomplete_discovery_input_coverage,
        0
    );
    assert_eq!(coverage.flow_cases_with_non_exhaustive_search, 0);
    assert_eq!(coverage.flow_cases_with_incomplete_report_details, 0);
    Ok(())
}

#[test]
fn validation_work_omission_keeps_recovery_coverage_partial() -> Result<(), Box<dyn Error>> {
    let mut coverage = RecoveryCoverage::default();
    let mut summary = recovery_run_summary(
        ALL_DISCOVERY_STATUS_COMPLETE,
        1,
        0,
        0,
        &flow_resource_totals(),
    )?;
    summary
        .omissions
        .push(RecoveryOmission::ArtifactValidation {
            input_node_id: 14,
            reason: l2_workbench::artifact::ArtifactResourceOmissionReason::InputTooLarge {
                length: 12,
                maximum: 8,
            },
        });
    coverage.record(&summary, RecoveryCaseKind::Flow)?;

    assert!(!coverage.is_complete());
    assert_eq!(coverage.omissions, 1);
    assert_eq!(coverage.validated_artifacts, 0);
    assert_eq!(coverage.flow_cases_with_non_exhaustive_search, 0);
    assert_eq!(coverage.flow_cases_with_incomplete_report_details, 0);
    assert_eq!(
        coverage.flow_cases_with_incomplete_discovery_input_coverage,
        0
    );

    let source = clean_full_source_coverage();
    let discovery = discovery_coverage(
        &source,
        ArtifactCoverage::default(),
        ArtifactLimits::default(),
        &coverage,
        true,
        super::EvidenceCoverage::default(),
    );
    assert_eq!(discovery.status, "partial");

    let manifest = serde_json::to_value(discovery)?;
    let recovery = manifest
        .get("recovery")
        .ok_or("recovery status is missing")?;
    assert_json_u64(recovery, "omissions", 1);
    assert_json_u64(recovery, "validated_artifacts", 0);
    Ok(())
}

fn clean_full_source_coverage() -> FullSourceCoverage {
    FullSourceCoverage {
        source: SourceCoverage {
            source_id: "source".to_owned(),
            bytes: 0,
            packet_records: 0,
            supported_transport_records: 0,
            packets_without_supported_transport: 0,
            collection_summary: l2_pcap::CollectionSummary::default(),
        },
        analysis: FlowAnalysisCoverage::default(),
        cohort_reconstruction: ReconstructionOmissionCoverage::default(),
        cohort_analysis: Some(l2_workbench::store::FlowCohortCoverage::default()),
    }
}

fn recovery_with_flow_and_cohort_totals() -> Result<RecoveryCoverage, Box<dyn Error>> {
    let mut recovery = RecoveryCoverage::default();
    let mut flow =
        recovery_run_summary(INPUT_COVERAGE_INCOMPLETE, 3, 1, 1, &flow_resource_totals())?;
    flow.complete_negative_transform_searches = 5;
    flow.omissions
        .push(RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some("source".to_owned()),
            omitted_runs: 1,
            reason_counts: BTreeMap::default(),
        });
    recovery.record(&flow, RecoveryCaseKind::Flow)?;
    let mut cohort = recovery_run_summary(
        ALL_DISCOVERY_STATUS_COMPLETE,
        1,
        1,
        0,
        &cohort_resource_totals(),
    )?;
    cohort.complete_negative_transform_searches = 7;
    recovery.record(&cohort, RecoveryCaseKind::Cohort)?;
    Ok(recovery)
}

fn recovery_run_summary(
    [
        input_coverage_complete,
        search_exhaustive_within_plan,
        report_details_complete,
    ]: [bool; 3],
    candidate_count: usize,
    validated_artifact_count: usize,
    cycle_skips: usize,
    resources: &RecoveryResourceSummary,
) -> Result<RecoveryRunSummary, Box<dyn Error>> {
    let mut case = l2_workbench::evidence::Case::new();
    let mut summary = crate::workbench::recover_case(&mut case)?;
    summary.discovery.input_coverage_complete = input_coverage_complete;
    summary.discovery.search_exhaustive_within_plan = search_exhaustive_within_plan;
    summary.discovery.report_details_complete = report_details_complete;
    summary.candidate_count = candidate_count;
    summary.validated_artifact_count = validated_artifact_count;
    summary.cycle_skips = cycle_skips;
    summary.resources = *resources;
    Ok(summary)
}

fn assert_serialized_flow_and_cohort_statuses(manifest: &serde_json::Value) {
    for (field, expected) in [
        ("flow_cases", 2),
        ("flow_cases_with_incomplete_discovery_input_coverage", 1),
        ("flow_cases_with_non_exhaustive_search", 1),
        ("flow_cases_with_incomplete_report_details", 0),
        ("cohort_cases_with_incomplete_report_details", 1),
    ] {
        assert_json_u64(manifest, field, expected);
    }
}

fn assert_serialized_flow_recovery_statuses(recovery: &serde_json::Value) {
    for (field, expected) in [
        ("flow_cases", 1),
        ("flow_cases_with_incomplete_case_evidence_collection", 0),
        ("flow_cases_with_incomplete_discovery_input_coverage", 1),
        ("flow_cases_with_non_exhaustive_search", 0),
        ("flow_cases_with_incomplete_report_details", 0),
        ("cohort_cases_with_incomplete_discovery_input_coverage", 0),
    ] {
        assert_json_u64(recovery, field, expected);
    }
}

fn assert_json_u64(value: &serde_json::Value, field: &str, expected: u64) {
    assert_eq!(
        value.get(field).and_then(serde_json::Value::as_u64),
        Some(expected),
        "manifest field {field} has an unexpected value"
    );
}

fn flow_resource_totals() -> RecoveryResourceSummary {
    RecoveryResourceSummary {
        max_input_bytes: 10,
        max_output_bytes: 20,
        max_work_bytes: 30,
        work_charged_bytes: 12,
        work_remaining_bytes: 18,
        max_case_index_work_units: 21,
        case_index_work_units_charged: 9,
        case_index_work_units_remaining: 12,
        max_candidate_task_identity_bytes: 24,
        candidate_task_identity_bytes_charged: 8,
        candidate_task_identity_bytes_remaining: 16,
        max_transform_proposal_identity_bytes: 32,
        transform_proposal_identity_bytes_charged: 12,
        transform_proposal_identity_bytes_remaining: 20,
        max_transform_proposal_associations: 55,
        transform_proposal_associations_charged: 9,
        transform_proposal_associations_remaining: 46,
        max_parent_links: 40,
        parent_links_retained: 7,
        parent_links_remaining: 33,
        max_lineage_work: 50,
        lineage_work_charged: 9,
        lineage_work_remaining: 41,
        max_context_aliases: 60,
        context_aliases_retained: 10,
        context_aliases_remaining: 50,
        max_pending_origin_links: 70,
        pending_origin_links_retained: 11,
        pending_origin_links_remaining: 59,
        max_record_phase_work: 19,
        record_phase_work_charged: 7,
        record_phase_work_remaining: 12,
        max_depth: 4,
    }
}

fn cohort_resource_totals() -> RecoveryResourceSummary {
    RecoveryResourceSummary {
        max_input_bytes: 10,
        max_output_bytes: 20,
        max_work_bytes: 30,
        work_charged_bytes: 4,
        work_remaining_bytes: 26,
        max_case_index_work_units: 21,
        case_index_work_units_charged: 3,
        case_index_work_units_remaining: 18,
        max_candidate_task_identity_bytes: 16,
        candidate_task_identity_bytes_charged: 8,
        candidate_task_identity_bytes_remaining: 8,
        max_transform_proposal_identity_bytes: 24,
        transform_proposal_identity_bytes_charged: 8,
        transform_proposal_identity_bytes_remaining: 16,
        max_transform_proposal_associations: 80,
        transform_proposal_associations_charged: 4,
        transform_proposal_associations_remaining: 76,
        max_parent_links: 40,
        parent_links_retained: 2,
        parent_links_remaining: 38,
        max_lineage_work: 50,
        lineage_work_charged: 3,
        lineage_work_remaining: 47,
        max_context_aliases: 80,
        context_aliases_retained: 4,
        context_aliases_remaining: 76,
        max_pending_origin_links: 90,
        pending_origin_links_retained: 5,
        pending_origin_links_remaining: 85,
        max_record_phase_work: 23,
        record_phase_work_charged: 5,
        record_phase_work_remaining: 18,
        max_depth: 4,
    }
}

fn assert_discovery_resource_totals(resources: &serde_json::Value) {
    assert_per_case_resource_limits(resources);
    assert_aggregate_work_totals(resources);
    assert_aggregate_origin_totals(resources);
}

fn assert_per_case_resource_limits(resources: &serde_json::Value) {
    assert_eq!(
        resources.pointer("/candidate_task_identity_bytes_per_case"),
        Some(&serde_json::json!({"minimum": 16, "maximum": 24}))
    );
    assert_eq!(
        resources.pointer("/transform_proposal_identity_bytes_per_case"),
        Some(&serde_json::json!({"minimum": 24, "maximum": 32}))
    );
    assert_eq!(
        resources.pointer("/parent_links_per_case"),
        Some(&serde_json::json!({"minimum": 40, "maximum": 40}))
    );
    assert_eq!(
        resources.pointer("/transform_proposal_associations_per_case"),
        Some(&serde_json::json!({"minimum": 55, "maximum": 80}))
    );
    assert_eq!(
        resources.pointer("/lineage_work_per_case"),
        Some(&serde_json::json!({"minimum": 50, "maximum": 50}))
    );
    assert_eq!(
        resources.pointer("/context_aliases_per_case"),
        Some(&serde_json::json!({"minimum": 60, "maximum": 80}))
    );
    assert_eq!(
        resources.pointer("/pending_origin_links_per_case"),
        Some(&serde_json::json!({"minimum": 70, "maximum": 90}))
    );
}

fn assert_aggregate_work_totals(resources: &serde_json::Value) {
    assert_eq!(
        resources.pointer("/candidate_task_identity_bytes_charged_total"),
        Some(&16.into())
    );
    assert_eq!(
        resources.pointer("/candidate_task_identity_bytes_remaining_total"),
        Some(&24.into())
    );
    assert_eq!(
        resources.pointer("/transform_proposal_identity_bytes_charged_total"),
        Some(&20.into())
    );
    assert_eq!(
        resources.pointer("/transform_proposal_identity_bytes_remaining_total"),
        Some(&36.into())
    );
    assert_eq!(
        resources.pointer("/transform_proposal_associations_charged_total"),
        Some(&13.into())
    );
    assert_eq!(
        resources.pointer("/transform_proposal_associations_remaining_total"),
        Some(&122.into())
    );
    assert_eq!(
        resources.pointer("/lineage_work_charged_total"),
        Some(&12.into())
    );
    assert_eq!(
        resources.pointer("/lineage_work_remaining_total"),
        Some(&88.into())
    );
    assert_eq!(
        resources.pointer("/case_index_work_units_per_case"),
        Some(&serde_json::json!({"minimum": 21, "maximum": 21}))
    );
    assert_eq!(
        resources.pointer("/case_index_work_units_charged_total"),
        Some(&12.into())
    );
    assert_eq!(
        resources.pointer("/case_index_work_units_remaining_total"),
        Some(&30.into())
    );
    assert_eq!(
        resources.pointer("/record_phase_work_per_case"),
        Some(&serde_json::json!({"minimum": 19, "maximum": 23}))
    );
    assert_eq!(
        resources.pointer("/record_phase_work_charged_total"),
        Some(&12.into())
    );
    assert_eq!(
        resources.pointer("/record_phase_work_remaining_total"),
        Some(&30.into())
    );
}

fn assert_aggregate_origin_totals(resources: &serde_json::Value) {
    assert_eq!(
        resources.pointer("/parent_links_retained_total"),
        Some(&9.into())
    );
    assert_eq!(
        resources.pointer("/parent_links_remaining_total"),
        Some(&71.into())
    );
    assert_eq!(
        resources.pointer("/context_aliases_retained_total"),
        Some(&14.into())
    );
    assert_eq!(
        resources.pointer("/context_aliases_remaining_total"),
        Some(&126.into())
    );
    assert_eq!(
        resources.pointer("/pending_origin_links_retained_total"),
        Some(&16.into())
    );
    assert_eq!(
        resources.pointer("/pending_origin_links_remaining_total"),
        Some(&144.into())
    );
}

#[test]
fn merges_deserialized_recovery_coverage_and_budget_ranges() -> Result<(), Box<dyn Error>> {
    let mut first_value = serde_json::to_value(RecoveryCoverage::default())?;
    first_value["flow_cases"] = 1.into();
    first_value["candidates"] = 3.into();
    first_value["resources"]["recovery_cases"] = 1.into();
    first_value["resources"]["input_bytes_per_item_by_case"] =
        serde_json::json!({"minimum": 128, "maximum": 256});
    first_value["resources"]["work_bytes_charged_total"] = 10.into();

    let mut second_value = serde_json::to_value(RecoveryCoverage::default())?;
    second_value["cohort_cases"] = 1.into();
    second_value["candidates"] = 4.into();
    second_value["resources"]["recovery_cases"] = 1.into();
    second_value["resources"]["input_bytes_per_item_by_case"] =
        serde_json::json!({"minimum": 64, "maximum": 512});
    second_value["resources"]["work_bytes_charged_total"] = 20.into();

    let mut first: RecoveryCoverage = serde_json::from_value(first_value)?;
    let second: RecoveryCoverage = serde_json::from_value(second_value)?;

    first.merge(&second)?;

    assert_eq!((first.flow_cases, first.cohort_cases), (1, 1));
    assert_eq!(first.candidates, 7);
    assert_eq!(first.resources.recovery_cases, 2);
    assert_eq!(first.resources.work_bytes_charged_total, 30);
    assert_eq!(
        serde_json::to_value(first)?["resources"]["input_bytes_per_item_by_case"],
        serde_json::json!({"minimum": 64, "maximum": 512})
    );
    Ok(())
}

#[test]
fn coverage_merge_overflow_keeps_existing_aggregate_unchanged() -> Result<(), Box<dyn Error>> {
    let mut first_value = serde_json::to_value(RecoveryCoverage::default())?;
    first_value["flow_cases"] = 7.into();
    first_value["candidates"] = u64::MAX.into();
    let mut second_value = serde_json::to_value(RecoveryCoverage::default())?;
    second_value["flow_cases"] = 1.into();
    second_value["candidates"] = 1.into();
    let mut first: RecoveryCoverage = serde_json::from_value(first_value)?;
    let second: RecoveryCoverage = serde_json::from_value(second_value)?;
    let before = serde_json::to_value(first)?;

    assert!(first.merge(&second).is_err());
    assert_eq!(serde_json::to_value(first)?, before);
    Ok(())
}
