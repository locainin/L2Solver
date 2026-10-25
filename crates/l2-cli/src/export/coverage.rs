//! Account for source, search, resource, and extraction completion coverage

use super::{
    artifact_collection::{ArtifactCoverage, ArtifactLimits},
    evidence::EvidenceCoverage,
    summary::summary_text,
    tshark_objects,
};
use crate::workbench;
use serde::{Deserialize, Serialize};
use std::{error::Error, io};

macro_rules! merge_coverage_counts {
    ($target:ident, $source:ident; $($field:ident),+ $(,)?) => {
        $(
            $target.$field = coverage_add($target.$field, $source.$field)?;
        )+
    };
}

pub(super) struct ExportCompletion {
    pub(super) complete: bool,
    pub(super) incomplete_components: Vec<IncompleteComponent>,
    pub(super) tshark_required: bool,
}

#[derive(Serialize)]
pub(super) struct IncompleteComponent {
    pub(super) component: &'static str,
    pub(super) reason: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct DiscoveryCoverage {
    pub(super) scope: &'static str,
    pub(super) status: &'static str,
    pub(super) flow_cases_processed: u64,
    pub(super) limits: ArtifactLimits,
    pub(super) artifacts: ArtifactCoverage,
    pub(super) recovery: RecoveryCoverage,
    pub(super) evidence: EvidenceCoverage,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryCoverage {
    pub(super) flow_cases: u64,
    pub(super) cohort_cases: u64,
    pub(super) flow_cases_with_incomplete_case_evidence_collection: u64,
    pub(super) cohort_cases_with_incomplete_case_evidence_collection: u64,
    pub(super) flow_cases_with_incomplete_discovery_input_coverage: u64,
    pub(super) cohort_cases_with_incomplete_discovery_input_coverage: u64,
    pub(super) flow_cases_with_non_exhaustive_search: u64,
    pub(super) cohort_cases_with_non_exhaustive_search: u64,
    pub(super) flow_cases_with_incomplete_report_details: u64,
    pub(super) cohort_cases_with_incomplete_report_details: u64,
    pub(super) omitted_framing_input_runs: u64,
    pub(super) omitted_record_input_frames: u64,
    pub(super) candidates: u64,
    pub(super) complete_negative_transform_searches: u64,
    pub(super) validated_artifacts: u64,
    pub(super) omissions: u64,
    pub(super) cycle_skips: u64,
    pub(super) resources: RecoveryResourceCoverage,
}

impl RecoveryCoverage {
    pub(super) fn merge(&mut self, other: &Self) -> Result<(), Box<dyn Error>> {
        let mut merged = *self;
        merge_coverage_counts!(
            merged,
            other;
            flow_cases,
            cohort_cases,
            flow_cases_with_incomplete_case_evidence_collection,
            cohort_cases_with_incomplete_case_evidence_collection,
            flow_cases_with_incomplete_discovery_input_coverage,
            cohort_cases_with_incomplete_discovery_input_coverage,
            flow_cases_with_non_exhaustive_search,
            cohort_cases_with_non_exhaustive_search,
            flow_cases_with_incomplete_report_details,
            cohort_cases_with_incomplete_report_details,
            omitted_framing_input_runs,
            omitted_record_input_frames,
            candidates,
            complete_negative_transform_searches,
            validated_artifacts,
            omissions,
            cycle_skips,
        );
        merged.resources.merge(&other.resources)?;
        *self = merged;
        Ok(())
    }

    pub(super) fn record(
        &mut self,
        outcome: &workbench::RecoveryRunSummary,
        kind: RecoveryCaseKind,
    ) -> Result<(), Box<dyn Error>> {
        match kind {
            RecoveryCaseKind::Flow => self.flow_cases = coverage_add(self.flow_cases, 1)?,
            RecoveryCaseKind::Cohort => self.cohort_cases = coverage_add(self.cohort_cases, 1)?,
        }
        self.record_status_counts(outcome, kind)?;
        self.record_discovery_input_omissions(outcome)?;
        self.candidates = coverage_add(self.candidates, u64::try_from(outcome.candidate_count)?)?;
        self.complete_negative_transform_searches = coverage_add(
            self.complete_negative_transform_searches,
            u64::try_from(outcome.complete_negative_transform_searches)?,
        )?;
        self.validated_artifacts = coverage_add(
            self.validated_artifacts,
            u64::try_from(outcome.validated_artifact_count)?,
        )?;
        self.omissions = coverage_add(self.omissions, u64::try_from(outcome.omissions.len())?)?;
        self.cycle_skips = coverage_add(self.cycle_skips, u64::try_from(outcome.cycle_skips)?)?;
        self.resources.record(&outcome.resources)?;
        Ok(())
    }

    fn record_status_counts(
        &mut self,
        outcome: &workbench::RecoveryRunSummary,
        kind: RecoveryCaseKind,
    ) -> Result<(), Box<dyn Error>> {
        let discovery = outcome.discovery;
        let statuses = [
            outcome.case_evidence_collection_complete,
            discovery.input_coverage_complete,
            discovery.search_exhaustive_within_plan,
            discovery.report_details_complete,
        ];
        let incomplete = match kind {
            RecoveryCaseKind::Flow => [
                &mut self.flow_cases_with_incomplete_case_evidence_collection,
                &mut self.flow_cases_with_incomplete_discovery_input_coverage,
                &mut self.flow_cases_with_non_exhaustive_search,
                &mut self.flow_cases_with_incomplete_report_details,
            ],
            RecoveryCaseKind::Cohort => [
                &mut self.cohort_cases_with_incomplete_case_evidence_collection,
                &mut self.cohort_cases_with_incomplete_discovery_input_coverage,
                &mut self.cohort_cases_with_non_exhaustive_search,
                &mut self.cohort_cases_with_incomplete_report_details,
            ],
        };
        for (count, complete) in incomplete.into_iter().zip(statuses) {
            if !complete {
                *count = coverage_add(*count, 1)?;
            }
        }
        Ok(())
    }

    fn record_discovery_input_omissions(
        &mut self,
        outcome: &workbench::RecoveryRunSummary,
    ) -> Result<(), Box<dyn Error>> {
        for omission in &outcome.omissions {
            match omission {
                workbench::RecoveryOmission::FramingDiscoveryInputs { omitted_runs, .. } => {
                    self.omitted_framing_input_runs = coverage_add(
                        self.omitted_framing_input_runs,
                        u64::try_from(*omitted_runs)?,
                    )?;
                }
                workbench::RecoveryOmission::RecordDiscoveryInputs { omitted_frames, .. } => {
                    self.omitted_record_input_frames = coverage_add(
                        self.omitted_record_input_frames,
                        u64::try_from(*omitted_frames)?,
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) const fn is_complete(&self) -> bool {
        self.flow_cases_with_incomplete_case_evidence_collection == 0
            && self.cohort_cases_with_incomplete_case_evidence_collection == 0
            && self.flow_cases_with_incomplete_discovery_input_coverage == 0
            && self.cohort_cases_with_incomplete_discovery_input_coverage == 0
            && self.flow_cases_with_non_exhaustive_search == 0
            && self.cohort_cases_with_non_exhaustive_search == 0
            && self.flow_cases_with_incomplete_report_details == 0
            && self.cohort_cases_with_incomplete_report_details == 0
            && self.omitted_framing_input_runs == 0
            && self.omitted_record_input_frames == 0
            && self.omissions == 0
    }
}

#[derive(Clone, Copy)]
pub(super) enum RecoveryCaseKind {
    Flow,
    Cohort,
}

/// Exact resource budgets and work totals summed across analyzed Cases
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryResourceCoverage {
    pub(super) recovery_cases: u64,
    pub(super) input_bytes_per_item_by_case: PerCaseBudgetRange,
    pub(super) output_bytes_per_candidate_by_case: PerCaseBudgetRange,
    pub(super) work_bytes_per_case: PerCaseBudgetRange,
    pub(super) work_bytes_charged_total: u64,
    pub(super) work_bytes_remaining_total: u64,
    pub(super) case_index_work_units_per_case: PerCaseBudgetRange,
    pub(super) case_index_work_units_charged_total: u64,
    pub(super) case_index_work_units_remaining_total: u64,
    pub(super) record_phase_work_per_case: PerCaseBudgetRange,
    pub(super) record_phase_work_charged_total: u64,
    pub(super) record_phase_work_remaining_total: u64,
    pub(super) candidate_task_identity_bytes_per_case: PerCaseBudgetRange,
    pub(super) candidate_task_identity_bytes_charged_total: u64,
    pub(super) candidate_task_identity_bytes_remaining_total: u64,
    pub(super) transform_proposal_identity_bytes_per_case: PerCaseBudgetRange,
    pub(super) transform_proposal_identity_bytes_charged_total: u64,
    pub(super) transform_proposal_identity_bytes_remaining_total: u64,
    pub(super) transform_proposal_associations_per_case: PerCaseBudgetRange,
    pub(super) transform_proposal_associations_charged_total: u64,
    pub(super) transform_proposal_associations_remaining_total: u64,
    pub(super) parent_links_per_case: PerCaseBudgetRange,
    pub(super) parent_links_retained_total: u64,
    pub(super) parent_links_remaining_total: u64,
    pub(super) lineage_work_per_case: PerCaseBudgetRange,
    pub(super) lineage_work_charged_total: u64,
    pub(super) lineage_work_remaining_total: u64,
    pub(super) context_aliases_per_case: PerCaseBudgetRange,
    pub(super) context_aliases_retained_total: u64,
    pub(super) context_aliases_remaining_total: u64,
    pub(super) pending_origin_links_per_case: PerCaseBudgetRange,
    pub(super) pending_origin_links_retained_total: u64,
    pub(super) pending_origin_links_remaining_total: u64,
    pub(super) depth_limit_per_case: PerCaseBudgetRange,
}

impl RecoveryResourceCoverage {
    pub(super) fn has_single_case_ranges(&self) -> bool {
        self.recovery_cases == 1
            && [
                &self.input_bytes_per_item_by_case,
                &self.output_bytes_per_candidate_by_case,
                &self.work_bytes_per_case,
                &self.case_index_work_units_per_case,
                &self.record_phase_work_per_case,
                &self.candidate_task_identity_bytes_per_case,
                &self.transform_proposal_identity_bytes_per_case,
                &self.transform_proposal_associations_per_case,
                &self.parent_links_per_case,
                &self.lineage_work_per_case,
                &self.context_aliases_per_case,
                &self.pending_origin_links_per_case,
                &self.depth_limit_per_case,
            ]
            .into_iter()
            .all(PerCaseBudgetRange::is_single_case)
    }

    fn merge(&mut self, other: &Self) -> Result<(), Box<dyn Error>> {
        let mut merged = *self;
        merge_coverage_counts!(
            merged,
            other;
            recovery_cases,
            work_bytes_charged_total,
            work_bytes_remaining_total,
            case_index_work_units_charged_total,
            case_index_work_units_remaining_total,
            record_phase_work_charged_total,
            record_phase_work_remaining_total,
            candidate_task_identity_bytes_charged_total,
            candidate_task_identity_bytes_remaining_total,
            transform_proposal_identity_bytes_charged_total,
            transform_proposal_identity_bytes_remaining_total,
            transform_proposal_associations_charged_total,
            transform_proposal_associations_remaining_total,
            parent_links_retained_total,
            parent_links_remaining_total,
            lineage_work_charged_total,
            lineage_work_remaining_total,
            context_aliases_retained_total,
            context_aliases_remaining_total,
            pending_origin_links_retained_total,
            pending_origin_links_remaining_total,
        );
        merged
            .input_bytes_per_item_by_case
            .merge(&other.input_bytes_per_item_by_case);
        merged
            .output_bytes_per_candidate_by_case
            .merge(&other.output_bytes_per_candidate_by_case);
        merged.work_bytes_per_case.merge(&other.work_bytes_per_case);
        merged
            .case_index_work_units_per_case
            .merge(&other.case_index_work_units_per_case);
        merged
            .record_phase_work_per_case
            .merge(&other.record_phase_work_per_case);
        merged
            .candidate_task_identity_bytes_per_case
            .merge(&other.candidate_task_identity_bytes_per_case);
        merged
            .transform_proposal_identity_bytes_per_case
            .merge(&other.transform_proposal_identity_bytes_per_case);
        merged
            .transform_proposal_associations_per_case
            .merge(&other.transform_proposal_associations_per_case);
        merged
            .parent_links_per_case
            .merge(&other.parent_links_per_case);
        merged
            .lineage_work_per_case
            .merge(&other.lineage_work_per_case);
        merged
            .context_aliases_per_case
            .merge(&other.context_aliases_per_case);
        merged
            .pending_origin_links_per_case
            .merge(&other.pending_origin_links_per_case);
        merged
            .depth_limit_per_case
            .merge(&other.depth_limit_per_case);
        *self = merged;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PerCaseBudgetRange {
    pub(super) minimum: Option<u64>,
    pub(super) maximum: Option<u64>,
}

impl PerCaseBudgetRange {
    const fn is_single_case(&self) -> bool {
        matches!((self.minimum, self.maximum), (Some(minimum), Some(maximum)) if minimum <= maximum)
    }

    fn merge(&mut self, other: &Self) {
        self.minimum = match (self.minimum, other.minimum) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        self.maximum = match (self.maximum, other.maximum) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
    }

    fn record(&mut self, value: u64) {
        self.minimum = Some(self.minimum.map_or(value, |current| current.min(value)));
        self.maximum = Some(self.maximum.map_or(value, |current| current.max(value)));
    }
}

impl RecoveryResourceCoverage {
    fn record(
        &mut self,
        resources: &workbench::RecoveryResourceSummary,
    ) -> Result<(), Box<dyn Error>> {
        self.recovery_cases = coverage_add(self.recovery_cases, 1)?;
        self.record_limits(resources)?;
        self.record_work_totals(resources)?;
        self.record_identity_resources(resources)?;
        self.record_retained_resource_totals(resources)?;
        Ok(())
    }

    fn record_limits(
        &mut self,
        resources: &workbench::RecoveryResourceSummary,
    ) -> Result<(), Box<dyn Error>> {
        self.input_bytes_per_item_by_case
            .record(u64::try_from(resources.max_input_bytes)?);
        self.output_bytes_per_candidate_by_case
            .record(u64::try_from(resources.max_output_bytes)?);
        self.work_bytes_per_case
            .record(u64::try_from(resources.max_work_bytes)?);
        self.candidate_task_identity_bytes_per_case
            .record(u64::try_from(resources.max_candidate_task_identity_bytes)?);
        self.transform_proposal_identity_bytes_per_case
            .record(u64::try_from(
                resources.max_transform_proposal_identity_bytes,
            )?);
        self.transform_proposal_associations_per_case
            .record(u64::try_from(
                resources.max_transform_proposal_associations,
            )?);
        self.parent_links_per_case
            .record(u64::try_from(resources.max_parent_links)?);
        self.lineage_work_per_case
            .record(u64::try_from(resources.max_lineage_work)?);
        self.record_phase_work_per_case
            .record(u64::try_from(resources.max_record_phase_work)?);
        self.context_aliases_per_case
            .record(u64::try_from(resources.max_context_aliases)?);
        self.pending_origin_links_per_case
            .record(u64::try_from(resources.max_pending_origin_links)?);
        self.depth_limit_per_case
            .record(u64::try_from(resources.max_depth)?);
        Ok(())
    }

    fn record_work_totals(
        &mut self,
        resources: &workbench::RecoveryResourceSummary,
    ) -> Result<(), Box<dyn Error>> {
        self.work_bytes_charged_total = coverage_add(
            self.work_bytes_charged_total,
            u64::try_from(resources.work_charged_bytes)?,
        )?;
        self.work_bytes_remaining_total = coverage_add(
            self.work_bytes_remaining_total,
            u64::try_from(resources.work_remaining_bytes)?,
        )?;
        self.case_index_work_units_per_case
            .record(u64::try_from(resources.max_case_index_work_units)?);
        self.case_index_work_units_charged_total = coverage_add(
            self.case_index_work_units_charged_total,
            u64::try_from(resources.case_index_work_units_charged)?,
        )?;
        self.case_index_work_units_remaining_total = coverage_add(
            self.case_index_work_units_remaining_total,
            u64::try_from(resources.case_index_work_units_remaining)?,
        )?;
        self.record_phase_work_charged_total = coverage_add(
            self.record_phase_work_charged_total,
            u64::try_from(resources.record_phase_work_charged)?,
        )?;
        self.record_phase_work_remaining_total = coverage_add(
            self.record_phase_work_remaining_total,
            u64::try_from(resources.record_phase_work_remaining)?,
        )?;
        Ok(())
    }

    fn record_identity_resources(
        &mut self,
        resources: &workbench::RecoveryResourceSummary,
    ) -> Result<(), Box<dyn Error>> {
        self.candidate_task_identity_bytes_charged_total = coverage_add(
            self.candidate_task_identity_bytes_charged_total,
            u64::try_from(resources.candidate_task_identity_bytes_charged)?,
        )?;
        self.candidate_task_identity_bytes_remaining_total = coverage_add(
            self.candidate_task_identity_bytes_remaining_total,
            u64::try_from(resources.candidate_task_identity_bytes_remaining)?,
        )?;
        self.transform_proposal_identity_bytes_charged_total = coverage_add(
            self.transform_proposal_identity_bytes_charged_total,
            u64::try_from(resources.transform_proposal_identity_bytes_charged)?,
        )?;
        self.transform_proposal_identity_bytes_remaining_total = coverage_add(
            self.transform_proposal_identity_bytes_remaining_total,
            u64::try_from(resources.transform_proposal_identity_bytes_remaining)?,
        )?;
        Ok(())
    }

    fn record_retained_resource_totals(
        &mut self,
        resources: &workbench::RecoveryResourceSummary,
    ) -> Result<(), Box<dyn Error>> {
        self.transform_proposal_associations_charged_total = coverage_add(
            self.transform_proposal_associations_charged_total,
            u64::try_from(resources.transform_proposal_associations_charged)?,
        )?;
        self.transform_proposal_associations_remaining_total = coverage_add(
            self.transform_proposal_associations_remaining_total,
            u64::try_from(resources.transform_proposal_associations_remaining)?,
        )?;
        self.parent_links_retained_total = coverage_add(
            self.parent_links_retained_total,
            u64::try_from(resources.parent_links_retained)?,
        )?;
        self.parent_links_remaining_total = coverage_add(
            self.parent_links_remaining_total,
            u64::try_from(resources.parent_links_remaining)?,
        )?;
        self.lineage_work_charged_total = coverage_add(
            self.lineage_work_charged_total,
            u64::try_from(resources.lineage_work_charged)?,
        )?;
        self.lineage_work_remaining_total = coverage_add(
            self.lineage_work_remaining_total,
            u64::try_from(resources.lineage_work_remaining)?,
        )?;
        self.context_aliases_retained_total = coverage_add(
            self.context_aliases_retained_total,
            u64::try_from(resources.context_aliases_retained)?,
        )?;
        self.context_aliases_remaining_total = coverage_add(
            self.context_aliases_remaining_total,
            u64::try_from(resources.context_aliases_remaining)?,
        )?;
        self.pending_origin_links_retained_total = coverage_add(
            self.pending_origin_links_retained_total,
            u64::try_from(resources.pending_origin_links_retained)?,
        )?;
        self.pending_origin_links_remaining_total = coverage_add(
            self.pending_origin_links_remaining_total,
            u64::try_from(resources.pending_origin_links_remaining)?,
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct ExportCompletionInputs<'a> {
    pub(super) coverage: &'a workbench::full_source::FullSourceCoverage,
    pub(super) artifacts: ArtifactCoverage,
    pub(super) recovery: &'a RecoveryCoverage,
    pub(super) tshark_required: bool,
    pub(super) tshark: &'a tshark_objects::Collection,
    pub(super) tshark_error: Option<&'a str>,
    pub(super) blocking_limitations: u64,
    pub(super) evidence: EvidenceCoverage,
}

pub(super) fn export_completion(inputs: &ExportCompletionInputs<'_>) -> ExportCompletion {
    let ExportCompletionInputs {
        coverage,
        artifacts,
        recovery,
        tshark_required,
        tshark,
        tshark_error,
        blocking_limitations,
        evidence,
    } = *inputs;
    let flows_complete = flow_analysis_complete(coverage);
    let cohorts_complete = cohort_analysis_complete(coverage);
    let recovery_complete = recovery.is_complete();
    let artifacts_complete = artifacts.references_omitted == 0;
    let evidence_complete = evidence.omitted_cases == 0;
    let tshark_complete = tshark_is_complete(tshark, tshark_error);
    let limitations_complete = blocking_limitations == 0;
    let complete = flows_complete
        && cohorts_complete
        && recovery_complete
        && (!tshark_required || tshark_complete)
        && artifacts_complete
        && evidence_complete
        && limitations_complete;
    let mut incomplete_components = source_incomplete_components(coverage);
    incomplete_components.extend(
        [
            flow_incomplete_component(coverage, flows_complete),
            cohort_incomplete_component(coverage, cohorts_complete),
            recovery_incomplete_component(recovery),
            if tshark_required {
                tshark_incomplete_component(tshark, tshark_error, tshark_complete)
            } else {
                None
            },
            artifact_incomplete_component(artifacts, artifacts_complete),
            evidence_incomplete_component(evidence, evidence_complete),
            blocking_limitations_component(blocking_limitations, limitations_complete),
        ]
        .into_iter()
        .flatten(),
    );
    ExportCompletion {
        complete,
        incomplete_components,
        tshark_required,
    }
}

fn evidence_incomplete_component(
    evidence: EvidenceCoverage,
    complete: bool,
) -> Option<IncompleteComponent> {
    (!complete).then(|| IncompleteComponent {
        component: "case_evidence",
        reason: format!(
            "{} of {} Case records omitted from evidence.jsonl ({} encoded bytes omitted; {} byte aggregate budget)",
            evidence.omitted_cases,
            evidence.selected_cases,
            evidence.omitted_bytes,
            evidence.budget_bytes
        ),
    })
}

fn source_incomplete_components(
    coverage: &workbench::full_source::FullSourceCoverage,
) -> Vec<IncompleteComponent> {
    let mut components = Vec::new();
    let collection = coverage.source.collection_summary;
    if l2_workbench::capture_collection::reports_incomplete_collection(collection) {
        let mut reasons = Vec::new();
        if collection.incomplete_sections != 0 {
            reasons.push(format!(
                "{} incomplete collection sections",
                collection.incomplete_sections
            ));
        }
        if collection.packet_block_packets_dropped != 0 {
            reasons.push(format!(
                "{} packets reported dropped between obsolete Packet Blocks",
                collection.packet_block_packets_dropped
            ));
        }
        if collection.packet_blocks_with_unavailable_drop_count != 0 {
            reasons.push(format!(
                "{} obsolete Packet Blocks have unavailable drop counts",
                collection.packet_blocks_with_unavailable_drop_count
            ));
        }
        components.push(IncompleteComponent {
            component: "source_collection",
            reason: reasons.join("; "),
        });
    }
    components
}

fn flow_incomplete_component(
    coverage: &workbench::full_source::FullSourceCoverage,
    complete: bool,
) -> Option<IncompleteComponent> {
    (!complete).then(|| IncompleteComponent {
        component: "flow_analysis",
        reason: format!(
            "{} incomplete flows, {} omitted records, and {} range-omission flows",
            coverage.analysis.incomplete_flows,
            coverage.analysis.omitted_flow_records,
            coverage.analysis.range_omission_flows
        ),
    })
}

fn cohort_incomplete_component(
    coverage: &workbench::full_source::FullSourceCoverage,
    complete: bool,
) -> Option<IncompleteComponent> {
    if complete {
        return None;
    }
    let reason = coverage.cohort_analysis.map_or_else(
        || String::from("cohort analysis was not run"),
        |cohorts| {
            format!(
                "{} incomplete groups, {} split groups, {} omitted records, {} singleton chunks skipped, and {} oversized flows skipped",
                cohorts.incomplete_groups,
                cohorts.split_groups,
                cohorts.omitted_records,
                cohorts.singleton_chunks_skipped,
                cohorts.oversized_flows_skipped
            )
        },
    );
    Some(IncompleteComponent {
        component: "cohort_analysis",
        reason,
    })
}

fn recovery_incomplete_component(recovery: &RecoveryCoverage) -> Option<IncompleteComponent> {
    (!recovery.is_complete()).then(|| IncompleteComponent {
        component: "recovery",
        reason: format!(
            "{} flow Cases with incomplete Case evidence collection, {} with incomplete discovery input coverage, {} with non-exhaustive search, and {} with incomplete report details; {} cohort Cases with incomplete Case evidence collection, {} with incomplete discovery input coverage, {} with non-exhaustive search, and {} with incomplete report details; {} framing input runs and {} record input frames omitted, {} total recovery omissions",
            recovery.flow_cases_with_incomplete_case_evidence_collection,
            recovery.flow_cases_with_incomplete_discovery_input_coverage,
            recovery.flow_cases_with_non_exhaustive_search,
            recovery.flow_cases_with_incomplete_report_details,
            recovery.cohort_cases_with_incomplete_case_evidence_collection,
            recovery.cohort_cases_with_incomplete_discovery_input_coverage,
            recovery.cohort_cases_with_non_exhaustive_search,
            recovery.cohort_cases_with_incomplete_report_details,
            recovery.omitted_framing_input_runs,
            recovery.omitted_record_input_frames,
            recovery.omissions,
        ),
    })
}

fn tshark_incomplete_component(
    tshark: &tshark_objects::Collection,
    tshark_error: Option<&str>,
    complete: bool,
) -> Option<IncompleteComponent> {
    if complete {
        return None;
    }
    let reason = tshark_error.map_or_else(
        || {
            format!(
                "{} issue(s), {} object(s) skipped",
                tshark.issues.len(),
                tshark.skipped
            )
        },
        summary_text,
    );
    Some(IncompleteComponent {
        component: "tshark_export",
        reason,
    })
}

fn artifact_incomplete_component(
    artifacts: ArtifactCoverage,
    complete: bool,
) -> Option<IncompleteComponent> {
    (!complete).then(|| IncompleteComponent {
        component: "artifact_retention",
        reason: format!(
            "{} artifact references omitted",
            artifacts.references_omitted
        ),
    })
}

fn blocking_limitations_component(
    blocking_limitations: u64,
    complete: bool,
) -> Option<IncompleteComponent> {
    (!complete).then(|| IncompleteComponent {
        component: "blocking_limitations",
        reason: format!("{blocking_limitations} blocking limitations; see limitations.txt"),
    })
}

pub(super) fn tshark_is_complete(
    collection: &tshark_objects::Collection,
    error: Option<&str>,
) -> bool {
    error.is_none()
        && collection.issues.is_empty()
        && !collection.scan_limit_reached
        && collection.export_status == Some(workbench::ObjectExportStatus::Complete)
}

pub(super) const fn discovery_coverage(
    coverage: &workbench::full_source::FullSourceCoverage,
    artifacts: ArtifactCoverage,
    limits: ArtifactLimits,
    recovery: &RecoveryCoverage,
    tshark_complete: bool,
    evidence: EvidenceCoverage,
) -> DiscoveryCoverage {
    let complete = flow_analysis_complete(coverage)
        && cohort_analysis_complete(coverage)
        && recovery.is_complete()
        && tshark_complete
        && artifacts.references_omitted == 0
        && evidence.omitted_cases == 0;
    DiscoveryCoverage {
        scope: "retained_supported_transport_flow_cases_bounded_unordered_source_scope_ip_pair_cohorts_and_known_tshark_object_types",
        status: if complete { "complete" } else { "partial" },
        flow_cases_processed: coverage.analysis.flows,
        limits,
        artifacts,
        recovery: *recovery,
        evidence,
    }
}

pub(super) const fn flow_analysis_complete(
    coverage: &workbench::full_source::FullSourceCoverage,
) -> bool {
    coverage.analysis.incomplete_flows == 0
        && coverage.analysis.omitted_flow_records == 0
        && coverage.analysis.range_omission_flows == 0
        && coverage.analysis.omitted_tcp_records == 0
        && coverage.analysis.omitted_fragments == 0
        && coverage.analysis.omitted_sequence_ranges == 0
        && coverage.analysis.omitted_tcp_bytes == 0
        && coverage.analysis.omitted_tcp_observations == 0
        && coverage.analysis.omitted_fragment_bytes == 0
        && coverage.analysis.omitted_fragment_observations == 0
        && coverage.analysis.unmeasured_omitted_ranges == 0
        && coverage.analysis.omitted_state_observations == 0
        && reconstruction_is_complete(
            &coverage
                .analysis
                .supplementary_pages
                .reconstruction_omissions,
        )
        && !l2_workbench::capture_collection::reports_incomplete_collection(
            coverage.source.collection_summary,
        )
}

pub(super) const fn flow_reconstruction_coverage(
    coverage: &workbench::full_source::FullSourceCoverage,
) -> workbench::full_source::ReconstructionOmissionCoverage {
    workbench::full_source::ReconstructionOmissionCoverage {
        cases: coverage.analysis.flows,
        cases_with_omissions: coverage.analysis.reconstruction_omission_flows,
        omitted_tcp_records: coverage.analysis.omitted_tcp_records,
        omitted_fragments: coverage.analysis.omitted_fragments,
        omitted_sequence_ranges: coverage.analysis.omitted_sequence_ranges,
        omitted_tcp_bytes: coverage.analysis.omitted_tcp_bytes,
        omitted_tcp_observations: coverage.analysis.omitted_tcp_observations,
        omitted_fragment_bytes: coverage.analysis.omitted_fragment_bytes,
        omitted_fragment_observations: coverage.analysis.omitted_fragment_observations,
        unmeasured_omitted_ranges: coverage.analysis.unmeasured_omitted_ranges,
        omitted_state_observations: coverage.analysis.omitted_state_observations,
    }
}

pub(super) const fn reconstruction_is_complete(
    coverage: &workbench::full_source::ReconstructionOmissionCoverage,
) -> bool {
    coverage.omitted_tcp_records == 0
        && coverage.omitted_fragments == 0
        && coverage.omitted_sequence_ranges == 0
        && coverage.omitted_tcp_bytes == 0
        && coverage.omitted_tcp_observations == 0
        && coverage.omitted_fragment_bytes == 0
        && coverage.omitted_fragment_observations == 0
        && coverage.unmeasured_omitted_ranges == 0
        && coverage.omitted_state_observations == 0
}

pub(super) fn retention_limit_names(
    limits: &[l2_workbench::reconstruction::RecordRetentionLimit],
) -> String {
    let names = limits
        .iter()
        .map(|limit| match limit {
            l2_workbench::reconstruction::RecordRetentionLimit::Frames => "frames",
            l2_workbench::reconstruction::RecordRetentionLimit::Bytes => "bytes",
            l2_workbench::reconstruction::RecordRetentionLimit::Units => "units",
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        String::from("none reported")
    } else {
        names.join(", ")
    }
}

pub(super) const fn cohort_analysis_complete(
    coverage: &workbench::full_source::FullSourceCoverage,
) -> bool {
    let Some(cohorts) = &coverage.cohort_analysis else {
        return false;
    };
    cohorts.incomplete_groups == 0
        && cohorts.complete_groups == cohorts.multi_flow_groups
        && cohorts.split_groups == 0
        && cohorts.incomplete_chunks == 0
        && cohorts.omitted_records == 0
        && cohorts.singleton_chunks_skipped == 0
        && cohorts.oversized_flows_skipped == 0
        && reconstruction_is_complete(&coverage.cohort_reconstruction)
}

pub(super) fn coverage_add(value: u64, increment: u64) -> Result<u64, Box<dyn Error>> {
    value
        .checked_add(increment)
        .ok_or_else(|| io::Error::other("export recovery coverage count overflow").into())
}
