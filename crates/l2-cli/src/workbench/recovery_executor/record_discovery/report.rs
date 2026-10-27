use super::super::case_scan::{ScanAdmission, case_scan_work_bounds, preflight_scan};
use super::super::diagnostics::{record_cohort_enqueue, record_cohort_omission};
use super::super::discovery::OrderedUnique;
use super::super::evidence::{add_transaction_links, case_evidence_quota};
use super::super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask,
};
use super::analysis::{analyze_strategies, has_survivors, reports as strategy_reports};
use super::collect_input_plan_excluding;
use super::input::{
    RecordCohortKey, RecordCohortOrigin, RecordDiscoveryInputOmissions, RecordDiscoveryPlan,
    RecordFrameInput, apply_input_limits,
};
use super::work::cohort_work_bound;
use l2_workbench::{
    evidence::Case,
    job::RecoveryTransitionStage,
    protocol::{
        RecordDiscoveryPartition, RecordSchema, RecordSchemaDiscoveryReport,
        RecordSchemaMultiStrategyAnalysisReport, RecordSchemaProposalReport,
    },
    recovery::{EnqueueOutcome, RecoveryCandidate, RecoveryError, RecoveryResult},
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

const REPORT_KIND: &str = "recovery_record_discovery_report";
const REPORT_VERSION: u16 = 3;
const STATUS_NO_CANDIDATES: &str = "no_candidates";
const STATUS_HYPOTHESES_FOUND: &str = "hypotheses_found";

#[derive(Clone)]
pub(in crate::workbench::recovery_executor) struct RecordDiscoveryContext {
    key: RecordCohortKey,
    inputs: Vec<RecordFrameInput>,
    application_inputs: Arc<[RecordFrameInput]>,
    sampling: LearningSample,
    omitted_frames: usize,
    eligibility_omissions: RecordDiscoveryInputOmissions,
}

#[derive(Clone, Copy)]
pub(in crate::workbench::recovery_executor) struct PendingRecordSuffix {
    pub(in crate::workbench::recovery_executor) candidate_id: RecoveryCandidateId,
    pub(in crate::workbench::recovery_executor) context_index: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LearningSample {
    SessionPrefix,
    SessionSuffix,
}

impl LearningSample {
    const fn label(self) -> &'static str {
        match self {
            Self::SessionPrefix => "session_prefix",
            Self::SessionSuffix => "session_suffix",
        }
    }
}

#[derive(Default)]
pub(in crate::workbench::recovery_executor) struct RecordSchemaReportLinks {
    reports: OrderedUnique<u64>,
    linked_receipt: Option<u64>,
    linked_count: usize,
}

impl RecordSchemaReportLinks {
    pub(in crate::workbench::recovery_executor) fn contains(&self, report_node_id: u64) -> bool {
        self.reports.contains(&report_node_id)
    }

    pub(in crate::workbench::recovery_executor) fn try_insert(
        &mut self,
        report_node_id: u64,
    ) -> Result<bool, std::collections::TryReserveError> {
        self.reports.try_insert(report_node_id)
    }

    pub(in crate::workbench::recovery_executor) fn pending_for(
        &self,
        receipt_node_id: u64,
    ) -> &[u64] {
        let linked_count = if self.linked_receipt == Some(receipt_node_id) {
            self.linked_count
        } else {
            0
        };
        self.reports
            .as_slice()
            .get(linked_count..)
            .unwrap_or_default()
    }

    pub(in crate::workbench::recovery_executor) fn as_slice(&self) -> &[u64] {
        self.reports.as_slice()
    }

    pub(in crate::workbench::recovery_executor) fn mark_linked(&mut self, receipt_node_id: u64) {
        self.linked_receipt = Some(receipt_node_id);
        self.linked_count = self.reports.as_slice().len();
    }
}

impl RecordDiscoveryContext {
    pub(super) fn matches(
        &self,
        key: &RecordCohortKey,
        inputs: &[RecordFrameInput],
        application_inputs: &[RecordFrameInput],
        omitted_frames: usize,
    ) -> bool {
        self.key == *key
            && self.omitted_frames == omitted_frames
            && self.inputs.len() == inputs.len()
            && self
                .inputs
                .iter()
                .zip(inputs)
                .all(|(stored, incoming)| stored.node_id == incoming.node_id)
            && self.application_inputs.len() == application_inputs.len()
            && self
                .application_inputs
                .iter()
                .zip(application_inputs)
                .all(|(stored, incoming)| stored.node_id == incoming.node_id)
    }
}

#[derive(Default)]
struct SessionPartition {
    basis: &'static str,
    training_count: usize,
    training_session_nodes: Vec<u64>,
    held_out_session_nodes: Vec<u64>,
}

struct RecordAnalysis {
    result: &'static str,
    search_exhaustive_within_plan: bool,
    report_details_complete: bool,
    no_candidate_reason: Option<&'static str>,
    strategy_omission: Option<&'static str>,
    strategy_not_run_reason: Option<&'static str>,
    partition: SessionPartition,
    strategies: Option<RecordSchemaMultiStrategyAnalysisReport>,
}

struct RecordReportOutput {
    context: RecordDiscoveryContext,
    analysis: RecordAnalysis,
    bytes: Vec<u8>,
    work_bound_bytes: usize,
}

struct RecordDiscoveryWorkPlan {
    contexts: Vec<(RecordDiscoveryContext, usize)>,
    origins: Vec<u64>,
    requested_work: usize,
}

fn record_report_bytes(reports: &[RecordReportOutput]) -> Result<usize, RecoveryExecutionError> {
    reports.iter().try_fold(0_usize, |total, report| {
        total.checked_add(report.bytes.len()).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "combined record discovery report size overflowed".to_owned(),
            )
        })
    })
}

fn compact_reports_if_needed(
    reports: &mut [RecordReportOutput],
    max_output_bytes: usize,
) -> Result<bool, RecoveryExecutionError> {
    if record_report_bytes(reports)? <= max_output_bytes {
        return Ok(false);
    }
    for report in reports {
        report.analysis.report_details_complete = false;
        let compact_report =
            build_compact_report(&report.context, &report.analysis, report.work_bound_bytes)?;
        report.bytes = serde_json::to_vec(&compact_report).map_err(|source| {
            operational(
                "compact record discovery report serialization failed",
                source,
            )
        })?;
    }
    Ok(true)
}

impl Executor<'_> {
    fn record_discovery_snapshot(
        &mut self,
    ) -> Result<Option<std::sync::Arc<RecordDiscoveryPlan>>, RecoveryExecutionError> {
        let snapshot = self.policy.record_discovery_snapshot.clone();
        if let Some(snapshot) = &snapshot {
            if !self.charge_record_case_scan(snapshot.scan_work())? {
                self.omissions
                    .extend(super::input_omissions(&snapshot.plan));
                return Ok(None);
            }
            let suffix_bound = snapshot.node_suffix_scan_bound(self.case)?;
            let remaining = self.record_case_scan_remaining()?;
            match preflight_scan(suffix_bound, remaining, || {
                let (matches_case, work) = snapshot.inspect_case_suffix(self.case)?;
                Ok((matches_case, work))
            })? {
                ScanAdmission::Scanned { value: true, work } => {
                    if !self.charge_record_case_scan(work)? {
                        self.omissions
                            .extend(super::input_omissions(&snapshot.plan));
                        return Ok(None);
                    }
                    let snapshot_plan = apply_input_limits(
                        (*snapshot.plan).clone(),
                        self.policy.record_schema_proposal_limits,
                    )?;
                    return Ok(Some(std::sync::Arc::new(snapshot_plan)));
                }
                ScanAdmission::Scanned { value: false, work } => {
                    if !self.charge_record_case_scan(work)? {
                        self.omissions
                            .extend(super::input_omissions(&snapshot.plan));
                        return Ok(None);
                    }
                }
                ScanAdmission::Exhausted { requested } => {
                    self.record_case_scan_exhausted(requested)?;
                    self.omissions
                        .extend(super::input_omissions(&snapshot.plan));
                    return Ok(None);
                }
            }
        }

        let scan_bound = case_scan_work_bounds(self.case)?.record;
        let remaining = self.record_case_scan_remaining()?;
        let derived_discovery = &self.derived_discovery;
        let admission = preflight_scan(scan_bound, remaining, || {
            let plan = collect_input_plan_excluding(self.case, |node_id| {
                derived_discovery.has_context(node_id)
            })?;
            let work = plan.graph_work;
            Ok((std::sync::Arc::new(plan), work))
        })?;
        match admission {
            ScanAdmission::Scanned { value, work } => {
                if self.charge_record_case_scan(work)? {
                    let plan = apply_input_limits(
                        (*value).clone(),
                        self.policy.record_schema_proposal_limits,
                    )?;
                    Ok(Some(std::sync::Arc::new(plan)))
                } else {
                    if let Some(snapshot) = &snapshot {
                        self.omissions
                            .extend(super::input_omissions(&snapshot.plan));
                    }
                    Ok(None)
                }
            }
            ScanAdmission::Exhausted { requested } => {
                self.record_case_scan_exhausted(requested)?;
                if let Some(snapshot) = &snapshot {
                    self.omissions
                        .extend(super::input_omissions(&snapshot.plan));
                }
                Ok(None)
            }
        }
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_record_discovery_if_enabled(
        &mut self,
    ) -> Result<(), RecoveryExecutionError> {
        if self.plan.discover_records {
            self.enqueue_record_discovery()?;
        }
        Ok(())
    }

    fn enqueue_record_discovery(&mut self) -> Result<(), RecoveryExecutionError> {
        let Some(plan) = self.record_discovery_snapshot()? else {
            return Ok(());
        };
        self.enqueue_record_discovery_plan((*plan).clone(), None)
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_relational_record_discovery(
        &mut self,
        key: RecordCohortKey,
        frames: Vec<RecordFrameInput>,
    ) -> Result<(), RecoveryExecutionError> {
        if !self.plan.discover_records || frames.is_empty() {
            return Ok(());
        }
        let mut plan = RecordDiscoveryPlan::default();
        plan.application_cohorts.insert(key.clone(), frames.clone());
        plan.cohorts.insert(key, frames);
        let plan = apply_input_limits(plan, self.policy.record_schema_proposal_limits)?;
        self.enqueue_record_discovery_plan(plan, None)
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_derived_record_discovery(
        &mut self,
        key: RecordCohortKey,
        frames: Vec<(RecoveryCandidateId, RecordFrameInput)>,
    ) -> Result<(), RecoveryExecutionError> {
        if !self.plan.discover_records || frames.is_empty() {
            return Ok(());
        }
        if !matches!(&key.origin, RecordCohortOrigin::Transformed { .. }) {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let mut parent_by_frame = HashMap::new();
        parent_by_frame
            .try_reserve(frames.len())
            .map_err(|source| operational("derived record parent allocation failed", source))?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(frames.len())
            .map_err(|source| operational("derived record input allocation failed", source))?;
        for (parent, frame) in frames {
            if parent_by_frame.insert(frame.node_id, parent).is_some() {
                return Err(RecoveryError::InvariantFailure.into());
            }
            inputs.push(frame);
        }
        let mut plan = RecordDiscoveryPlan::default();
        plan.application_cohorts.insert(key.clone(), inputs.clone());
        plan.cohorts.insert(key, inputs);
        let plan = apply_input_limits(plan, self.policy.record_schema_proposal_limits)?;
        self.enqueue_record_discovery_plan(plan, Some(&parent_by_frame))
    }

    fn enqueue_record_discovery_plan(
        &mut self,
        plan: RecordDiscoveryPlan,
        derived_parents: Option<&HashMap<u64, RecoveryCandidateId>>,
    ) -> Result<(), RecoveryExecutionError> {
        for (source_id, omission) in &plan.omissions {
            for (reason, count) in &omission.reason_counts {
                let input_node_id = omission
                    .examples
                    .iter()
                    .find(|example| example.get("reason").and_then(Value::as_str) == Some(*reason))
                    .and_then(|example| example.get("frame_node_id"))
                    .and_then(Value::as_u64);
                record_cohort_omission(
                    self,
                    RecoveryTransitionStage::Schema,
                    source_id.as_deref(),
                    input_node_id,
                    *count,
                    reason,
                )?;
            }
            if omission.total > 0 {
                self.omissions
                    .push(RecoveryOmission::RecordDiscoveryInputs {
                        source_id: source_id.clone(),
                        omitted_frames: omission.total,
                        reason_counts: omission.reason_counts.clone(),
                        examples: omission.examples.clone(),
                    });
            }
        }
        for (key, frames) in &plan.application_cohorts {
            if matches!(&key.origin, RecordCohortOrigin::Relational { .. }) {
                continue;
            }
            let source_eligibility_omissions = plan
                .omissions
                .get(&Some(key.source_id.clone()))
                .map_or(0, |omission| omission.eligibility_only().total);
            self.collect_relational_frame_samples(
                key,
                frames,
                source_eligibility_omissions == 0,
                source_eligibility_omissions,
            )?;
        }
        let contains_tcp_cohorts = plan
            .cohorts
            .keys()
            .any(|key| matches!(&key.origin, RecordCohortOrigin::TcpMaterialized));
        if contains_tcp_cohorts {
            let contains_immediate_cohorts = plan
                .cohorts
                .keys()
                .any(|key| !matches!(&key.origin, RecordCohortOrigin::TcpMaterialized));
            if contains_immediate_cohorts || self.deferred_record_discovery_plan.is_some() {
                return Err(RecoveryError::InvariantFailure.into());
            }
            self.deferred_record_discovery_plan = Some(plan);
            return Ok(());
        }
        self.enqueue_record_discovery_cohorts(&plan, derived_parents)
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_deferred_record_discovery(
        &mut self,
    ) -> Result<bool, RecoveryExecutionError> {
        let Some(plan) = self.deferred_record_discovery_plan.take() else {
            return Ok(false);
        };
        self.enqueue_record_discovery_cohorts(&plan, None)?;
        Ok(true)
    }

    fn enqueue_record_discovery_cohorts(
        &mut self,
        plan: &RecordDiscoveryPlan,
        derived_parents: Option<&HashMap<u64, RecoveryCandidateId>>,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::RecordDiscovery;
        for (key, inputs) in &plan.cohorts {
            if inputs.is_empty() {
                continue;
            }
            let mut node_ids = Vec::new();
            node_ids.try_reserve_exact(inputs.len()).map_err(|source| {
                operational("record discovery input allocation failed", source)
            })?;
            node_ids.extend(inputs.iter().map(|input| input.node_id));
            let result = if let Some(parents) = derived_parents {
                let mut parent_child_pairs = Vec::new();
                parent_child_pairs
                    .try_reserve_exact(inputs.len())
                    .map_err(|source| {
                        operational("derived record pair allocation failed", source)
                    })?;
                for input in inputs {
                    let parent = parents
                        .get(&input.node_id)
                        .copied()
                        .ok_or(RecoveryError::InvariantFailure)?;
                    parent_child_pairs.push((parent, input.node_id));
                }
                self.coordinator.enqueue_derived_many(
                    self.case,
                    &parent_child_pairs,
                    task.clone(),
                )?
            } else {
                self.coordinator
                    .enqueue_nodes(self.case, &node_ids, task.clone())?
            };
            let candidate_id = super::super::scheduler::enqueue_candidate_id(&result);
            self.record_enqueue(result, &task, &node_ids)?;
            record_cohort_enqueue(
                self,
                RecoveryTransitionStage::Schema,
                &key.source_id,
                &node_ids,
                result,
            )?;
            if let Some(candidate_id) = candidate_id {
                let omitted_frames = plan
                    .cohort_omitted_frames
                    .get(key)
                    .copied()
                    .unwrap_or_default();
                let application_inputs = plan
                    .application_cohorts
                    .get(key)
                    .ok_or(RecoveryError::InvariantFailure)?;
                let eligibility_omissions = plan
                    .omissions
                    .get(&Some(key.source_id.clone()))
                    .map(RecordDiscoveryInputOmissions::eligibility_only)
                    .unwrap_or_default();
                let contexts = self.record_discoveries.entry(candidate_id).or_default();
                if !contexts
                    .iter()
                    .any(|context| context.matches(key, inputs, application_inputs, omitted_frames))
                {
                    contexts.try_reserve(1).map_err(|source| {
                        operational("record discovery context allocation failed", source)
                    })?;
                    contexts.push(RecordDiscoveryContext {
                        key: key.clone(),
                        inputs: inputs.clone(),
                        application_inputs: Arc::from(application_inputs.clone()),
                        sampling: LearningSample::SessionPrefix,
                        omitted_frames,
                        eligibility_omissions,
                    });
                }
            }
        }
        Ok(())
    }

    fn charge_record_case_scan(
        &mut self,
        requested: usize,
    ) -> Result<bool, RecoveryExecutionError> {
        self.charge_record_case_work(requested)
    }

    fn record_case_scan_remaining(&self) -> Result<usize, RecoveryExecutionError> {
        let record_remaining = self
            .policy
            .record_phase_work_limit
            .checked_sub(self.record_phase_work_charged)
            .ok_or(RecoveryError::InvariantFailure)?;
        Ok(record_remaining.min(self.coordinator.remaining_work_bytes()))
    }

    fn record_case_scan_exhausted(
        &mut self,
        requested: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let record_remaining = self
            .policy
            .record_phase_work_limit
            .checked_sub(self.record_phase_work_charged)
            .ok_or(RecoveryError::InvariantFailure)?;
        let (limit, used) = if requested > record_remaining {
            (
                self.policy.record_phase_work_limit,
                self.record_phase_work_charged,
            )
        } else {
            (
                self.policy.resources.max_work_bytes,
                self.coordinator.work_bytes_charged(),
            )
        };
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery,
            input_node_ids: Vec::new(),
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit,
            used,
            requested,
        });
        Ok(())
    }

    pub(in crate::workbench::recovery_executor) fn run_record_discovery(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let proposal_limits = self.policy.record_schema_proposal_limits;
        let work_plan = self.plan_record_discovery_work(candidate_id, proposal_limits)?;
        if !self.charge_work(
            candidate_id,
            &RecoveryTask::RecordDiscovery,
            &work_plan.origins,
            work_plan.requested_work,
        )? {
            return Ok(());
        }
        let mut reports = self.analyze_record_contexts(work_plan.contexts, proposal_limits)?;
        let report_truncated =
            compact_reports_if_needed(&mut reports, self.policy.resources.max_output_bytes)?;
        self.record_report_omissions(&reports, report_truncated);
        let retained_report_bytes = record_report_bytes(&reports)?;
        if !self.check_output(
            candidate_id,
            &RecoveryTask::RecordDiscovery,
            &work_plan.origins,
            retained_report_bytes,
        )? {
            return Ok(());
        }
        let Some(report_nodes) =
            self.retain_record_reports_or_finish_quota(candidate_id, &work_plan.origins, &reports)?
        else {
            return Ok(());
        };
        self.enqueue_retained_report_schemas(&reports, &report_nodes)?;
        self.defer_suffix_fallbacks(candidate_id, &reports)
    }

    fn defer_suffix_fallbacks(
        &mut self,
        candidate_id: RecoveryCandidateId,
        reports: &[RecordReportOutput],
    ) -> Result<(), RecoveryExecutionError> {
        for report in reports {
            let context = &report.context;
            if report.analysis.result != STATUS_NO_CANDIDATES
                || context.sampling != LearningSample::SessionPrefix
                || context.omitted_frames == 0
                || !matches!(context.key.origin, RecordCohortOrigin::TcpMaterialized)
            {
                continue;
            }
            let context_index = self
                .record_discoveries
                .get(&candidate_id)
                .and_then(|contexts| {
                    contexts.iter().position(|stored| {
                        stored.sampling == context.sampling
                            && stored.matches(
                                &context.key,
                                &context.inputs,
                                &context.application_inputs,
                                context.omitted_frames,
                            )
                    })
                })
                .ok_or(RecoveryError::InvariantFailure)?;
            if self.pending_record_suffixes.len() >= self.policy.resources.max_candidates {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task: RecoveryTask::RecordDiscovery,
                    input_node_ids: context.inputs.iter().map(|input| input.node_id).collect(),
                    resource: l2_workbench::recovery::RecoveryResource::CandidateCount,
                    limit: self.policy.resources.max_candidates,
                    used: self.pending_record_suffixes.len(),
                    requested: 1,
                });
                continue;
            }
            self.pending_record_suffixes
                .try_reserve(1)
                .map_err(|source| operational("record suffix queue allocation failed", source))?;
            self.pending_record_suffixes.push_back(PendingRecordSuffix {
                candidate_id,
                context_index,
            });
        }
        Ok(())
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_next_record_suffix(
        &mut self,
    ) -> Result<bool, RecoveryExecutionError> {
        let Some(pending) = self.pending_record_suffixes.pop_front() else {
            return Ok(false);
        };
        let context = self
            .record_discoveries
            .get(&pending.candidate_id)
            .and_then(|contexts| contexts.get(pending.context_index))
            .cloned()
            .ok_or(RecoveryError::InvariantFailure)?;
        // Account for the full-cohort scan before choosing any later observations
        if !self.charge_record_case_work(context.application_inputs.len())? {
            return Ok(true);
        }
        let Some(inputs) = suffix_inputs(&context, self.policy.record_schema_proposal_limits)?
        else {
            return Ok(true);
        };
        let mut node_ids = Vec::new();
        node_ids
            .try_reserve_exact(inputs.len())
            .map_err(|source| operational("record suffix node allocation failed", source))?;
        node_ids.extend(inputs.iter().map(|input| input.node_id));
        let task = RecoveryTask::RecordDiscovery;
        let outcome = self
            .coordinator
            .enqueue_nodes(self.case, &node_ids, task.clone())?;
        let candidate_id = match outcome {
            EnqueueOutcome::Queued(id)
            | EnqueueOutcome::Merged(id)
            | EnqueueOutcome::MergedNeedsContext(id)
            | EnqueueOutcome::CycleSkipped { candidate_id: id } => Some(id),
            EnqueueOutcome::ResourceExhausted { .. } => None,
        };
        self.record_enqueue(outcome, &task, &node_ids)?;
        record_cohort_enqueue(
            self,
            RecoveryTransitionStage::Schema,
            &context.key.source_id,
            &node_ids,
            outcome,
        )?;
        if let Some(candidate_id) = candidate_id {
            let mut later = context;
            later.inputs = inputs;
            later.sampling = LearningSample::SessionSuffix;
            let contexts = self.record_discoveries.entry(candidate_id).or_default();
            if !contexts.iter().any(|existing| {
                existing.sampling == later.sampling
                    && existing.matches(
                        &later.key,
                        &later.inputs,
                        &later.application_inputs,
                        later.omitted_frames,
                    )
            }) {
                contexts.try_reserve(1).map_err(|source| {
                    operational("record discovery context allocation failed", source)
                })?;
                contexts.push(later);
            }
        }
        Ok(true)
    }

    fn plan_record_discovery_work(
        &self,
        candidate_id: RecoveryCandidateId,
        proposal_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    ) -> Result<RecordDiscoveryWorkPlan, RecoveryExecutionError> {
        let contexts = self
            .record_discoveries
            .get(&candidate_id)
            .cloned()
            .ok_or(RecoveryError::InvariantFailure)?;
        let first_context = contexts.first().ok_or(RecoveryError::InvariantFailure)?;
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        let origins = candidate_origins(candidate, first_context)?;
        for context in &contexts {
            if candidate_origins(candidate, context)? != origins {
                return Err(RecoveryError::InvariantFailure.into());
            }
        }
        let mut planned_contexts = Vec::new();
        planned_contexts
            .try_reserve_exact(contexts.len())
            .map_err(|source| operational("record discovery context allocation failed", source))?;
        let mut requested_work = 0_usize;
        for context in contexts {
            let work_bound_bytes =
                cohort_work_bound(&context.key, &context.inputs, proposal_limits).ok_or_else(
                    || {
                        RecoveryExecutionError::InvalidPolicy(
                        "record discovery cohort work bound exceeds this platform's address space"
                            .to_owned(),
                    )
                    },
                )?;
            requested_work = requested_work
                .checked_add(work_bound_bytes)
                .ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "merged record discovery work bound overflowed".to_owned(),
                    )
                })?;
            planned_contexts.push((context, work_bound_bytes));
        }
        Ok(RecordDiscoveryWorkPlan {
            contexts: planned_contexts,
            origins,
            requested_work,
        })
    }

    fn analyze_record_contexts(
        &self,
        contexts: Vec<(RecordDiscoveryContext, usize)>,
        proposal_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    ) -> Result<Vec<RecordReportOutput>, RecoveryExecutionError> {
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(contexts.len())
            .map_err(|source| operational("record discovery report allocation failed", source))?;
        for (context, work_bound_bytes) in contexts {
            let partition = partition_inputs(&context.inputs)?;
            let include_repeated_boundaries =
                !matches!(&context.key.origin, RecordCohortOrigin::TcpMaterialized);
            let analysis = self.analyze_record_cohort(
                &context.inputs,
                partition,
                proposal_limits,
                context.omitted_frames > 0,
                include_repeated_boundaries,
            )?;
            let full_report = build_report(&context, &analysis, work_bound_bytes)?;
            let bytes = serde_json::to_vec(&full_report).map_err(|source| {
                operational("record discovery report serialization failed", source)
            })?;
            reports.push(RecordReportOutput {
                context,
                analysis,
                bytes,
                work_bound_bytes,
            });
        }
        Ok(reports)
    }

    fn record_report_omissions(&mut self, reports: &[RecordReportOutput], report_truncated: bool) {
        for report in reports {
            self.record_analysis_omission(&report.context, &report.analysis);
            if report_truncated {
                let (
                    omitted_input_frames,
                    omitted_schema_proposals,
                    omitted_surviving_schemas,
                    omitted_falsification_details,
                ) = report_detail_counts(&report.analysis, &report.context);
                self.omissions
                    .push(RecoveryOmission::RecordDiscoveryReportDetails {
                        source_id: report.context.key.source_id.clone(),
                        omitted_input_frames,
                        omitted_schema_proposals,
                        omitted_surviving_schemas,
                        omitted_falsification_details,
                    });
            }
        }
    }

    fn retain_record_reports_or_finish_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        reports: &[RecordReportOutput],
    ) -> Result<Option<Vec<u64>>, RecoveryExecutionError> {
        match self.retain_record_reports(candidate_id, origins, reports) {
            Ok(node_ids) => Ok(Some(node_ids)),
            Err(RecoveryExecutionError::Evidence(evidence_error)) => {
                let Some((resource, limit, used)) = case_evidence_quota(self.case, &evidence_error)
                else {
                    return Err(RecoveryExecutionError::Evidence(evidence_error));
                };
                self.finish_record_report_quota(candidate_id, origins, resource, limit, used, 1)?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn enqueue_retained_report_schemas(
        &mut self,
        reports: &[RecordReportOutput],
        report_nodes: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        if reports.len() != report_nodes.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let mut schemas_by_report = Vec::new();
        schemas_by_report
            .try_reserve_exact(reports.len())
            .map_err(|source| operational("record schema selection allocation failed", source))?;
        for report in reports {
            let mut schemas = Vec::<RecordSchema>::new();
            if let Some(strategies) = report.analysis.strategies.as_ref() {
                for strategy in strategy_reports(strategies) {
                    let Some(discovery) = strategy.discovery.as_ref() else {
                        continue;
                    };
                    schemas
                        .try_reserve(discovery.surviving.len())
                        .map_err(|source| {
                            operational("record schema selection allocation failed", source)
                        })?;
                    for hypothesis in &discovery.surviving {
                        if !schemas.contains(&hypothesis.schema) {
                            schemas.push(hypothesis.schema.clone());
                        }
                    }
                }
            }
            schemas_by_report.push(schemas);
        }
        let schema_count = schemas_by_report
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or_default();
        let mut requests = Vec::new();
        let requested_schemas = schema_count.checked_mul(reports.len()).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy("record schema queue size overflowed".to_owned())
        })?;
        requests
            .try_reserve(requested_schemas)
            .map_err(|source| operational("record schema queue allocation failed", source))?;
        for schema_index in 0..schema_count {
            for ((report, report_node), schemas) in
                reports.iter().zip(report_nodes).zip(&schemas_by_report)
            {
                let Some(schema) = schemas.get(schema_index) else {
                    continue;
                };
                Self::append_discovered_record_schema(
                    &report.context,
                    *report_node,
                    schema,
                    &mut requests,
                )?;
            }
        }
        self.defer_record_schema_group(requests)
    }

    fn retain_record_reports(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        reports: &[RecordReportOutput],
    ) -> Result<Vec<u64>, RecoveryExecutionError> {
        self.record_discovery_context_by_report
            .try_reserve(reports.len())
            .map_err(|source| {
                operational("record discovery report-context allocation failed", source)
            })?;
        let node_ids = self.case_transaction_and_finish(candidate_id, |case, identities| {
            let mut node_ids = Vec::new();
            node_ids
                .try_reserve_exact(reports.len())
                .map_err(|source| {
                    operational("record discovery report node allocation failed", source)
                })?;
            for report in reports {
                let details = json!({
                    "representation":"json_blob",
                    "report_schema_version":REPORT_VERSION,
                    "result":report.analysis.result,
                    "search_exhaustive_within_plan":report.analysis.search_exhaustive_within_plan,
                    "report_details_complete":report.analysis.report_details_complete,
                    "input_frame_count":report.context.inputs.len(),
                    "source_id":report.context.key.source_id,
                });
                let node_id =
                    case.add_bytes_node(REPORT_KIND, &report.bytes, Vec::new(), details)?;
                add_transaction_links(
                    case,
                    identities,
                    node_id,
                    origins,
                    "record_discovery_input",
                    l2_workbench::evidence::EvidenceStatus::Unresolved,
                    "This report analyzes these exact materialized frame inputs",
                )?;
                node_ids.push(node_id);
            }
            let result_node = node_ids
                .first()
                .copied()
                .ok_or(RecoveryError::InvariantFailure)?;
            Ok((
                node_ids,
                RecoveryResult::Hypothesis {
                    node_id: result_node,
                },
            ))
        })?;
        if node_ids.len() != reports.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        for (node_id, report) in node_ids.iter().copied().zip(reports) {
            self.record_discovery_context_by_report
                .insert(node_id, report.context.clone());
        }
        Ok(node_ids)
    }

    fn finish_record_report_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        resource: l2_workbench::recovery::RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery,
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested,
        });
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            },
        )
    }

    fn append_discovered_record_schema(
        context: &RecordDiscoveryContext,
        report_node: u64,
        schema: &RecordSchema,
        requests: &mut Vec<(Vec<u64>, l2_workbench::protocol::RecordSchema, u64)>,
    ) -> Result<(), RecoveryExecutionError> {
        if matches!(&context.key.origin, RecordCohortOrigin::Relational { .. }) {
            let mut node_ids = Vec::new();
            node_ids
                .try_reserve_exact(context.application_inputs.len())
                .map_err(|source| {
                    operational("relational record session allocation failed", source)
                })?;
            node_ids.extend(context.application_inputs.iter().map(|input| input.node_id));
            requests
                .try_reserve(1)
                .map_err(|source| operational("record schema queue allocation failed", source))?;
            requests.push((node_ids, schema.clone(), report_node));
            return Ok(());
        }
        for session in context
            .application_inputs
            .chunk_by(|left, right| left.session_node_id == right.session_node_id)
        {
            let mut node_ids = Vec::new();
            node_ids
                .try_reserve_exact(session.len())
                .map_err(|source| operational("record schema session allocation failed", source))?;
            node_ids.extend(session.iter().map(|input| input.node_id));
            requests
                .try_reserve(1)
                .map_err(|source| operational("record schema queue allocation failed", source))?;
            requests.push((node_ids, schema.clone(), report_node));
        }
        Ok(())
    }

    fn analyze_record_cohort(
        &self,
        inputs: &[RecordFrameInput],
        partition: SessionPartition,
        proposal_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
        input_budget_partial: bool,
        include_repeated_boundaries: bool,
    ) -> Result<RecordAnalysis, RecoveryExecutionError> {
        let training_inputs = inputs
            .get(..partition.training_count)
            .ok_or(RecoveryError::InvariantFailure)?;
        let held_out_inputs = inputs
            .get(partition.training_count..)
            .ok_or(RecoveryError::InvariantFailure)?;
        let training = message_refs(self.case, training_inputs)?;
        let held_out = message_refs(self.case, held_out_inputs)?;
        if training.is_empty() {
            return Ok(RecordAnalysis {
                result: STATUS_NO_CANDIDATES,
                search_exhaustive_within_plan: !input_budget_partial,
                report_details_complete: true,
                no_candidate_reason: Some("insufficient_training_messages"),
                strategy_omission: None,
                strategy_not_run_reason: None,
                partition,
                strategies: None,
            });
        }
        let strategies = analyze_strategies(
            &training,
            &held_out,
            proposal_limits,
            include_repeated_boundaries,
        )
        .map_err(invalid_discovery_policy)?;
        let strategy_omission = (include_repeated_boundaries
            && strategies.repeated_boundaries.is_none())
        .then_some("repeated_boundaries_not_run_due_to_shared_limits");
        let strategy_not_run_reason = (!include_repeated_boundaries)
            .then_some("repeated_boundaries_not_requested_for_tcp_materialized_frames");
        let search_exhaustive_within_plan = !input_budget_partial
            && strategy_omission.is_none()
            && strategy_reports(&strategies).all(|report| {
                report.proposal.search_exhaustive_within_plan
                    && report
                        .discovery
                        .as_ref()
                        .is_none_or(|discovery| discovery.search_exhaustive_within_plan)
            });
        let result = if has_survivors(&strategies) {
            STATUS_HYPOTHESES_FOUND
        } else {
            STATUS_NO_CANDIDATES
        };
        let report_details_complete = strategy_reports(&strategies).all(|report| {
            report
                .discovery
                .as_ref()
                .is_none_or(|item| item.report_details_complete)
        });
        let no_candidate_reason = if result == STATUS_NO_CANDIDATES {
            if strategy_reports(&strategies).all(|report| report.proposal.candidate_space.is_none())
            {
                Some("no_structural_candidate_space")
            } else {
                Some("no_schema_survived_strict_parsing")
            }
        } else {
            None
        };
        Ok(RecordAnalysis {
            result,
            search_exhaustive_within_plan,
            report_details_complete,
            no_candidate_reason,
            strategy_omission,
            strategy_not_run_reason,
            partition,
            strategies: Some(strategies),
        })
    }

    fn record_analysis_omission(
        &mut self,
        context: &RecordDiscoveryContext,
        analysis: &RecordAnalysis,
    ) {
        if analysis.search_exhaustive_within_plan && analysis.report_details_complete {
            return;
        }
        let omitted_candidates = analysis.strategies.as_ref().and_then(|strategies| {
            let mut total = 0_usize;
            let mut had_count = false;
            for report in strategy_reports(strategies) {
                let count = report
                    .discovery
                    .as_ref()
                    .and_then(|item| item.unexamined_combinations)
                    .or(report.proposal.omitted_schema_combinations);
                if let Some(count) = count {
                    total = total.checked_add(count)?;
                    had_count = true;
                }
            }
            had_count.then_some(total)
        });
        let (omitted_field_checks, omitted_pair_checks, omitted_length_checks) = analysis
            .strategies
            .as_ref()
            .map_or((0, 0, 0), |strategies| {
                strategy_reports(strategies).fold((0_usize, 0_usize, 0_usize), |totals, report| {
                    (
                        totals
                            .0
                            .saturating_add(report.proposal.omitted_field_checks),
                        totals.1.saturating_add(report.proposal.omitted_pair_checks),
                        totals
                            .2
                            .saturating_add(report.proposal.omitted_length_checks),
                    )
                })
            });
        let (omitted_survivors, omitted_falsification_examples) =
            analysis.strategies.as_ref().map_or((0, 0), |strategies| {
                strategy_reports(strategies).fold((0_usize, 0_usize), |totals, report| {
                    let discovery = report.discovery.as_ref();
                    (
                        totals
                            .0
                            .saturating_add(discovery.map_or(0, |item| item.omitted_survivors)),
                        totals.1.saturating_add(
                            discovery.map_or(0, |item| item.omitted_falsification_examples),
                        ),
                    )
                })
            });
        self.omissions
            .push(RecoveryOmission::RecordDiscoveryAnalysis {
                source_id: context.key.source_id.clone(),
                search_exhaustive_within_plan: analysis.search_exhaustive_within_plan,
                report_details_complete: analysis.report_details_complete,
                omitted_candidates,
                omitted_survivors,
                omitted_falsification_examples,
                omitted_field_checks,
                omitted_pair_checks,
                omitted_length_checks,
            });
    }
}

fn build_compact_report(
    context: &RecordDiscoveryContext,
    analysis: &RecordAnalysis,
    requested_work: usize,
) -> Result<Value, RecoveryExecutionError> {
    let scope = serde_json::from_str::<Value>(&context.key.scope_json)
        .map_err(|source| operational("record discovery scope could not be decoded", source))?;
    let endpoints = serde_json::from_str::<Value>(&context.key.endpoints_json)
        .map_err(|source| operational("record discovery endpoints could not be decoded", source))?;
    let framing_rule = serde_json::from_str::<Value>(&context.key.framing_rule_json)
        .map_err(|source| operational("record discovery rule could not be decoded", source))?;
    let (
        omitted_input_frame_descriptors,
        omitted_schema_proposals,
        omitted_surviving_schemas,
        omitted_falsification_details,
    ) = report_detail_counts(analysis, context);
    let input_frame_refs =
        report_input_frame_refs(&context.inputs, analysis.partition.training_count);
    Ok(json!({
        "version":REPORT_VERSION,
        "case_scope":"current_case",
        "result":analysis.result,
        "search_exhaustive_within_plan":analysis.search_exhaustive_within_plan,
        "report_details_complete":false,
        "no_candidate_reason":analysis.no_candidate_reason,
        "strategy_omission":analysis.strategy_omission,
        "strategy_not_run_reason":analysis.strategy_not_run_reason,
        "cohort":{
            "source_id":context.key.source_id,
            "scope":scope,
            "endpoints":endpoints,
            "direction":context.key.direction,
            "framing_rule":framing_rule,
        },
        "partition":report_partition(context, analysis),
        "input_frame_refs":input_frame_refs,
        "input_omissions":report_input_omissions(context),
        "application":report_application(context, analysis),
        "report_detail_omissions":{
            "input_frame_descriptors":omitted_input_frame_descriptors,
            "schema_proposal_details":omitted_schema_proposals,
            "schema_survivor_details":omitted_surviving_schemas,
            "schema_falsification_details":omitted_falsification_details,
        },
        "work_bound_bytes":requested_work,
    }))
}

fn report_detail_counts(
    analysis: &RecordAnalysis,
    context: &RecordDiscoveryContext,
) -> (usize, usize, usize, usize) {
    let (proposal_count, survivor_count, falsification_count) = analysis
        .strategies
        .as_ref()
        .map_or((0_usize, 0_usize, 0_usize), |strategies| {
            strategy_reports(strategies).fold((0_usize, 0_usize, 0_usize), |counts, report| {
                (
                    counts.0.saturating_add(1),
                    counts.1.saturating_add(
                        report
                            .discovery
                            .as_ref()
                            .map_or(0, |item| item.surviving.len()),
                    ),
                    counts.2.saturating_add(
                        report
                            .discovery
                            .as_ref()
                            .map_or(0, |item| item.falsifications.len()),
                    ),
                )
            })
        });
    (
        context.inputs.len(),
        proposal_count,
        survivor_count,
        falsification_count,
    )
}

fn candidate_origins(
    candidate: &RecoveryCandidate,
    context: &RecordDiscoveryContext,
) -> Result<Vec<u64>, RecoveryExecutionError> {
    let mut origins = Vec::new();
    origins
        .try_reserve(candidate.inputs().len())
        .map_err(|source| operational("record discovery origin allocation failed", source))?;
    for input in candidate.inputs() {
        let [origin_node_id] = input.origin_node_ids() else {
            return Err(RecoveryError::InvariantFailure.into());
        };
        origins.push(*origin_node_id);
    }
    if origins.len() != context.inputs.len()
        || origins
            .iter()
            .zip(&context.inputs)
            .any(|(origin, input)| *origin != input.node_id)
    {
        return Err(RecoveryError::InvariantFailure.into());
    }
    Ok(origins)
}

fn suffix_inputs(
    context: &RecordDiscoveryContext,
    limits: l2_workbench::protocol::RecordSchemaProposalLimits,
) -> Result<Option<Vec<RecordFrameInput>>, RecoveryExecutionError> {
    let mut selected_sessions = context
        .inputs
        .chunk_by(|left, right| left.session_node_id == right.session_node_id)
        .peekable();
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(context.inputs.len())
        .map_err(|source| operational("record suffix sample allocation failed", source))?;
    let mut bytes = 0_usize;
    for session in context
        .application_inputs
        .chunk_by(|left, right| left.session_node_id == right.session_node_id)
    {
        let Some(prefix) = selected_sessions.peek() else {
            break;
        };
        if prefix.first().map(|input| input.session_node_id)
            != session.first().map(|input| input.session_node_id)
        {
            continue;
        }
        let count = prefix.len();
        let start = session
            .len()
            .checked_sub(count)
            .ok_or(RecoveryError::InvariantFailure)?;
        for input in session
            .get(start..)
            .ok_or(RecoveryError::InvariantFailure)?
        {
            bytes = bytes
                .checked_add(input.byte_length)
                .ok_or(RecoveryError::InvariantFailure)?;
            if bytes > limits.discovery.record_limits.max_input_bytes {
                return Ok(None);
            }
            selected.push(input.clone());
        }
        selected_sessions.next();
    }
    if selected_sessions.peek().is_some() || selected.len() != context.inputs.len() {
        return Err(RecoveryError::InvariantFailure.into());
    }
    if selected
        .iter()
        .zip(&context.inputs)
        .all(|(left, right)| left.node_id == right.node_id)
    {
        return Ok(None);
    }
    Ok(Some(selected))
}

fn partition_inputs(
    inputs: &[RecordFrameInput],
) -> Result<SessionPartition, RecoveryExecutionError> {
    let same_session = |left: &RecordFrameInput, right: &RecordFrameInput| {
        left.session_node_id == right.session_node_id
    };
    let group_count = inputs.chunk_by(same_session).count();
    let mut partition = SessionPartition::default();
    partition
        .training_session_nodes
        .try_reserve(group_count)
        .map_err(|source| operational("record discovery session allocation failed", source))?;
    partition
        .held_out_session_nodes
        .try_reserve(group_count)
        .map_err(|source| operational("record discovery session allocation failed", source))?;
    let training_group_end = if group_count < 2 {
        partition.basis = "single_session_training_only";
        group_count
    } else {
        partition.basis = "complete_sessions";
        group_count / 2
    };
    for (group_index, group) in inputs.chunk_by(same_session).enumerate() {
        let session_node_id = group
            .first()
            .ok_or(RecoveryError::InvariantFailure)?
            .session_node_id;
        if group_index < training_group_end {
            partition.training_session_nodes.push(session_node_id);
            partition.training_count = partition
                .training_count
                .checked_add(group.len())
                .ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "record discovery training count overflowed".to_owned(),
                    )
                })?;
        } else {
            partition.held_out_session_nodes.push(session_node_id);
        }
    }
    Ok(partition)
}

fn message_refs<'a>(
    case: &'a Case,
    inputs: &[RecordFrameInput],
) -> Result<Vec<&'a [u8]>, RecoveryExecutionError> {
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(inputs.len())
        .map_err(|source| operational("record discovery message allocation failed", source))?;
    for input in inputs {
        let blob = case
            .blob(&input.blob_id)
            .filter(|blob| blob.id == input.blob_id)
            .ok_or(RecoveryError::InvariantFailure)?;
        if blob.bytes.len() != input.byte_length {
            return Err(RecoveryError::InvariantFailure.into());
        }
        messages.push(blob.bytes.as_slice());
    }
    Ok(messages)
}

fn build_report(
    context: &RecordDiscoveryContext,
    analysis: &RecordAnalysis,
    requested_work: usize,
) -> Result<Value, RecoveryExecutionError> {
    let scope: Value = serde_json::from_str(&context.key.scope_json)
        .map_err(|source| operational("record discovery scope could not be decoded", source))?;
    let endpoints: Value = serde_json::from_str(&context.key.endpoints_json)
        .map_err(|source| operational("record discovery endpoints could not be decoded", source))?;
    let framing_rule: Value = serde_json::from_str(&context.key.framing_rule_json)
        .map_err(|source| operational("record discovery rule could not be decoded", source))?;
    let input_frame_refs =
        report_input_frame_refs(&context.inputs, analysis.partition.training_count);
    let fixed_layout = analysis
        .strategies
        .as_ref()
        .map(|strategies| &strategies.fixed_layout);
    let schema_proposal = fixed_layout.map(|report| proposal_json(&report.proposal));
    let schema_discovery = fixed_layout
        .and_then(|report| report.discovery.as_ref())
        .map(discovery_json);
    let repeated_boundary_analysis = analysis
        .strategies
        .as_ref()
        .and_then(|strategies| strategies.repeated_boundaries.as_ref())
        .map(|report| {
            json!({
                "proposal":proposal_json(&report.proposal),
                "discovery":report.discovery.as_ref().map(discovery_json),
            })
        });
    Ok(json!({
        "version":REPORT_VERSION,
        "case_scope":"current_case",
        "result":analysis.result,
        "search_exhaustive_within_plan":analysis.search_exhaustive_within_plan,
        "report_details_complete":analysis.report_details_complete,
        "no_candidate_reason":analysis.no_candidate_reason,
        "strategy_omission":analysis.strategy_omission,
        "strategy_not_run_reason":analysis.strategy_not_run_reason,
        "cohort":{
            "source_id":context.key.source_id,
            "scope":scope,
            "endpoints":endpoints,
            "direction":context.key.direction,
            "framing_rule":framing_rule,
        },
        "partition":report_partition(context, analysis),
        "input_frame_refs":input_frame_refs,
        "input_omissions":report_input_omissions(context),
        "application":report_application(context, analysis),
        "schema_proposal":schema_proposal,
        "schema_discovery":schema_discovery,
        "repeated_boundary_analysis":repeated_boundary_analysis,
        "work_bound_bytes":requested_work,
    }))
}

fn report_partition(context: &RecordDiscoveryContext, analysis: &RecordAnalysis) -> Value {
    json!({
        "basis":analysis.partition.basis,
        "sampling":context.sampling.label(),
        "training_session_nodes":analysis.partition.training_session_nodes,
        "held_out_session_nodes":analysis.partition.held_out_session_nodes,
        "training_message_count":analysis.partition.training_count,
        "held_out_message_count":context.inputs.len() - analysis.partition.training_count,
    })
}

fn report_input_omissions(context: &RecordDiscoveryContext) -> Value {
    json!({
        "learning_budget_omitted_frame_count":context.omitted_frames,
        "eligibility_omitted_frame_count":context.eligibility_omissions.total,
        "eligibility_reason_counts":context.eligibility_omissions.reason_counts,
        "eligibility_examples":context.eligibility_omissions.examples,
    })
}

fn report_application(context: &RecordDiscoveryContext, analysis: &RecordAnalysis) -> Value {
    json!({
        "eligible_frame_count":context.application_inputs.len(),
        "learning_sampled_frame_count":context.inputs.len(),
        "not_applied_by_this_report_no_schema_frame_count":if analysis.result == STATUS_NO_CANDIDATES { context.application_inputs.len() } else { 0 },
        "session_count":application_session_count(&context.application_inputs),
    })
}

fn report_input_frame_refs(inputs: &[RecordFrameInput], training_count: usize) -> Vec<Value> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let partition = if index < training_count {
                RecordDiscoveryPartition::Training
            } else {
                RecordDiscoveryPartition::HeldOut
            };
            json!([input.node_id, partition.as_str()])
        })
        .collect()
}

fn application_session_count(inputs: &[RecordFrameInput]) -> usize {
    inputs
        .chunk_by(|left, right| left.session_node_id == right.session_node_id)
        .count()
}

fn proposal_json(report: &RecordSchemaProposalReport) -> Value {
    let candidate_space = report.candidate_space.as_ref().map(|space| {
        json!({
            "records_offsets":space.records_offsets,
            "counts":space.counts,
            "identifier_fields":space.identifier_fields,
            "sequence_fields":space.sequence_fields,
            "length_fields":space.length_fields,
            "data_offsets":space.data_offsets,
            "length_meanings":space.length_meanings,
            "sequence_base":space.sequence_base,
        })
    });
    json!({
        "validation_basis":report.validation_basis.as_str(),
        "training_message_count":report.training_message_count,
        "held_out_message_count":report.held_out_message_count,
        "candidate_space":candidate_space,
        "candidate_combinations":report.candidate_combinations,
        "examined_field_checks":report.examined_field_checks,
        "omitted_field_checks":report.omitted_field_checks,
        "examined_pair_checks":report.examined_pair_checks,
        "omitted_pair_checks":report.omitted_pair_checks,
        "examined_length_checks":report.examined_length_checks,
        "omitted_length_checks":report.omitted_length_checks,
        "omitted_record_views":report.omitted_record_views,
        "repeated_boundary_cues":report.repeated_boundary_cues.iter().map(|cue| {
            json!({"message_index":cue.message_index,"range":cue.range})
        }).collect::<Vec<_>>(),
        "omitted_schema_combinations":report.omitted_schema_combinations,
        "search_exhaustive_within_plan":report.search_exhaustive_within_plan,
        "limitations":report.limitations,
    })
}

fn discovery_json(report: &RecordSchemaDiscoveryReport) -> Value {
    let surviving = report
        .surviving
        .iter()
        .map(|hypothesis| {
            json!({
                "schema":hypothesis.schema,
                "training_message_count":hypothesis.training_message_count,
                "held_out_message_count":hypothesis.held_out_message_count,
                "training_record_count":hypothesis.training_record_count,
                "held_out_record_count":hypothesis.held_out_record_count,
            })
        })
        .collect::<Vec<_>>();
    let falsifications = report
        .falsifications
        .iter()
        .map(|failure| {
            json!({
                "schema":failure.schema,
                "partition":failure.partition.as_str(),
                "message_index":failure.message_index,
                "error":format!("{:?}", failure.error),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "validation_basis":report.validation_basis.as_str(),
        "candidate_combinations":report.candidate_combinations,
        "examined_combinations":report.examined_combinations,
        "unexamined_combinations":report.unexamined_combinations,
        "search_exhaustive_within_plan":report.search_exhaustive_within_plan,
        "report_details_complete":report.report_details_complete,
        "surviving":surviving,
        "omitted_survivors":report.omitted_survivors,
        "falsifications":falsifications,
        "falsified_count":report.falsified_count,
        "omitted_falsification_examples":report.omitted_falsification_examples,
    })
}

fn operational(
    message: &'static str,
    source: impl std::error::Error + 'static,
) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: RecoveryStage::RecordDiscovery,
        source: Box::new(RecordDiscoveryReportError {
            message,
            source: Box::new(source),
        }),
    }
}

fn invalid_discovery_policy(message: impl std::fmt::Display) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(format!("record discovery could not run: {message}"))
}

#[derive(Debug)]
struct RecordDiscoveryReportError {
    message: &'static str,
    source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for RecordDiscoveryReportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.message, self.source)
    }
}

impl std::error::Error for RecordDiscoveryReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_record_discovery_sampling.rs"]
mod sampling_tests;
