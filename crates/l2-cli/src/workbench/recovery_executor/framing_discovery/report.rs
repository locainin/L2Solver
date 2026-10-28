use super::super::case_scan::{ScanAdmission, case_scan_work_bounds, preflight_scan};
use super::super::derived_discovery::DerivedFramingCohort;
use super::super::diagnostics::{record_cohort_enqueue, record_cohort_omission};
use super::super::evidence::case_evidence_quota;
use super::super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask, relational::RawRelationalRunInput,
};
use super::input::{FramingInput, collect_plan};
use super::work::work_bound;
use l2_workbench::{evidence::Case, job::RecoveryTransitionStage};
use l2_workbench::{
    protocol::{
        ByteRange as StreamRange, ByteRunSample, Direction, FramingBootstrapExecution,
        FramingBootstrapReport, ProtocolError, ProtocolLimits,
        bootstrap_framing_with_execution_plan,
    },
    recovery::{
        EnqueueOutcome, RecoveryCandidate, RecoveryError, RecoveryInput, RecoveryResource,
        RecoveryResult,
    },
};
use serde_json::{Value, json};

const REPORT_KIND: &str = "recovery_framing_discovery_report";
const REPORT_VERSION: u16 = 1;

impl Executor<'_> {
    fn framing_discovery_snapshot(
        &mut self,
        limits: ProtocolLimits,
    ) -> Result<
        Option<(std::sync::Arc<super::input::FramingDiscoveryPlan>, usize)>,
        RecoveryExecutionError,
    > {
        let Some(snapshot) = self.policy.framing_discovery_plan.as_ref() else {
            let scan_bound = case_scan_work_bounds(self.case)?.framing;
            let remaining = self.coordinator.remaining_work_bytes();
            let admission = preflight_scan(scan_bound, remaining, || {
                let plan = collect_plan(self.case, limits)?;
                let work = super::super::framing_discovery::scan_work(&plan);
                Ok((std::sync::Arc::new(plan), work))
            })?;
            return match admission {
                ScanAdmission::Scanned { value, work } => {
                    // Keep the exact scan result available to later source-frame admission
                    self.policy.framing_discovery_plan = Some(std::sync::Arc::clone(&value));
                    Ok(Some((value, work)))
                }
                ScanAdmission::Exhausted { requested } => {
                    self.omit_case_scan_exhausted(requested);
                    Ok(None)
                }
            };
        };
        if !snapshot.matches_case(self.case) {
            return Err(RecoveryExecutionError::InvalidPolicy(
                "framing discovery policy snapshot no longer matches the Case".to_owned(),
            ));
        }
        Ok(Some((
            std::sync::Arc::clone(snapshot),
            super::super::framing_discovery::scan_work(snapshot),
        )))
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_framing_discovery_if_enabled(
        &mut self,
    ) -> Result<(), RecoveryExecutionError> {
        let transforms_have_transport_input = self.plan.discover_transforms
            && self
                .case
                .nodes()
                .iter()
                .any(|node| node.kind == "tcp_byte_run");
        // Optional relational discovery must not spend byte-analysis work on unrelated file inputs
        if self.plan.discover_framing || transforms_have_transport_input {
            self.enqueue_framing_discovery()?;
        }
        Ok(())
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_framing_discovery(
        &mut self,
    ) -> Result<(), RecoveryExecutionError> {
        let limits = ProtocolLimits::default();
        let Some((plan, scan_work)) = self.framing_discovery_snapshot(limits)? else {
            return Ok(());
        };
        self.seed_derived_tcp_contexts(&plan)?;
        let enqueue_discovery = self.charge_case_scan_work(scan_work);
        if enqueue_discovery {
            if self.plan.discover_transforms {
                for (cohort_key, inputs) in &plan.cohorts {
                    let mut raw_runs = Vec::new();
                    raw_runs.try_reserve_exact(inputs.len()).map_err(|source| {
                        RecoveryExecutionError::Operational {
                            stage: RecoveryStage::TransformDiscovery,
                            source: Box::new(source),
                        }
                    })?;
                    raw_runs.extend(inputs.iter().map(|input| RawRelationalRunInput {
                        node_id: input.node_id,
                        episode_node_id: input.episode_node_id,
                        direction_node_id: input.direction_node_id,
                        session_order: input.session_order,
                        stream_offset: input.stream_offset,
                        // A captured prefix can hold an exact artifact without a closing TCP packet
                        start_known: input.start_known,
                    }));
                    self.collect_relational_raw_runs(
                        &cohort_key.source_id,
                        &cohort_key.scope,
                        cohort_key.direction,
                        &raw_runs,
                        &plan,
                    )?;
                }
                // Raw streams are tested before framing hypotheses create graph outputs
                self.flush_relational_cohorts(super::super::relational::RelationalLane::Normal)?;
            }
            if self.plan.discover_framing {
                self.enqueue_framing_cohorts(&plan)?;
            }
        }
        for (source_id, omission) in &plan.omissions {
            for (reason, count) in &omission.counts {
                let input_node_id = omission
                    .example
                    .as_ref()
                    .and_then(|(id, example_reason)| (example_reason == reason).then_some(*id));
                record_cohort_omission(
                    self,
                    RecoveryTransitionStage::Framing,
                    source_id.as_deref(),
                    input_node_id,
                    *count,
                    reason,
                )?;
            }
            if omission.total > 0 {
                self.omissions
                    .push(RecoveryOmission::FramingDiscoveryInputs {
                        source_id: source_id.clone(),
                        omitted_runs: omission.total,
                        reason_counts: omission.counts.clone(),
                    });
            }
        }
        Ok(())
    }

    fn charge_case_scan_work(&mut self, requested: usize) -> bool {
        match self.coordinator.charge_case_work(requested) {
            l2_workbench::recovery::BudgetCheck::WithinBudget => true,
            l2_workbench::recovery::BudgetCheck::Exhausted {
                resource,
                limit,
                used,
                requested,
            } => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task: RecoveryTask::FramingDiscovery,
                    input_node_ids: Vec::new(),
                    resource,
                    limit,
                    used,
                    requested,
                });
                false
            }
        }
    }

    fn omit_case_scan_exhausted(&mut self, requested: usize) {
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
            input_node_ids: Vec::new(),
            resource: RecoveryResource::WorkBytes,
            limit: self.policy.resources.max_work_bytes,
            used: self.coordinator.work_bytes_charged(),
            requested,
        });
    }

    fn enqueue_framing_cohorts(
        &mut self,
        plan: &super::input::FramingDiscoveryPlan,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::FramingDiscovery;
        for (cohort_key, inputs) in &plan.cohorts {
            if inputs.is_empty() {
                continue;
            }
            let node_ids = inputs.iter().map(|input| input.node_id).collect::<Vec<_>>();
            let result = self
                .coordinator
                .enqueue_nodes(self.case, &node_ids, task.clone())?;
            let candidate_id = match &result {
                EnqueueOutcome::Queued(id)
                | EnqueueOutcome::Merged(id)
                | EnqueueOutcome::MergedNeedsContext(id) => Some(*id),
                EnqueueOutcome::CycleSkipped { candidate_id } => Some(*candidate_id),
                EnqueueOutcome::ResourceExhausted { .. } => None,
            };
            self.record_enqueue(result, &task, &node_ids)?;
            record_cohort_enqueue(
                self,
                RecoveryTransitionStage::Framing,
                &cohort_key.source_id,
                &node_ids,
                result,
            )?;
            if let Some(candidate_id) = candidate_id {
                self.framing_discoveries.insert(
                    candidate_id,
                    FramingDiscoveryContext {
                        source_id: cohort_key.source_id.clone(),
                        scope: cohort_key.scope.clone(),
                        endpoint_pair: cohort_key.endpoint_pair.clone(),
                        direction: cohort_key.direction,
                        native_http_coverage_receipts: inputs
                            .iter()
                            .filter_map(|input| {
                                let coverage =
                                    plan.native_http_coverage_by_run().get(&input.node_id)?;
                                if coverage.message_ranges.is_empty() {
                                    return None;
                                }
                                let full_run = StreamRange {
                                    start: 0,
                                    end: input.byte_length,
                                };
                                Some(NativeHttpCoverageReceipt {
                                    input_run_node_id: input.node_id,
                                    application_checks_node_id: coverage.application_checks_node_id,
                                    message_candidate_node_ids: coverage
                                        .message_candidate_node_ids
                                        .clone(),
                                    fully_covers_observed_run:
                                        super::input::range_covered_by_native_messages(
                                            full_run,
                                            &coverage.message_ranges,
                                        ),
                                })
                            })
                            .collect(),
                        inputs: inputs.clone(),
                        parents: vec![None; inputs.len()],
                        ancestry_id: None,
                    },
                );
            }
        }
        Ok(())
    }

    pub(in crate::workbench::recovery_executor) fn enqueue_derived_framing_discovery(
        &mut self,
        cohort: DerivedFramingCohort,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::FramingDiscovery;
        if cohort.inputs.is_empty() || cohort.inputs.len() != cohort.parents.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let mut parent_child_pairs = Vec::new();
        let mut node_ids = Vec::new();
        parent_child_pairs
            .try_reserve_exact(cohort.inputs.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::FramingDiscovery,
                source: Box::new(source),
            })?;
        node_ids
            .try_reserve_exact(cohort.inputs.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::FramingDiscovery,
                source: Box::new(source),
            })?;
        parent_child_pairs.extend(
            cohort
                .parents
                .iter()
                .copied()
                .zip(cohort.inputs.iter().map(|input| input.node_id)),
        );
        node_ids.extend(cohort.inputs.iter().map(|input| input.node_id));
        let result =
            self.coordinator
                .enqueue_derived_many(self.case, &parent_child_pairs, task.clone())?;
        let candidate_id = match &result {
            EnqueueOutcome::Queued(id)
            | EnqueueOutcome::Merged(id)
            | EnqueueOutcome::MergedNeedsContext(id) => Some(*id),
            EnqueueOutcome::CycleSkipped { .. } | EnqueueOutcome::ResourceExhausted { .. } => None,
        };
        self.record_enqueue(result, &task, &node_ids)?;
        if let Some(candidate_id) = candidate_id {
            self.framing_discoveries.insert(
                candidate_id,
                FramingDiscoveryContext {
                    source_id: cohort.key.source_id,
                    scope: cohort.key.scope,
                    endpoint_pair: cohort.key.endpoint_pair,
                    direction: cohort.key.direction,
                    native_http_coverage_receipts: Vec::new(),
                    parents: cohort.parents.into_iter().map(Some).collect(),
                    inputs: cohort.inputs,
                    ancestry_id: Some(cohort.ancestry_id),
                },
            );
        }
        Ok(())
    }

    pub(in crate::workbench::recovery_executor) fn run_framing_discovery(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let context = self
            .framing_discoveries
            .get(&candidate_id)
            .cloned()
            .ok_or(RecoveryError::InvariantFailure)?;
        if context.inputs.len() != context.parents.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .cloned()
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        let origins = candidate_origins(&candidate, &context)?;
        let limits = ProtocolLimits::default();
        let requested_work = work_bound(&context.inputs, limits).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "framing discovery work bound exceeds this platform's address space".to_owned(),
            )
        })?;
        if !self.charge_work(
            candidate_id,
            &RecoveryTask::FramingDiscovery,
            &origins,
            requested_work,
        )? {
            return Ok(());
        }
        let bootstrap = run_bootstrap(self.case, &context.inputs, limits)?;
        let report_node = self.retain_framing_report(
            candidate_id,
            &context,
            &origins,
            requested_work,
            limits,
            bootstrap.as_ref().map(|execution| &execution.report),
        )?;
        if let (Some(report_node), Some(execution)) = (report_node, bootstrap.as_ref()) {
            for (input, parent) in context.inputs.iter().zip(&context.parents) {
                for rule in &execution.execution_plan.surviving_hypotheses {
                    if let Some(parent) = parent {
                        self.enqueue_discovered_framing_derived(
                            *parent,
                            input.node_id,
                            rule,
                            report_node,
                        )?;
                    } else {
                        self.enqueue_discovered_framing(input.node_id, rule, report_node)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn retain_framing_report(
        &mut self,
        candidate_id: RecoveryCandidateId,
        context: &FramingDiscoveryContext,
        origins: &[u64],
        requested_work: usize,
        limits: ProtocolLimits,
        bootstrap: Option<&FramingBootstrapReport>,
    ) -> Result<Option<u64>, RecoveryExecutionError> {
        let full_report =
            build_framing_report(context, &context.inputs, requested_work, limits, bootstrap);
        let (report_bytes, report_truncated) =
            bounded_report_bytes(&full_report, bootstrap, limits.max_report_bytes)?;
        self.record_framing_report_omissions(context, bootstrap, report_truncated)?;
        if !self.check_output(
            candidate_id,
            &RecoveryTask::FramingDiscovery,
            origins,
            report_bytes.len(),
        )? {
            return Ok(None);
        }
        let details = json!({
            "case_scope": "current_case",
            "source_id": context.source_id,
            "input_run_count": context.inputs.len(),
            "report_bytes": report_bytes.len(),
        });
        let requested_details_bytes = serde_json::to_vec(&details)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::FramingDiscovery,
                source: Box::new(source),
            })?
            .len();
        let report_node = match self.receipt_node_bytes_and_finish(
            candidate_id,
            REPORT_KIND,
            &report_bytes,
            details,
            |node_id| RecoveryResult::Hypothesis { node_id },
        ) {
            Ok(node_id) => node_id,
            Err(RecoveryExecutionError::Evidence(error)) => {
                let Some((resource, limit, used)) = case_evidence_quota(self.case, &error) else {
                    return Err(RecoveryExecutionError::Evidence(error));
                };
                let requested = framing_report_quota_request(
                    resource,
                    origins.len(),
                    report_bytes.len(),
                    requested_details_bytes,
                );
                self.finish_framing_report_quota(
                    candidate_id,
                    origins,
                    resource,
                    limit,
                    used,
                    requested,
                )?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(report_node))
    }

    fn finish_framing_report_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    ) -> Result<(), RecoveryExecutionError> {
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
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

    fn record_framing_report_omissions(
        &mut self,
        context: &FramingDiscoveryContext,
        bootstrap: Option<&FramingBootstrapReport>,
        report_truncated: bool,
    ) -> Result<(), RecoveryExecutionError> {
        if report_truncated {
            self.omissions
                .push(RecoveryOmission::FramingDiscoveryReportDetails {
                    source_id: context.source_id.clone(),
                    omitted_input_runs: context.inputs.len(),
                    omitted_hypotheses: bootstrap.map_or(0, |report| report.hypotheses.len()),
                });
        }
        let Some(bootstrap) = bootstrap.filter(|report| {
            !report.search_exhaustive_within_plan || !report.report_details_complete
        }) else {
            return Ok(());
        };
        let detail_incomplete_runs = bootstrap
            .discovery
            .iter()
            .chain(&bootstrap.holdout)
            .filter(|run| !run.boundaries.report_details_complete)
            .count();
        let omitted_frame_examples = bootstrap
            .discovery
            .iter()
            .chain(&bootstrap.holdout)
            .flat_map(|run| &run.boundaries.candidates)
            .try_fold(0_usize, |total, candidate| {
                total.checked_add(candidate.omitted_frames)
            })
            .ok_or_else(|| RecoveryExecutionError::Operational {
                stage: RecoveryStage::FramingDiscovery,
                source: "omitted framing frame examples exceed this platform's address space"
                    .into(),
            })?;
        self.omissions
            .push(RecoveryOmission::FramingDiscoveryAnalysis {
                source_id: context.source_id.clone(),
                search_exhaustive_within_plan: bootstrap.search_exhaustive_within_plan,
                report_details_complete: bootstrap.report_details_complete,
                omitted_candidates: bootstrap.omitted_candidates,
                omitted_hypothesis_details: bootstrap.omitted_hypothesis_details,
                omitted_candidate_details: bootstrap.omitted_candidate_details,
                omitted_alias_candidates: bootstrap.omitted_alias_candidates,
                detail_incomplete_runs,
                omitted_frame_examples,
            });
        Ok(())
    }
}

const fn framing_report_quota_request(
    resource: RecoveryResource,
    origin_count: usize,
    report_bytes: usize,
    details_bytes: usize,
) -> usize {
    match resource {
        RecoveryResource::EvidenceEdges => origin_count,
        RecoveryResource::EvidenceBlobBytes => report_bytes,
        RecoveryResource::EvidenceTotalDetailsBytes => details_bytes,
        _ => 1,
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::workbench::recovery_executor) struct FramingDiscoveryContext {
    source_id: String,
    scope: String,
    endpoint_pair: String,
    direction: Direction,
    native_http_coverage_receipts: Vec<NativeHttpCoverageReceipt>,
    inputs: Vec<FramingInput>,
    parents: Vec<Option<RecoveryCandidateId>>,
    ancestry_id: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct NativeHttpCoverageReceipt {
    input_run_node_id: u64,
    application_checks_node_id: u64,
    message_candidate_node_ids: Vec<u64>,
    fully_covers_observed_run: bool,
}

fn candidate_origins(
    candidate: &RecoveryCandidate,
    context: &FramingDiscoveryContext,
) -> Result<Vec<u64>, RecoveryExecutionError> {
    let mut origins = candidate
        .inputs()
        .iter()
        .flat_map(RecoveryInput::origin_node_ids)
        .copied()
        .collect::<Vec<_>>();
    origins.sort_unstable();
    origins.dedup();
    let mut expected = context
        .inputs
        .iter()
        .map(|input| input.node_id)
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if origins != expected {
        return Err(RecoveryError::InvariantFailure.into());
    }
    Ok(origins)
}

fn run_bootstrap(
    case: &Case,
    inputs: &[FramingInput],
    limits: ProtocolLimits,
) -> Result<Option<FramingBootstrapExecution>, RecoveryExecutionError> {
    let runs = inputs
        .iter()
        .map(|input| {
            let blob = case
                .blob(&input.blob_id)
                .ok_or(RecoveryError::InvariantFailure)?;
            if blob.bytes.len() != input.byte_length {
                return Err(RecoveryError::InvariantFailure.into());
            }
            Ok(ByteRunSample {
                sample: input.node_id,
                context: Some(input.context.clone()),
                bytes: blob.bytes.as_slice(),
            })
        })
        .collect::<Result<Vec<_>, RecoveryExecutionError>>()?;
    match bootstrap_framing_with_execution_plan(&runs, limits) {
        Ok(execution) => Ok(Some(execution)),
        Err(ProtocolError::NoFramingCandidates) => Ok(None),
        Err(source) => Err(RecoveryExecutionError::Operational {
            stage: RecoveryStage::FramingDiscovery,
            source: Box::new(source),
        }),
    }
}

fn build_framing_report(
    context: &FramingDiscoveryContext,
    runs: &[FramingInput],
    requested_work: usize,
    limits: ProtocolLimits,
    bootstrap: Option<&FramingBootstrapReport>,
) -> Value {
    let input_runs = runs
        .iter()
        .map(|input| {
            json!({
                "node_id": input.node_id,
                "blob_id": input.blob_id,
                "context": input.context,
                "ancestry": {
                    "direction_node_id": input.direction_node_id,
                    "direction_contains_status": input.direction_contains_status,
                    "episode_node_id": input.episode_node_id,
                    "episode_contains_status": input.episode_contains_status,
                },
                "stream_offset": input.stream_offset,
                "byte_length": input.byte_length,
                "start_known": input.start_known,
                "end_observed": input.end_observed,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "version": REPORT_VERSION,
        "case_scope": "current_case",
        "source_id": context.source_id,
        "input_generation": context.ancestry_id.as_deref().map_or_else(
            || json!({"kind":"tcp_materialized_stream"}),
            |ancestry_id| json!({"kind":"transformed_stream", "ancestry_id":ancestry_id}),
        ),
        "cohort": {
            "scope": context.scope,
            "endpoint_pair": context.endpoint_pair,
            "direction": context.direction,
        },
        "protocol_limits": limits,
        "input_runs": input_runs,
        "unknown_wire_relational_scope": {
            "native_http_coverage_receipts": context.native_http_coverage_receipts.iter().map(|receipt| json!({
                "input_run_node_id":receipt.input_run_node_id,
                "application_checks_node_id":receipt.application_checks_node_id,
                "message_candidate_node_ids":receipt.message_candidate_node_ids,
                "fully_covers_observed_run":receipt.fully_covers_observed_run,
            })).collect::<Vec<_>>(),
            "scope_reason": "Complete native HTTP message ranges exclude only the covered source bytes from unknown-wire relational discovery; an entire raw run is excluded only when those ranges cover every observed byte",
            "frame_range_rule": "A source-framed range is excluded only when complete native HTTP message ranges cover the full frame range",
            "end_observed_required": false,
            "unparsed_ranges_remain_eligible": true,
        },
        "bootstrap": bootstrap,
        "work_bound_bytes": requested_work,
    })
}

pub(in crate::workbench::recovery_executor) fn bounded_report_bytes(
    full_report: &Value,
    bootstrap: Option<&FramingBootstrapReport>,
    maximum: usize,
) -> Result<(Vec<u8>, bool), RecoveryExecutionError> {
    let full = serialize_report(full_report)?;
    if full.len() <= maximum {
        return Ok((full, false));
    }
    let counts = omitted_report_counts(full_report, bootstrap)?;
    let compact = serialize_report(&compact_report(full_report, bootstrap, counts))?;
    if compact.len() <= maximum {
        return Ok((compact, true));
    }
    let minimal = serialize_report(&minimal_report(full_report, bootstrap, counts))?;
    if minimal.len() > maximum {
        return Err(RecoveryExecutionError::Operational {
            stage: RecoveryStage::FramingDiscovery,
            source: "minimum framing report exceeds configured report limit".into(),
        });
    }
    Ok((minimal, true))
}

#[derive(Clone, Copy)]
struct OmittedReportCounts {
    input_runs: usize,
    boundary_runs: usize,
    sample_ids: usize,
}

fn omitted_report_counts(
    full_report: &Value,
    bootstrap: Option<&FramingBootstrapReport>,
) -> Result<OmittedReportCounts, RecoveryExecutionError> {
    let input_runs = full_report
        .get("input_runs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let (boundary_runs, sample_ids) = match bootstrap {
        Some(report) => {
            let boundary_runs = report
                .discovery
                .len()
                .checked_add(report.holdout.len())
                .ok_or_else(report_count_overflow)?;
            let sample_ids = report
                .discovery_samples
                .len()
                .checked_add(report.holdout_samples.len())
                .ok_or_else(report_count_overflow)?;
            (boundary_runs, sample_ids)
        }
        None => (0, 0),
    };
    Ok(OmittedReportCounts {
        input_runs,
        boundary_runs,
        sample_ids,
    })
}

fn report_count_overflow() -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(
        "framing report detail counts exceed this platform's address space".to_owned(),
    )
}

fn compact_report(
    full_report: &Value,
    bootstrap: Option<&FramingBootstrapReport>,
    counts: OmittedReportCounts,
) -> Value {
    json!({
        "version": REPORT_VERSION,
        "case_scope": value_field(full_report, "case_scope"),
        "source_id": value_field(full_report, "source_id"),
        "cohort": value_field(full_report, "cohort"),
        "unknown_wire_relational_scope": value_field(full_report, "unknown_wire_relational_scope"),
        "protocol_limits": value_field(full_report, "protocol_limits"),
        "input_run_count": counts.input_runs,
        "input_run_details_omitted": counts.input_runs,
        "bootstrap_summary": bootstrap.map(|report| json!({
            "hypothesis_count": report.hypotheses.len(),
            "hypotheses_omitted": report.hypotheses.len(),
            "discovery_run_count": report.discovery_samples.len(),
            "holdout_run_count": report.holdout_samples.len(),
            "boundary_details_omitted": counts.boundary_runs,
            "sample_ids_omitted": counts.sample_ids,
            "limitations_omitted": report.limitations.len(),
            "prefix_offset_limit": report.prefix_offset_limit,
            "split_basis": report.split_basis,
            "validation_basis": report.validation_basis,
            "omitted_candidates": report.omitted_candidates,
            "omitted_hypothesis_details": report.omitted_hypothesis_details,
            "omitted_candidate_details": report.omitted_candidate_details,
            "omitted_alias_candidates": report.omitted_alias_candidates,
            "search_exhaustive_within_plan": report.search_exhaustive_within_plan,
            "report_details_complete": report.report_details_complete,
        })),
        "report_truncated": true,
        "work_bound_bytes": value_field(full_report, "work_bound_bytes"),
    })
}

fn minimal_report(
    full_report: &Value,
    bootstrap: Option<&FramingBootstrapReport>,
    counts: OmittedReportCounts,
) -> Value {
    json!({
        "version": REPORT_VERSION,
        "case_scope": "current_case",
        "source_id": value_field(full_report, "source_id"),
        "cohort": value_field(full_report, "cohort"),
        "unknown_wire_relational_scope": value_field(full_report, "unknown_wire_relational_scope"),
        "input_run_count": counts.input_runs,
        "input_run_details_omitted": counts.input_runs,
        "protocol_limits_omitted": true,
        "bootstrap_details_omitted": bootstrap.is_some(),
        "bootstrap_hypotheses_omitted": bootstrap.map_or(0, |report| report.hypotheses.len()),
        "bootstrap_run_details_omitted": counts.boundary_runs,
        "bootstrap_sample_ids_omitted": counts.sample_ids,
        "bootstrap_limitations_omitted": bootstrap.map_or(0, |report| report.limitations.len()),
        "bootstrap_prefix_offset_limit_omitted": bootstrap.is_some(),
        "bootstrap_omitted_candidates": bootstrap.map_or(0, |report| report.omitted_candidates),
        "bootstrap_omitted_hypothesis_details": bootstrap.map_or(0, |report| report.omitted_hypothesis_details),
        "bootstrap_omitted_candidate_details": bootstrap.map_or(0, |report| report.omitted_candidate_details),
        "bootstrap_omitted_alias_candidates": bootstrap.map_or(0, |report| report.omitted_alias_candidates),
        "bootstrap_search_exhaustive_within_plan": bootstrap.map(|report| report.search_exhaustive_within_plan),
        "bootstrap_report_details_complete": bootstrap.map(|report| report.report_details_complete),
        "report_truncated": true,
        "work_bound_bytes": value_field(full_report, "work_bound_bytes"),
    })
}

fn serialize_report(value: &Value) -> Result<Vec<u8>, RecoveryExecutionError> {
    serde_json::to_vec(value).map_err(|source| RecoveryExecutionError::Operational {
        stage: RecoveryStage::FramingDiscovery,
        source: Box::new(source),
    })
}

fn value_field(value: &Value, field: &str) -> Value {
    value.get(field).cloned().unwrap_or(Value::Null)
}
