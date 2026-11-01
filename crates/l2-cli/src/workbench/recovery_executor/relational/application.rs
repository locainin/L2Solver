use super::record_gate::{
    AcceptedFrameIdentity, AcceptedRecordSchema, GateStatus, SchemaOffsetScope,
};
use super::search::CandidateGate;
use super::{
    AppliedOutput, DecodedFrameOutput, GateAssessment, MAX_RETAINED_RELATIONAL_APPLICATIONS,
    RelationalDiscoveryContext, RetainedRelationalRule, StoredSample, checked_output_sha256,
    invalid_policy, operational,
};
use l2_workbench::{
    artifact::{ArtifactStructure, ArtifactValidationOutcome, ArtifactValidationPolicy},
    job::{Counter, Job},
    protocol::{
        ByteRange, RecordSchemaStrategy, RelationalAppliedOutput, RelationalCandidateOutputs,
        RelationalOutputMapping, RelationalParserScope, RelationalRecordSample,
        RelationalRetainedEvaluation, RelationalTransformPlan, RelationalTransformReport,
        RelationalTransformRule, apply_relational_transform_rule,
    },
    recovery::RecoveryError,
    sha256,
};
use serde_json::{Value, json};
use std::{borrow::Cow, collections::HashSet};

pub(super) struct AppliedCandidates {
    pub(super) outputs: Vec<AppliedOutput>,
    pub(super) decoded_frames: Vec<DecodedFrameOutput>,
    pub(super) accepted_schemas: Vec<(usize, AcceptedRecordSchema)>,
    pub(super) structural_evidence: Vec<(usize, super::record_gate::StructuralEvidence)>,
    pub(super) aggregate_parser_checks: Vec<Value>,
    pub(super) application_evidence_checks: Vec<Value>,
    pub(super) supported_rules: usize,
    pub(super) applied_rules: usize,
    pub(super) used_work: usize,
    pub(super) reason: Option<&'static str>,
}

struct AcrossSessionCandidate<'a> {
    candidate_index: usize,
    rule: &'a RelationalTransformRule,
    outputs: &'a [RelationalAppliedOutput],
    frames: Vec<DecodedFrameOutput>,
    assessment: GateAssessment,
    status: GateStatus,
    priority: u8,
    exact_aggregate_output: Option<AppliedOutput>,
}

pub(super) struct DecodedFrameContext<'a> {
    pub(super) samples: &'a [RelationalRecordSample<'a>],
    pub(super) stored_samples: &'a [StoredSample],
    pub(super) candidate_index: usize,
    pub(super) expected_session_orders: &'a [u64],
    pub(super) raw_directional_run: bool,
    pub(super) job: Option<&'a Job>,
}

pub(super) struct AggregateOutput {
    pub(super) bytes: Vec<u8>,
    pub(super) payload_mappings: Vec<RelationalOutputMapping>,
    pub(super) seed_samples: Vec<u64>,
    pub(super) session_ids: Vec<u64>,
    pub(super) session_orders: Vec<u64>,
    pub(super) session_work: usize,
}

struct DecodedFrameBytes {
    bytes: Vec<u8>,
    payload_range: l2_workbench::protocol::ByteRange,
    preserved_header_end: Option<usize>,
    stream_offset: usize,
}

type DecodedOutputMappingKey = (u64, usize, usize, usize, usize);
type DecodedAliasKey = (Vec<DecodedOutputMappingKey>, Vec<String>, String);

pub(super) struct CandidateApplication<'a> {
    context: &'a RelationalDiscoveryContext,
    samples: &'a [RelationalRecordSample<'a>],
    search_plan: &'a RelationalTransformPlan,
    artifact_validation_policy: ArtifactValidationPolicy,
    cohort_work_budget: usize,
    replay_work_remaining: usize,
    job: Option<&'a Job>,
    supported_rules: usize,
    attempted_rule_count: usize,
    qualified_rule_count: usize,
    aggregate_parser_checks: Vec<Value>,
    application_evidence_checks: Vec<Value>,
    application_unresolved: bool,
    retained_rules: Vec<RetainedRelationalRule>,
    structural_evidence: Vec<(usize, super::record_gate::StructuralEvidence)>,
    retained_frame_bytes: usize,
    aliases: HashSet<(Vec<u64>, String)>,
    decoded_aliases: HashSet<DecodedAliasKey>,
}

impl<'a> CandidateApplication<'a> {
    pub(super) fn new(
        context: &'a RelationalDiscoveryContext,
        samples: &'a [RelationalRecordSample<'a>],
        search_plan: &'a RelationalTransformPlan,
        artifact_validation_policy: ArtifactValidationPolicy,
        cohort_work_budget: usize,
        report: &RelationalTransformReport,
        job: Option<&'a Job>,
    ) -> Result<Self, super::RecoveryExecutionError> {
        let maximum_materialized_rules = search_plan
            .limits
            .max_retained_candidates
            .min(MAX_RETAINED_RELATIONAL_APPLICATIONS);
        let supported_rules = report
            .candidates
            .iter()
            .filter(|candidate| {
                matches!(
                    candidate.status,
                    l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied
                        | l2_workbench::protocol::RelationalTransformStatus::AwaitingAcrossSessionValidation
                )
            })
            .count();
        let mut retained_rules = Vec::new();
        retained_rules
            .try_reserve_exact(maximum_materialized_rules)
            .map_err(|source| operational("retained relational rule allocation failed", source))?;
        Ok(Self {
            context,
            samples,
            search_plan,
            artifact_validation_policy,
            cohort_work_budget,
            replay_work_remaining: cohort_work_budget.saturating_sub(report.work_bytes),
            job,
            supported_rules,
            attempted_rule_count: 0,
            qualified_rule_count: 0,
            aggregate_parser_checks: Vec::new(),
            application_evidence_checks: Vec::new(),
            application_unresolved: !context.input_coverage_complete,
            retained_rules,
            structural_evidence: Vec::new(),
            retained_frame_bytes: 0,
            aliases: HashSet::new(),
            decoded_aliases: HashSet::new(),
        })
    }

    pub(super) fn apply(
        mut self,
        report: &RelationalTransformReport,
        evaluations: Vec<RelationalRetainedEvaluation<GateAssessment>>,
        gate: &CandidateGate<'_>,
    ) -> Result<AppliedCandidates, super::RecoveryExecutionError> {
        if evaluations.len() != report.candidates.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        for (candidate_index, (candidate, evaluation)) in
            report.candidates.iter().zip(evaluations).enumerate()
        {
            self.apply_candidate(candidate_index, candidate, report, evaluation, gate)?;
        }
        self.retained_rules
            .sort_unstable_by_key(|rule| rule.candidate_index);
        let applied_rules = self.retained_rules.len();
        let retained_rules = std::mem::take(&mut self.retained_rules);
        let mut outputs = Vec::new();
        let mut decoded_frames = Vec::new();
        let mut accepted_schemas = Vec::new();
        accepted_schemas
            .try_reserve_exact(retained_rules.len())
            .map_err(|source| {
                operational("accepted relational schema allocation failed", source)
            })?;
        for mut rule in retained_rules {
            outputs.append(&mut rule.outputs);
            decoded_frames.append(&mut rule.decoded_frames);
            if let Some(accepted) = rule.accepted_schema.take() {
                accepted_schemas.push((rule.candidate_index, accepted));
            }
        }
        let replay_used = self
            .cohort_work_budget
            .saturating_sub(report.work_bytes)
            .saturating_sub(self.replay_work_remaining);
        let used_work = report
            .work_bytes
            .checked_add(replay_used)
            .ok_or_else(|| invalid_policy("relational work count overflowed"))?;
        let reason = if self.application_unresolved {
            Some("aggregate_application_unresolved")
        } else if self.qualified_rule_count > applied_rules
            || self.attempted_rule_count < self.supported_rules
        {
            Some("supported_rule_application_limit")
        } else {
            None
        };
        Ok(AppliedCandidates {
            outputs,
            decoded_frames,
            accepted_schemas,
            structural_evidence: self.structural_evidence,
            aggregate_parser_checks: self.aggregate_parser_checks,
            application_evidence_checks: self.application_evidence_checks,
            supported_rules: self.supported_rules,
            applied_rules,
            used_work,
            reason,
        })
    }

    fn apply_candidate(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        report: &RelationalTransformReport,
        evaluation: RelationalRetainedEvaluation<GateAssessment>,
        gate: &CandidateGate<'_>,
    ) -> Result<(), super::RecoveryExecutionError> {
        if !matches!(
            candidate.status,
            l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied
                | l2_workbench::protocol::RelationalTransformStatus::AwaitingAcrossSessionValidation
        ) {
            return Ok(());
        }
        self.attempted_rule_count += 1;
        if let Some(job) = self.job {
            job.check_cancelled()?;
        }
        let candidate_outputs = self.replay_candidate_outputs(candidate, evaluation.outputs)?;
        let assessment = evaluation.assessment;
        match candidate.rule.parser_scope {
            RelationalParserScope::EachSession => {
                if assessment.accepted_schema.is_some() {
                    return Err(RecoveryError::InvariantFailure.into());
                }
                self.apply_each_session(
                    candidate_index,
                    candidate,
                    candidate_outputs,
                    &assessment.details,
                )
            }
            RelationalParserScope::AcrossSessions => self.apply_across_sessions(
                candidate_index,
                candidate,
                candidate_outputs,
                assessment,
                report,
                gate,
            ),
        }
    }

    fn replay_candidate_outputs(
        &mut self,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        captured_outputs: Option<RelationalCandidateOutputs>,
    ) -> Result<Vec<RelationalAppliedOutput>, super::RecoveryExecutionError> {
        // Replay every retained output against its frozen length and digest
        let expected_check_status = match candidate.rule.parser_scope {
            RelationalParserScope::EachSession => {
                l2_workbench::protocol::RelationalFitStatus::ConstraintsSatisfied
            }
            RelationalParserScope::AcrossSessions => {
                l2_workbench::protocol::RelationalFitStatus::TransformConstraintsSatisfied
            }
        };
        let all_checks = candidate
            .discovery
            .checks
            .iter()
            .chain(&candidate.heldout.checks);
        let mut captured_outputs = captured_outputs.map(|outputs| {
            let mut captured = outputs.discovery;
            captured.extend(outputs.heldout);
            captured.sort_unstable_by_key(|output| output.session_order);
            captured
        });
        let mut candidate_outputs = Vec::new();
        for check in all_checks {
            if check.status != expected_check_status {
                return Err(invalid_policy(
                    "supported relational candidate contains an unexpected session check",
                ));
            }
            if let Some(job) = self.job {
                job.check_cancelled()?;
            }
            if !self
                .samples
                .iter()
                .any(|sample| sample.context.session == check.session.session)
            {
                continue;
            }
            let applied = if let Some(captured) = &mut captured_outputs {
                let Some(position) = captured
                    .iter()
                    .position(|output| output.session.session == check.session.session)
                else {
                    return Err(RecoveryError::InvariantFailure.into());
                };
                captured.remove(position)
            } else {
                let session_samples = self
                    .samples
                    .iter()
                    .filter(|sample| sample.context.session == check.session.session)
                    .cloned()
                    .collect::<Vec<_>>();
                apply_relational_transform_rule(
                    &session_samples,
                    &candidate.rule,
                    self.search_plan.limits,
                    self.replay_work_remaining,
                )?
            };
            if check.output_length != Some(applied.bytes.len())
                || check.output_sha256.as_deref() != Some(sha256(&applied.bytes).as_str())
            {
                return Err(invalid_policy(
                    "relational rule replay did not match its frozen check",
                ));
            }
            if captured_outputs.is_none() {
                self.replay_work_remaining = self
                    .replay_work_remaining
                    .checked_sub(applied.work_bytes)
                    .ok_or_else(|| invalid_policy("relational replay exceeded admitted work"))?;
            }
            candidate_outputs.push(applied);
        }
        if captured_outputs
            .as_ref()
            .is_some_and(|captured| !captured.is_empty())
        {
            return Err(RecoveryError::InvariantFailure.into());
        }
        Ok(candidate_outputs)
    }

    fn apply_each_session(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: Vec<RelationalAppliedOutput>,
        gate_details: &Value,
    ) -> Result<(), super::RecoveryExecutionError> {
        let mut candidate_applied = false;
        let mut candidate_retained_outputs = Vec::new();
        candidate_retained_outputs
            .try_reserve_exact(candidate_outputs.len())
            .map_err(|source| operational("relational output allocation failed", source))?;
        for applied in candidate_outputs {
            let session_id = applied.session.session;
            let session_order = applied.session_order;
            let seed_sample = applied.seed_sample;
            let digest = sha256(&applied.bytes);
            if self.aliases.insert((vec![session_id], digest.clone())) {
                candidate_retained_outputs.push(AppliedOutput {
                    candidate_index,
                    value: applied,
                    sha256: digest,
                    parser_format: candidate.rule.parser_format,
                    session_ids: vec![session_id],
                    session_orders: vec![session_order],
                    seed_samples: vec![seed_sample],
                });
            }
            candidate_applied = true;
        }
        if candidate_applied {
            self.qualified_rule_count = self.qualified_rule_count.saturating_add(1);
            self.application_evidence_checks.push(json!({
                "candidate_index":candidate_index,
                "status":GateStatus::ArtifactValidated.as_str(),
                "artifact_validated":true,
                "structurally_supported":true,
                "reason":"exact_each_session_parser_constraints_satisfied",
                "details":gate_details,
                "accepted_record_schema":Value::Null,
            }));
            let retained = RetainedRelationalRule {
                candidate_index,
                evidence_priority: GateStatus::ArtifactValidated.priority(),
                outputs: candidate_retained_outputs,
                decoded_frames: Vec::new(),
                accepted_schema: None,
            };
            let maximum_materialized_rules = self.maximum_materialized_rules();
            let _ = retain_relational_rule(
                &mut self.retained_rules,
                &mut self.retained_frame_bytes,
                maximum_materialized_rules,
                self.search_plan.limits.max_total_bytes,
                retained,
            )?;
        }
        Ok(())
    }

    fn apply_across_sessions(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        mut candidate_outputs: Vec<RelationalAppliedOutput>,
        mut gate_assessment: GateAssessment,
        report: &RelationalTransformReport,
        gate: &CandidateGate<'_>,
    ) -> Result<(), super::RecoveryExecutionError> {
        candidate_outputs.sort_by_key(|output| output.session_order);
        let expected_session_orders = candidate_outputs
            .iter()
            .map(|output| output.session_order)
            .collect::<Vec<_>>();
        let candidate_frames = self.decoded_candidate_frames(
            candidate_index,
            candidate,
            &candidate_outputs,
            &expected_session_orders,
        )?;
        let exact_aggregate_output =
            self.validate_aggregate(candidate_index, candidate, &candidate_outputs)?;
        let fallback_required = gate_assessment.needs_full_inference(self.replay_work_remaining);
        if exact_aggregate_output.is_some() {
            gate_assessment.status = GateStatus::ArtifactValidated;
            gate_assessment.assessment_scope = Some(SchemaOffsetScope::CompleteInput);
            if fallback_required {
                gate_assessment.details = json!({
                    "primary_assessment":gate_assessment.details,
                    "full_inference_fallback":{
                        "attempted":false,
                        "reason":"aggregate_artifact_validated",
                        "work_bytes":0,
                    }
                });
            }
        } else {
            self.apply_deferred_full_inference(
                candidate,
                &candidate_frames,
                report,
                &mut gate_assessment,
                gate,
            )?;
        }
        if let Some(accepted) = &gate_assessment.accepted_schema {
            validate_accepted_record_schema(
                candidate_index,
                &candidate_frames,
                accepted,
                |_, frame| Ok(Cow::Owned(sha256(&frame.bytes))),
            )?;
        }
        let (candidate_status, candidate_priority) =
            self.initial_candidate_status(&gate_assessment)?;
        self.retain_across_session_candidate(AcrossSessionCandidate {
            candidate_index,
            rule: &candidate.rule,
            outputs: &candidate_outputs,
            frames: candidate_frames,
            assessment: gate_assessment,
            status: candidate_status,
            priority: if candidate_status == GateStatus::ArtifactValidated {
                GateStatus::ArtifactValidated.priority()
            } else {
                candidate_priority
            },
            exact_aggregate_output,
        })
    }

    fn apply_deferred_full_inference(
        &mut self,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_frames: &[DecodedFrameOutput],
        report: &RelationalTransformReport,
        assessment: &mut GateAssessment,
        gate: &CandidateGate<'_>,
    ) -> Result<(), super::RecoveryExecutionError> {
        if !assessment.needs_full_inference(self.replay_work_remaining) {
            return Ok(());
        }
        let previous_work_limit = assessment.work_limited_at;
        let primary_details = std::mem::take(&mut assessment.details);
        if self.replay_work_remaining == 0 {
            assessment.details = json!({
                "primary_assessment":primary_details,
                "full_inference_fallback":{
                    "attempted":false,
                    "reason":"application_work_limit",
                    "work_bytes":0,
                }
            });
            return Ok(());
        }
        let admitted_work = self.replay_work_remaining;
        let fallback = gate.screen_full_inference(
            candidate_frames,
            report,
            candidate.rule.parser_format,
            self.replay_work_remaining,
        )?;
        if fallback.work_bytes > self.replay_work_remaining {
            return Err(invalid_policy(
                "deferred relational inference exceeded admitted application work",
            ));
        }
        self.replay_work_remaining -= fallback.work_bytes;
        assessment.status = fallback.status;
        assessment.accepted_schema = fallback.accepted_schema;
        assessment.structural_evidence = fallback.structural_evidence;
        assessment.assessment_scope = Some(SchemaOffsetScope::CompleteInput);
        assessment.work_limited_at = fallback.work_limited_at;
        assessment.details = json!({
            "primary_assessment":primary_details,
            "full_inference_fallback":{
                "attempted":true,
                "previous_work_limit":previous_work_limit,
                "admitted_work_bytes":admitted_work,
                "work_bytes":fallback.work_bytes,
                "assessment":fallback.details,
            }
        });
        Ok(())
    }

    fn initial_candidate_status(
        &mut self,
        gate_assessment: &GateAssessment,
    ) -> Result<(GateStatus, u8), super::RecoveryExecutionError> {
        let status = gate_assessment.status;
        if status == GateStatus::Pending {
            self.application_unresolved = true;
        } else if status == GateStatus::Contradicted
            && let Some(job) = self.job
        {
            job.increment(Counter::CandidatesRejected, 1)?;
        }
        Ok((status, status.priority()))
    }

    fn decoded_candidate_frames(
        &self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: &[RelationalAppliedOutput],
        expected_session_orders: &[u64],
    ) -> Result<Vec<DecodedFrameOutput>, super::RecoveryExecutionError> {
        let frame_context = DecodedFrameContext {
            samples: self.samples,
            stored_samples: &self.context.samples,
            candidate_index,
            expected_session_orders,
            raw_directional_run: self.context.key.framing_rule_json == super::RAW_RUN_FRAMING_RULE,
            job: self.job,
        };
        let mut candidate_frames = Vec::new();
        for applied in candidate_outputs {
            let output_sha256 = checked_output_sha256(candidate, applied)?;
            candidate_frames.extend(decoded_payload_frames(
                &frame_context,
                applied,
                &candidate.rule,
                output_sha256,
            )?);
        }
        Ok(candidate_frames)
    }

    // Across-session validation checks the joined bytes as one exact artifact
    fn validate_aggregate(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: &[RelationalAppliedOutput],
    ) -> Result<Option<AppliedOutput>, super::RecoveryExecutionError> {
        let aggregate_length = candidate_outputs
            .iter()
            .try_fold(0_usize, |total, output| {
                total.checked_add(output.bytes.len())
            })
            .ok_or_else(|| invalid_policy("relational aggregate output length overflowed"))?;
        if aggregate_length > self.search_plan.limits.max_total_bytes {
            self.record_aggregate_budget_failure(
                candidate_index,
                candidate,
                candidate_outputs,
                aggregate_length,
                "unresolved_on_aggregate_byte_limit",
                Some(self.search_plan.limits.max_total_bytes),
            );
            return Ok(None);
        }
        if aggregate_length > self.replay_work_remaining {
            self.record_aggregate_budget_failure(
                candidate_index,
                candidate,
                candidate_outputs,
                aggregate_length,
                "unresolved_on_aggregate_work_limit",
                None,
            );
            return Ok(None);
        }
        let aggregate = concatenate_outputs(candidate_outputs, aggregate_length, self.job)?;
        self.validate_aggregate_bytes(candidate_index, candidate, candidate_outputs, aggregate)
    }

    fn record_aggregate_budget_failure(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: &[RelationalAppliedOutput],
        aggregate_length: usize,
        status: &'static str,
        maximum: Option<usize>,
    ) {
        self.application_unresolved = true;
        let check = match maximum {
            Some(maximum) => json!({
                "candidate_index":candidate_index,
                "parser_format":format!("{:?}", candidate.rule.parser_format),
                "parser_scope":"across_sessions",
                "sessions":candidate_outputs.iter().map(|output| output.session.session).collect::<Vec<_>>(),
                "length":aggregate_length,
                "status":status,
                "maximum":maximum,
            }),
            None => json!({
                "candidate_index":candidate_index,
                "parser_format":format!("{:?}", candidate.rule.parser_format),
                "parser_scope":"across_sessions",
                "sessions":candidate_outputs.iter().map(|output| output.session.session).collect::<Vec<_>>(),
                "length":aggregate_length,
                "status":status,
                "remaining_work_bytes":self.replay_work_remaining,
            }),
        };
        self.aggregate_parser_checks.push(check);
    }

    fn validate_aggregate_bytes(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: &[RelationalAppliedOutput],
        aggregate: AggregateOutput,
    ) -> Result<Option<AppliedOutput>, super::RecoveryExecutionError> {
        let aggregate_length = aggregate.bytes.len();
        let parser_work_limit = self
            .replay_work_remaining
            .checked_sub(aggregate_length)
            .ok_or_else(|| invalid_policy("relational parser work limit underflowed"))?;
        let validator = aggregate_validator(
            self.artifact_validation_policy,
            aggregate_length,
            parser_work_limit,
        )?;
        let validation = validator.validate_as(candidate.rule.parser_format, &aggregate.bytes);
        let zip_expansion_work = match &validation {
            ArtifactValidationOutcome::Validated {
                structure: ArtifactStructure::Zip(report),
                ..
            } => report.expanded_work_byte_count,
            _ => 0,
        };
        let parser_work = aggregate_length
            .checked_add(zip_expansion_work)
            .ok_or_else(|| invalid_policy("relational parser work overflowed"))?;
        self.replay_work_remaining = self
            .replay_work_remaining
            .checked_sub(parser_work)
            .ok_or_else(|| invalid_policy("relational parser exceeded admitted work"))?;
        let (accepted, validation_status) = match &validation {
            ArtifactValidationOutcome::Validated { range, .. }
                if range.offset == 0 && range.length == aggregate_length =>
            {
                (true, "validated_exact_range")
            }
            ArtifactValidationOutcome::Validated { .. } => (false, "validated_non_exact_range"),
            ArtifactValidationOutcome::BoundaryUnproven { .. } => (false, "boundary_unproven"),
            ArtifactValidationOutcome::Rejected { .. } => (false, "rejected"),
            ArtifactValidationOutcome::Unsupported { .. } => (false, "unsupported"),
            ArtifactValidationOutcome::Omitted { .. } => (false, "omitted_on_parser_budget"),
        };
        self.aggregate_parser_checks.push(json!({
            "candidate_index":candidate_index,
            "parser_format":format!("{:?}", candidate.rule.parser_format),
            "parser_scope":"across_sessions",
            "sessions":aggregate.session_ids,
            "length":aggregate_length,
            "sha256":sha256(&aggregate.bytes),
            "parser_work_bytes":parser_work,
            "status":validation_status,
            "accepted":accepted,
            "result":format!("{validation:?}"),
        }));
        if accepted {
            return self.make_aggregate_output(
                candidate_index,
                candidate,
                candidate_outputs,
                aggregate,
            );
        }
        self.record_aggregate_rejection(&validation)?;
        Ok(None)
    }

    fn record_aggregate_rejection(
        &mut self,
        validation: &ArtifactValidationOutcome,
    ) -> Result<(), super::RecoveryExecutionError> {
        let parser_unresolved = matches!(validation, ArtifactValidationOutcome::Omitted { .. });
        self.application_unresolved |= parser_unresolved;
        if let Some(job) = self.job
            && !parser_unresolved
        {
            job.increment(Counter::CandidatesRejected, 1)?;
        }
        Ok(())
    }

    fn make_aggregate_output(
        &mut self,
        candidate_index: usize,
        candidate: &l2_workbench::protocol::RelationalTransformCandidate,
        candidate_outputs: &[RelationalAppliedOutput],
        aggregate: AggregateOutput,
    ) -> Result<Option<AppliedOutput>, super::RecoveryExecutionError> {
        let Some(first) = candidate_outputs.first() else {
            return Err(invalid_policy(
                "supported relational rule produced no session outputs",
            ));
        };
        let digest = sha256(&aggregate.bytes);
        if !self
            .aliases
            .insert((aggregate.session_ids.clone(), digest.clone()))
        {
            return Ok(None);
        }
        let work_bytes = aggregate
            .session_work
            .checked_add(aggregate.bytes.len())
            .ok_or_else(|| invalid_policy("relational aggregate work overflowed"))?;
        Ok(Some(AppliedOutput {
            candidate_index,
            value: RelationalAppliedOutput {
                session: first.session.clone(),
                session_order: first.session_order,
                seed_sample: first.seed_sample,
                payload_mappings: aggregate.payload_mappings,
                bytes: aggregate.bytes,
                parser_validation_deferred: false,
                work_bytes,
            },
            sha256: digest,
            parser_format: candidate.rule.parser_format,
            session_ids: aggregate.session_ids,
            session_orders: aggregate.session_orders,
            seed_samples: aggregate.seed_samples,
        }))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "preserve the single candidate retention transaction"
    )]
    fn retain_across_session_candidate(
        &mut self,
        candidate: AcrossSessionCandidate<'_>,
    ) -> Result<(), super::RecoveryExecutionError> {
        let AcrossSessionCandidate {
            candidate_index,
            rule,
            outputs,
            frames,
            mut assessment,
            status,
            priority,
            exact_aggregate_output,
        } = candidate;
        let accepted_schema = assessment.accepted_schema;
        if status == GateStatus::StructurallySupported
            && let Some(evidence) = assessment.structural_evidence.take()
        {
            self.structural_evidence
                .try_reserve(1)
                .map_err(|error| operational("structural evidence allocation failed", error))?;
            self.structural_evidence.push((candidate_index, evidence));
        }
        let keep_decoded_frames = should_retain_rule(status, self.context.input_coverage_complete);
        // Duplicate aliases keep the evidence graph bounded while preserving rank
        let decoded_alias = (
            outputs
                .iter()
                .flat_map(|output| {
                    output.payload_mappings.iter().map(|mapping| {
                        (
                            mapping.sample,
                            mapping.source_range.start,
                            mapping.source_range.end,
                            mapping.output_range.start,
                            mapping.output_range.end,
                        )
                    })
                })
                .collect::<Vec<_>>(),
            outputs
                .iter()
                .map(|output| sha256(&output.bytes))
                .collect::<Vec<_>>(),
            format!("{:?}", rule.parser_format),
        );
        let has_unique_decoded_alias =
            keep_decoded_frames && self.decoded_aliases.insert(decoded_alias);
        let candidate_retained_frames = if has_unique_decoded_alias || accepted_schema.is_some() {
            frames
        } else {
            Vec::new()
        };
        let mut candidate_retained_outputs = Vec::new();
        if candidate_retained_frames.is_empty() {
            self.application_evidence_checks.push(json!({
                "candidate_index":candidate_index,
                "status":status.as_str(),
                "artifact_validated":false,
                "structurally_supported":false,
                "details":assessment.details,
                "accepted_record_schema":accepted_schema.as_ref().map(accepted_record_schema_json),
            }));
        } else {
            self.qualified_rule_count = self.qualified_rule_count.saturating_add(1);
            if let Some(output) = exact_aggregate_output {
                candidate_retained_outputs.push(output);
            }
            self.application_evidence_checks.push(json!({
                "candidate_index":candidate_index,
                "status":status.as_str(),
                "artifact_validated":status == GateStatus::ArtifactValidated,
                "structurally_supported":status == GateStatus::StructurallySupported,
                "details":assessment.details,
                "accepted_record_schema":accepted_schema.as_ref().map(accepted_record_schema_json),
            }));
            let retained = RetainedRelationalRule {
                candidate_index,
                evidence_priority: priority,
                outputs: candidate_retained_outputs,
                decoded_frames: candidate_retained_frames,
                accepted_schema,
            };
            let maximum_materialized_rules = self.maximum_materialized_rules();
            let _ = retain_relational_rule(
                &mut self.retained_rules,
                &mut self.retained_frame_bytes,
                maximum_materialized_rules,
                self.search_plan.limits.max_total_bytes,
                retained,
            )?;
        }
        Ok(())
    }

    const fn maximum_materialized_rules(&self) -> usize {
        if self.search_plan.limits.max_retained_candidates < 8 {
            self.search_plan.limits.max_retained_candidates
        } else {
            8
        }
    }
}

pub(super) fn concatenate_outputs(
    outputs: &[RelationalAppliedOutput],
    aggregate_length: usize,
    job: Option<&Job>,
) -> Result<AggregateOutput, super::RecoveryExecutionError> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(aggregate_length)
        .map_err(|source| operational("relational aggregate output allocation failed", source))?;
    let mapping_count = outputs
        .iter()
        .try_fold(0_usize, |total, output| {
            total.checked_add(output.payload_mappings.len())
        })
        .ok_or_else(|| invalid_policy("relational payload mapping count overflowed"))?;
    let mut payload_mappings = Vec::new();
    payload_mappings
        .try_reserve_exact(mapping_count)
        .map_err(|source| operational("relational payload mapping allocation failed", source))?;
    let mut seed_samples = Vec::new();
    let mut session_ids = Vec::new();
    let mut session_orders = Vec::new();
    seed_samples
        .try_reserve_exact(outputs.len())
        .map_err(|source| operational("relational aggregate seed allocation failed", source))?;
    session_ids
        .try_reserve_exact(outputs.len())
        .map_err(|source| operational("relational aggregate session allocation failed", source))?;
    session_orders
        .try_reserve_exact(outputs.len())
        .map_err(|source| operational("relational aggregate order allocation failed", source))?;
    let mut session_work = 0_usize;
    for applied in outputs {
        validate_output_mappings(&applied.payload_mappings, applied.bytes.len(), job)?;
        let aggregate_offset = bytes.len();
        bytes.extend_from_slice(&applied.bytes);
        append_aggregate_mappings(
            &mut payload_mappings,
            aggregate_offset,
            &applied.payload_mappings,
            job,
        )?;
        seed_samples.push(applied.seed_sample);
        session_ids.push(applied.session.session);
        session_orders.push(applied.session_order);
        session_work = session_work
            .checked_add(applied.work_bytes)
            .ok_or_else(|| invalid_policy("relational session work overflowed"))?;
    }
    Ok(AggregateOutput {
        bytes,
        payload_mappings,
        seed_samples,
        session_ids,
        session_orders,
        session_work,
    })
}

fn validate_output_mappings(
    mappings: &[RelationalOutputMapping],
    output_length: usize,
    job: Option<&Job>,
) -> Result<(), super::RecoveryExecutionError> {
    let mut next_output_start = 0_usize;
    let mut samples = HashSet::new();
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    samples
        .try_reserve(mappings.len())
        .map_err(|source| operational("relational mapping index allocation failed", source))?;
    for (index, mapping) in mappings.iter().enumerate() {
        if index.is_multiple_of(256)
            && let Some(job) = job
        {
            job.check_cancelled()?;
        }
        let source_length = mapping
            .source_range
            .end
            .checked_sub(mapping.source_range.start)
            .ok_or(RecoveryError::InvariantFailure)?;
        let mapped_output_length = mapping
            .output_range
            .end
            .checked_sub(mapping.output_range.start)
            .ok_or(RecoveryError::InvariantFailure)?;
        if mapping.sample == 0
            || !samples.insert(mapping.sample)
            || source_length == 0
            || source_length != mapped_output_length
            || mapping.output_range.start != next_output_start
            || mapping.output_range.end > output_length
        {
            return Err(RecoveryError::InvariantFailure.into());
        }
        next_output_start = mapping.output_range.end;
    }
    if mappings.is_empty() || next_output_start != output_length {
        return Err(RecoveryError::InvariantFailure.into());
    }
    Ok(())
}

fn append_aggregate_mappings(
    mappings: &mut Vec<RelationalOutputMapping>,
    aggregate_offset: usize,
    applied_mappings: &[RelationalOutputMapping],
    job: Option<&Job>,
) -> Result<(), super::RecoveryExecutionError> {
    for (index, mapping) in applied_mappings.iter().enumerate() {
        if index.is_multiple_of(256)
            && let Some(job) = job
        {
            job.check_cancelled()?;
        }
        let output_range = mapping.output_range;
        mappings.push(RelationalOutputMapping {
            sample: mapping.sample,
            source_range: mapping.source_range,
            output_range: ByteRange {
                start: aggregate_offset
                    .checked_add(output_range.start)
                    .ok_or_else(|| invalid_policy("relational payload offset overflowed"))?,
                end: aggregate_offset
                    .checked_add(output_range.end)
                    .ok_or_else(|| invalid_policy("relational payload offset overflowed"))?,
            },
        });
    }
    Ok(())
}

pub(super) fn decoded_payload_frames(
    context: &DecodedFrameContext<'_>,
    applied: &RelationalAppliedOutput,
    rule: &RelationalTransformRule,
    transformed_output_sha256: &str,
) -> Result<Vec<DecodedFrameOutput>, super::RecoveryExecutionError> {
    validate_output_mappings(&applied.payload_mappings, applied.bytes.len(), context.job)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(applied.payload_mappings.len())
        .map_err(|source| operational("decoded relational frame allocation failed", source))?;
    for mapping in &applied.payload_mappings {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let sample = context
            .samples
            .iter()
            .find(|sample| sample.sample == mapping.sample)
            .ok_or(RecoveryError::InvariantFailure)?;
        let stored = context
            .stored_samples
            .iter()
            .find(|stored| stored.node_id == mapping.sample)
            .ok_or(RecoveryError::InvariantFailure)?;
        if sample.context.source != applied.session.source
            || sample.context.scope != applied.session.scope
            || sample.context.session != applied.session.session
            || sample.context.direction != rule.payload_locator.direction
            || sample.context != stored.context
            || sample.session_order != applied.session_order
            || stored.session_order != applied.session_order
        {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let transformed = applied
            .bytes
            .get(mapping.output_range.start..mapping.output_range.end)
            .ok_or(RecoveryError::InvariantFailure)?;
        let decoded = materialize_decoded_frame_bytes(
            sample.bytes,
            stored.stream_offset,
            transformed,
            mapping.source_range,
            context.raw_directional_run,
        )?;
        frames.push(DecodedFrameOutput {
            context: sample.context.clone(),
            input_node_id: sample.sample,
            seed_sample: applied.seed_sample,
            session_order: applied.session_order,
            transformed_output_sha256: transformed_output_sha256.to_owned(),
            direction_node_id: stored.direction_node_id,
            episode_node_id: stored.episode_node_id,
            stream_offset: decoded.stream_offset,
            candidate_index: context.candidate_index,
            parser_format: rule.parser_format,
            expected_session_orders: context.expected_session_orders.to_vec(),
            payload_range: decoded.payload_range,
            preserved_header_end: decoded.preserved_header_end,
            bytes: decoded.bytes,
        });
    }
    Ok(frames)
}

fn materialize_decoded_frame_bytes(
    sample_bytes: &[u8],
    stream_offset: usize,
    transformed: &[u8],
    source_range: ByteRange,
    raw_directional_run: bool,
) -> Result<DecodedFrameBytes, super::RecoveryExecutionError> {
    // Raw runs have no observed header; framed records keep their original header
    if raw_directional_run {
        let source_payload = sample_bytes
            .get(source_range.start..source_range.end)
            .ok_or(RecoveryError::InvariantFailure)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source_payload.len())
            .map_err(|source| operational("decoded relational frame allocation failed", source))?;
        bytes.extend_from_slice(transformed);
        let payload_end = bytes.len();
        let stream_offset = stream_offset
            .checked_add(source_range.start)
            .ok_or_else(|| invalid_policy("decoded stream offset overflowed"))?;
        Ok(DecodedFrameBytes {
            bytes,
            payload_range: ByteRange {
                start: 0,
                end: payload_end,
            },
            preserved_header_end: None,
            stream_offset,
        })
    } else {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(sample_bytes.len())
            .map_err(|source| operational("decoded relational frame allocation failed", source))?;
        bytes.extend_from_slice(sample_bytes);
        let destination = bytes
            .get_mut(source_range.start..source_range.end)
            .ok_or(RecoveryError::InvariantFailure)?;
        destination.copy_from_slice(transformed);
        Ok(DecodedFrameBytes {
            bytes,
            payload_range: source_range,
            preserved_header_end: Some(source_range.start),
            stream_offset,
        })
    }
}

fn retain_relational_rule(
    retained: &mut Vec<RetainedRelationalRule>,
    retained_frame_bytes: &mut usize,
    maximum_rules: usize,
    maximum_frame_bytes: usize,
    candidate: RetainedRelationalRule,
) -> Result<bool, super::RecoveryExecutionError> {
    if maximum_rules == 0 {
        return Ok(false);
    }
    let candidate_frame_bytes = candidate
        .decoded_frames
        .iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    let weakest_index = retained
        .iter()
        .enumerate()
        .min_by_key(|(_, existing)| {
            (
                existing.evidence_priority,
                usize::MAX - existing.candidate_index,
            )
        })
        .map(|(index, _)| index);
    let Some(weakest_index) = weakest_index.filter(|_| retained.len() >= maximum_rules) else {
        if candidate_frame_bytes > maximum_frame_bytes.saturating_sub(*retained_frame_bytes) {
            return Ok(false);
        }
        *retained_frame_bytes = retained_frame_bytes
            .checked_add(candidate_frame_bytes)
            .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
        retained
            .try_reserve(1)
            .map_err(|source| operational("retained relational rule allocation failed", source))?;
        retained.push(candidate);
        return Ok(true);
    };
    let weakest = retained
        .get(weakest_index)
        .ok_or(RecoveryError::InvariantFailure)?;
    let candidate_is_better = candidate.evidence_priority > weakest.evidence_priority
        || (candidate.evidence_priority == weakest.evidence_priority
            && candidate.candidate_index < weakest.candidate_index);
    if !candidate_is_better {
        return Ok(false);
    }
    let weakest_frame_bytes = weakest
        .decoded_frames
        .iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    let available_after_replacement = maximum_frame_bytes
        .saturating_sub(*retained_frame_bytes)
        .saturating_add(weakest_frame_bytes);
    if candidate_frame_bytes > available_after_replacement {
        return Ok(false);
    }
    *retained_frame_bytes = retained_frame_bytes
        .checked_sub(weakest_frame_bytes)
        .and_then(|total| total.checked_add(candidate_frame_bytes))
        .ok_or_else(|| invalid_policy("retained relational frame size overflowed"))?;
    *retained
        .get_mut(weakest_index)
        .ok_or(RecoveryError::InvariantFailure)? = candidate;
    Ok(true)
}

pub(super) fn validate_accepted_record_schema<'digest>(
    candidate_index: usize,
    frames: &[DecodedFrameOutput],
    accepted: &AcceptedRecordSchema,
    mut frame_digest: impl FnMut(
        usize,
        &DecodedFrameOutput,
    ) -> Result<Cow<'digest, str>, super::RecoveryExecutionError>,
) -> Result<(), super::RecoveryExecutionError> {
    if accepted.frame_indices.is_empty()
        || accepted.frame_indices.len() != accepted.frame_identities.len()
        || accepted.artifact_receipt.output_length.is_none()
        || accepted.artifact_receipt.output_sha256.is_none()
    {
        return Err(invalid_policy(
            "accepted record schema has incomplete frame or artifact evidence",
        ));
    }
    let mut previous_index = None;
    for (frame_index, identity) in accepted
        .frame_indices
        .iter()
        .copied()
        .zip(&accepted.frame_identities)
    {
        if previous_index.is_some_and(|previous| previous >= frame_index) {
            return Err(invalid_policy(
                "accepted record schema frame membership is not strictly ordered",
            ));
        }
        let frame = frames
            .get(frame_index)
            .ok_or_else(|| invalid_policy("accepted record schema references a missing frame"))?;
        // A fresh record parse can supply the same identity without another byte pass
        let frame_bytes_sha256 = frame_digest(frame_index, frame)?;
        validate_accepted_frame_identity(
            identity,
            frame,
            frame_index,
            frame.bytes.len(),
            &frame_bytes_sha256,
        )?;
        if frame.candidate_index != candidate_index
            || frame.parser_format != accepted.artifact_format
        {
            return Err(invalid_policy(
                "accepted record schema does not match its frozen candidate",
            ));
        }
        previous_index = Some(frame_index);
    }
    if accepted
        .artifact_receipt
        .parts
        .iter()
        .any(|part| part.input_index >= accepted.frame_indices.len())
    {
        return Err(invalid_policy(
            "accepted artifact receipt references a missing frame",
        ));
    }
    Ok(())
}

pub(super) fn validate_accepted_frame_identity(
    identity: &AcceptedFrameIdentity,
    frame: &DecodedFrameOutput,
    frame_index: usize,
    frame_byte_length: usize,
    frame_bytes_sha256: &str,
) -> Result<(), super::RecoveryExecutionError> {
    if identity.frame_index != frame_index
        || identity.input_node_id != frame.input_node_id
        || identity.context != frame.context
        || identity.session_order != frame.session_order
        || identity.stream_offset != frame.stream_offset
        || identity.frame_byte_length != frame_byte_length
        || identity.frame_byte_length != frame.bytes.len()
        || identity.frame_bytes_sha256 != frame_bytes_sha256
    {
        return Err(invalid_policy(
            "accepted record schema frame identity changed before materialization",
        ));
    }
    Ok(())
}

pub(super) fn accepted_record_schema_json(accepted: &AcceptedRecordSchema) -> Value {
    let strategy = match accepted.strategy {
        RecordSchemaStrategy::FixedLayout => "fixed_layout",
        RecordSchemaStrategy::RepeatedBoundaries => "repeated_boundaries",
    };
    let frame_identities = accepted.frame_identities.iter().map(|identity| {
        json!({
            "frame_index":identity.frame_index,
            "input_node_id":identity.input_node_id,
            "context":identity.context,
            "session_order":identity.session_order,
            "stream_offset":identity.stream_offset,
            "frame_byte_length":identity.frame_byte_length,
            "frame_bytes_sha256":identity.frame_bytes_sha256,
        })
    });
    json!({
        "schema":&accepted.schema,
        "strategy":strategy,
        "frame_indices":accepted.frame_indices,
        "frame_identities":frame_identities.collect::<Vec<_>>(),
        "artifact_receipt":&accepted.artifact_receipt,
        "artifact_format":format!("{:?}", accepted.artifact_format),
    })
}

pub(super) const fn should_retain_rule(status: GateStatus, input_coverage_complete: bool) -> bool {
    match status {
        GateStatus::ArtifactValidated => true,
        GateStatus::StructurallySupported => input_coverage_complete,
        GateStatus::Pending | GateStatus::Contradicted => false,
    }
}

pub(in crate::workbench::recovery_executor) fn aggregate_validator(
    mut policy: ArtifactValidationPolicy,
    input_length: usize,
    zip_expansion_budget: usize,
) -> Result<l2_workbench::artifact::ArtifactValidator, super::RecoveryExecutionError> {
    policy.max_input_bytes = policy.max_input_bytes.min(input_length);
    policy.png_limits.max_input_bytes = policy.png_limits.max_input_bytes.min(input_length);
    policy.zip_limits.max_archive_bytes = policy.zip_limits.max_archive_bytes.min(input_length);
    policy.zip_limits.max_entry_expanded_bytes = policy
        .zip_limits
        .max_entry_expanded_bytes
        .min(zip_expansion_budget.max(1));
    policy.zip_limits.max_total_expanded_bytes = policy
        .zip_limits
        .max_total_expanded_bytes
        .min(zip_expansion_budget);
    l2_workbench::artifact::ArtifactValidator::new(policy)
        .map_err(|source| operational("relational artifact parser policy was rejected", source))
}
