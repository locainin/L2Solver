//! Validate completed cohorts before resuming publication of a saved candidate

mod candidate;
mod report;

pub(in crate::workbench::recovery_executor::relational) use candidate::{
    CandidateVerification, verify_candidate,
};

use super::super::{
    PreparedRelationalCohort, RecoveryTask, operational, record_gate::SchemaCacheRestoreContext,
    search,
};
use super::{Executor, RelationalProgress};
use crate::workbench::recovery_executor::RecoveryExecutionError;
use l2_workbench::{
    job::{JsonMemoryAdmission, MemoryBudget, MemoryClass, admit_json},
    protocol::{
        RelationalParserScope, RelationalRecordSample, RelationalRestoreBudget,
        RelationalTransformEvaluationContext, RelationalTransformPlan,
        prepare_relational_session_partition, validate_relational_producer_parameters,
    },
    recovery::RecoveryError,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::{self, Write},
    mem::size_of_val,
};

pub(in crate::workbench::recovery_executor::relational) fn validate_prepared(
    executor: &Executor<'_>,
    progress: &RelationalProgress,
    memory: &MemoryBudget,
    work: &mut RelationalRestoreBudget,
    maximum_checkpoint_bytes: usize,
    maximum_workspace_bytes: usize,
) -> Result<(), RecoveryExecutionError> {
    charge_context_comparisons(executor, progress, work)?;
    progress.validate(executor)?;
    let contexts = executor
        .relational_discoveries
        .get(&progress.candidate_id)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if progress
        .prepared
        .iter()
        .zip(contexts)
        .any(|(cohort, expected)| cohort.context != *expected)
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let candidate = executor
        .coordinator
        .candidate(progress.candidate_id)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let source_plan = match candidate.task() {
        RecoveryTask::RelationalTransformDiscovery => &executor.policy.relational_transform_plan,
        RecoveryTask::RelationalTransformDiscoveryIncremental => executor
            .policy
            .relational_incremental_plan
            .as_ref()
            .ok_or(RecoveryError::InvalidCheckpoint)?,
        _ => return Err(RecoveryError::InvalidCheckpoint.into()),
    };
    if source_plan.parser_scope != RelationalParserScope::AcrossSessions {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    if progress.prepared.is_empty() {
        return Ok(());
    }
    let plan_bytes = plan_clone_bytes(source_plan)?;
    charge(work, plan_bytes)?;
    let _base_plan_memory = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(plan_bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("saved relational plan admission failed", error))?;
    let (_, base_plan) = executor.relational_task_plan(progress.candidate_id)?;
    let mut context = PreparedContext {
        executor,
        base_plan: &base_plan,
        memory,
        work,
        maximum_checkpoint_bytes,
        maximum_workspace_bytes,
    };
    let mut before = executor.coordinator.remaining_work_bytes();
    for cohort in &progress.prepared {
        validate_cohort(&mut context, cohort, before)?;
        before = cohort.work_bytes_remaining;
    }
    Ok(())
}

struct PreparedContext<'a, 'case> {
    executor: &'a Executor<'case>,
    base_plan: &'a RelationalTransformPlan,
    memory: &'a MemoryBudget,
    work: &'a mut RelationalRestoreBudget,
    maximum_checkpoint_bytes: usize,
    maximum_workspace_bytes: usize,
}

#[derive(Clone, Copy)]
struct CohortAccounting {
    before: usize,
    sample_bytes: usize,
    cohort_work_budget: usize,
}

fn validate_cohort(
    context: &mut PreparedContext<'_, '_>,
    cohort: &PreparedRelationalCohort,
    before: usize,
) -> Result<(), RecoveryExecutionError> {
    let executor = context.executor;
    let base_plan = context.base_plan;
    let memory = context.memory;
    let work = &mut *context.work;
    let maximum_checkpoint_bytes = context.maximum_checkpoint_bytes;
    let maximum_workspace_bytes = context.maximum_workspace_bytes;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let (_json_memory, value) = admit_report(cohort, memory, work, maximum_checkpoint_bytes)?;
    // The projection allowance also covers the cloned cohort plan and preflight report
    let report_workspace =
        report_workspace_needed(cohort, cohort.context.samples.len(), base_plan)?;
    if report_workspace > maximum_workspace_bytes {
        return Err(operational(
            "saved relational report workspace is too small",
            std::io::Error::other("report projection exceeds its configured limit"),
        ));
    }
    charge(work, report_workspace)?;
    let _report_workspace = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(report_workspace).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| {
            operational("saved relational report workspace admission failed", error)
        })?;
    let sample_memory = cohort
        .context
        .samples
        .iter()
        .try_fold(0_usize, |total, sample| {
            total
                .checked_add(4 * size_of::<RelationalRecordSample<'_>>())?
                .checked_add(sample.context.source.len().checked_mul(4)?)?
                .checked_add(sample.context.scope.len().checked_mul(4)?)
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    charge(work, sample_memory)?;
    let _sample_memory = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(sample_memory).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("saved relational sample admission failed", error))?;
    let samples = search::samples_for_context(executor.case, &cohort.context)?;
    let (plan, cohort_work_budget, sample_bytes) =
        search::configure_cohort(&cohort.context, &samples, base_plan, before)?;
    if report::preflight(cohort, &plan, &value, sample_bytes, before)? {
        return Ok(());
    }
    let accounting = CohortAccounting {
        before,
        sample_bytes,
        cohort_work_budget,
    };
    validate_searched_cohort(context, cohort, &plan, &value, &samples, accounting)
}

fn admit_report(
    cohort: &PreparedRelationalCohort,
    memory: &MemoryBudget,
    work: &mut RelationalRestoreBudget,
    maximum_checkpoint_bytes: usize,
) -> Result<(JsonMemoryAdmission, Value), RecoveryExecutionError> {
    if cohort.report_bytes.len() > maximum_checkpoint_bytes {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let report_work = cohort
        .report_bytes
        .len()
        .checked_mul(8)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    charge(work, report_work)?;
    let json_memory = admit_json(&cohort.report_bytes, memory, MemoryClass::Executor).map_err(
        |error| match error {
            l2_workbench::job::JsonMemoryError::InvalidJson { .. } => {
                RecoveryError::InvalidCheckpoint.into()
            }
            error => operational("saved relational report admission failed", error),
        },
    )?;
    let value: Value = serde_json::from_slice(&cohort.report_bytes)
        .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    // Publication writes these exact bytes, so reject alternate or duplicate-key encodings
    let mut canonical = ExactWriter {
        expected: &cohort.report_bytes,
        offset: 0,
    };
    serde_json::to_writer(&mut canonical, &value).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    if canonical.offset != cohort.report_bytes.len() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok((json_memory, value))
}

fn validate_searched_cohort(
    context: &mut PreparedContext<'_, '_>,
    cohort: &PreparedRelationalCohort,
    plan: &RelationalTransformPlan,
    value: &Value,
    samples: &[RelationalRecordSample<'_>],
    accounting: CohortAccounting,
) -> Result<(), RecoveryExecutionError> {
    let executor = context.executor;
    let memory = context.memory;
    let work = &mut *context.work;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    // The shared partition keeps the same complete-session split as discovery
    let (discovery, heldout, _partition_memory) =
        prepare_relational_session_partition(samples, plan.limits, job, memory, work)
            .map_err(cursor_error)?;
    let partition_count = discovery
        .len()
        .checked_add(heldout.len())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    charge(
        work,
        partition_count
            .checked_mul(size_of::<l2_workbench::protocol::RelationalSessionId>())
            .ok_or(RecoveryError::InvalidCheckpoint)?,
    )?;
    let mut canonical_bytes = 0_usize;
    for (index, session) in discovery.iter().chain(&heldout).enumerate() {
        if index.is_multiple_of(256)
            && let Some(job) = job
        {
            job.check_cancelled()?;
        }
        canonical_bytes = canonical_bytes
            .checked_add(2 * size_of::<l2_workbench::protocol::RelationalSessionId>())
            .and_then(|bytes| bytes.checked_add(session.source.len().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(session.scope.len().checked_mul(2)?))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
    }
    charge(work, canonical_bytes)?;
    let _canonical_memory = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(canonical_bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("saved session report admission failed", error))?;
    let canonical = search::empty_gate_report(&RelationalTransformEvaluationContext {
        discovery_sessions: &discovery,
        heldout_sessions: &heldout,
        work_bytes_remaining: plan.limits.max_work_bytes,
    });
    charge(work, membership_work(cohort, &canonical, value)?)?;
    for rule in cohort
        .producer_rules
        .iter()
        .map(|(_, rule)| rule)
        .chain(&cohort.published_rules)
    {
        validate_locator_limits(rule, plan)?;
    }
    let session_count = partition_count;
    if cohort.outputs.iter().any(|output| {
        output.session_ids.len() > session_count
            || output.session_orders.len() > session_count
            || output.seed_samples.len() > session_count
    }) {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    report::searched(report::SearchedReport {
        cohort,
        plan,
        canonical: &canonical,
        value,
        sample_bytes: accounting.sample_bytes,
        cohort_work_budget: accounting.cohort_work_budget,
        before: accounting.before,
    })?;
    verify_published(cohort, &canonical)?;
    verify_producers(context, cohort, plan, value, samples, &canonical)
}

fn verify_producers(
    context: &mut PreparedContext<'_, '_>,
    cohort: &PreparedRelationalCohort,
    plan: &RelationalTransformPlan,
    value: &Value,
    samples: &[RelationalRecordSample<'_>],
    canonical: &l2_workbench::protocol::RelationalTransformReport,
) -> Result<(), RecoveryExecutionError> {
    let executor = context.executor;
    let memory = context.memory;
    let work = &mut *context.work;
    let maximum_checkpoint_bytes = context.maximum_checkpoint_bytes;
    let maximum_workspace_bytes = context.maximum_workspace_bytes;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    let rules = value
        .get("retained_rules")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    for (index, rule) in &cohort.producer_rules {
        validate_relational_producer_parameters(plan, rule, job, work).map_err(cursor_error)?;
        let saved_schema = cohort
            .accepted_schemas
            .iter()
            .find(|(candidate, _)| candidate == index)
            .map(|(_, schema)| schema);
        let structural_evidence = cohort
            .structural_evidence
            .iter()
            .find(|(candidate, _)| candidate == index)
            .map(|(_, evidence)| evidence);
        let evidence = find_positive(
            value,
            "application_evidence_checks",
            *index,
            "artifact_validated",
            "structurally_supported",
        )?;
        let aggregate = find_positive(
            value,
            "aggregate_parser_checks",
            *index,
            "accepted",
            "accepted",
        )?;
        let mut context = SchemaCacheRestoreContext {
            raw_directional_run: cohort.context.key.framing_rule_json
                == super::super::RAW_RUN_FRAMING_RULE,
            samples,
            stored_samples: &cohort.context.samples,
            report: canonical,
            relational_limits: plan.limits,
            schema_limits: executor.policy.record_schema_proposal_limits,
            artifact_policy: executor.policy.artifact_validation_policy,
            maximum_checkpoint_bytes,
            maximum_workspace_bytes,
            memory,
            work: &mut *work,
            job,
        };
        verify_candidate(
            CandidateVerification {
                candidate_index: *index,
                rule,
                saved_outputs: &cohort.outputs,
                saved_frames: &cohort.decoded_frames,
                accepted_schema: saved_schema,
                structural_evidence,
                reported: rules.get(*index),
                reported_evidence: evidence,
                reported_aggregate: aggregate,
            },
            &mut context,
        )?;
    }
    Ok(())
}

fn report_workspace_needed(
    cohort: &super::super::PreparedRelationalCohort,
    maximum_sessions: usize,
    plan: &RelationalTransformPlan,
) -> Result<usize, RecoveryExecutionError> {
    let key = &cohort.context.key;
    let strings = [
        key.source_id.len(),
        key.scope_json.len(),
        key.endpoints_json.len(),
        key.framing_rule_json.len(),
        key.schema_json.len(),
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .ok_or(RecoveryError::InvalidCheckpoint)?;
    let entries = [
        cohort.context.sample_node_ids.len(),
        maximum_sessions,
        plan.parser_formats.len(),
        plan.counter_widths.len(),
        plan.counter_byte_orders.len(),
        plan.seed_orders.len(),
        plan.initial_counters.len(),
        plan.counter_resets.len(),
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .ok_or(RecoveryError::InvalidCheckpoint)?;
    entries
        .checked_mul(16 * size_of::<Value>())
        .and_then(|bytes| bytes.checked_add(strings.checked_mul(8)?))
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}

fn plan_clone_bytes(plan: &RelationalTransformPlan) -> Result<usize, RecoveryExecutionError> {
    let vectors = [
        size_of_val(plan.parser_formats.as_slice()),
        size_of_val(plan.counter_widths.as_slice()),
        size_of_val(plan.counter_byte_orders.as_slice()),
        size_of_val(plan.seed_orders.as_slice()),
        size_of_val(plan.initial_counters.as_slice()),
        size_of_val(plan.counter_resets.as_slice()),
    ];
    vectors
        .into_iter()
        .try_fold(size_of::<RelationalTransformPlan>(), usize::checked_add)
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}

struct ExactWriter<'a> {
    expected: &'a [u8],
    offset: usize,
}

impl Write for ExactWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("report length overflow"))?;
        if self.expected.get(self.offset..end) != Some(bytes) {
            return Err(io::Error::other("report is not canonical"));
        }
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn charge_context_comparisons(
    executor: &Executor<'_>,
    progress: &RelationalProgress,
    work: &mut RelationalRestoreBudget,
) -> Result<(), RecoveryExecutionError> {
    let contexts = executor
        .relational_discoveries
        .get(&progress.candidate_id)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if progress.prepared.len() > contexts.len() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    charge(
        work,
        progress
            .prepared
            .len()
            .checked_mul(size_of::<[usize; 8]>())
            .ok_or(RecoveryError::InvalidCheckpoint)?,
    )?;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    for cohort in &progress.prepared {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let context = &cohort.context;
        let key = &context.key;
        let mut bytes = context
            .sample_node_ids
            .len()
            .checked_mul(size_of::<u64>())
            .and_then(|bytes| {
                bytes.checked_add(
                    context
                        .samples
                        .len()
                        .checked_mul(size_of::<super::super::StoredSample>())?,
                )
            })
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        for length in [
            key.source_id.len(),
            key.scope_json.len(),
            key.endpoints_json.len(),
            key.framing_rule_json.len(),
            key.schema_json.len(),
        ] {
            bytes = bytes
                .checked_add(length)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
        }
        charge(work, bytes)?;
        for (index, sample) in context.samples.iter().enumerate() {
            if index.is_multiple_of(256)
                && let Some(job) = job
            {
                job.check_cancelled()?;
            }
            let bytes = sample
                .context
                .source
                .len()
                .checked_add(sample.context.scope.len())
                .ok_or(RecoveryError::InvalidCheckpoint)?;
            charge(work, bytes)?;
        }
    }
    Ok(())
}

fn find_positive<'a>(
    value: &'a Value,
    field: &str,
    index: usize,
    first: &str,
    second: &str,
) -> Result<Option<&'a Value>, RecoveryExecutionError> {
    let entries = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let mut matched = entries.iter().filter(|entry| {
        entry
            .get("candidate_index")
            .and_then(Value::as_u64)
            .and_then(|id| usize::try_from(id).ok())
            == Some(index)
            && (entry.get(first) == Some(&Value::Bool(true))
                || entry.get(second) == Some(&Value::Bool(true))
                || (field == "application_evidence_checks"
                    && matches!(
                        entry.get("status").and_then(Value::as_str),
                        Some("artifact_validated" | "structurally_supported")
                    )))
    });
    let first = matched.next();
    if matched.next().is_some() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(first)
}

fn verify_published(
    cohort: &super::super::PreparedRelationalCohort,
    report: &l2_workbench::protocol::RelationalTransformReport,
) -> Result<(), RecoveryExecutionError> {
    if !cohort.history_used {
        return if cohort.published_rules.is_empty() {
            Ok(())
        } else {
            Err(RecoveryError::InvalidCheckpoint.into())
        };
    }
    let sessions = report
        .discovery_sessions
        .iter()
        .chain(&report.heldout_sessions)
        .map(|session| session.session)
        .collect::<BTreeSet<_>>();
    let mut published = cohort.published_rules.iter();
    for (index, rule) in &cohort.producer_rules {
        let Some(output) = cohort
            .outputs
            .iter()
            .find(|output| output.candidate_index == *index)
        else {
            continue;
        };
        let actual = output.session_ids.iter().copied().collect::<BTreeSet<_>>();
        if !sessions.is_empty()
            && actual == sessions
            && output.session_ids.len() == sessions.len()
            && published.next() != Some(rule)
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    if published.next().is_some() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn charge(work: &mut RelationalRestoreBudget, bytes: usize) -> Result<(), RecoveryExecutionError> {
    if !work.try_charge_verification(bytes) {
        return Err(operational("saved cohort verification work limit reached",
            l2_workbench::protocol::RelationalCursorError::<std::convert::Infallible>::RestoreWorkLimit));
    }
    Ok(())
}

fn cursor_error(
    error: l2_workbench::protocol::RelationalCursorError<std::convert::Infallible>,
) -> RecoveryExecutionError {
    use l2_workbench::protocol::{RelationalCursorError, RelationalTransformError};
    match error {
        RelationalCursorError::InvalidCheckpoint
        | RelationalCursorError::Search(
            RelationalTransformError::InvalidPlan(_)
            | RelationalTransformError::InvalidInput(_)
            | RelationalTransformError::RecordTooLarge { .. }
            | RelationalTransformError::TotalBytesTooLarge { .. }
            | RelationalTransformError::TooManySessions { .. }
            | RelationalTransformError::TooManyRecords { .. },
        ) => RecoveryError::InvalidCheckpoint.into(),
        RelationalCursorError::Search(RelationalTransformError::Job(error)) => error.into(),
        error => operational("saved relational verification failed", error),
    }
}

fn membership_work(
    cohort: &super::super::PreparedRelationalCohort,
    canonical: &l2_workbench::protocol::RelationalTransformReport,
    value: &Value,
) -> Result<usize, RecoveryExecutionError> {
    let report_entries = [
        "application_evidence_checks",
        "aggregate_parser_checks",
        "retained_rules",
    ]
    .iter()
    .try_fold(0_usize, |total, key| {
        total.checked_add(value.get(*key)?.as_array()?.len())
    })
    .ok_or(RecoveryError::InvalidCheckpoint)?;
    let sessions = canonical
        .discovery_sessions
        .len()
        .checked_add(canonical.heldout_sessions.len())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let maximum_context = cohort
        .context
        .samples
        .iter()
        .try_fold(0_usize, |longest, sample| {
            Some(
                longest.max(
                    sample
                        .context
                        .source
                        .len()
                        .checked_add(sample.context.scope.len())?,
                ),
            )
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let maximum_markers = cohort
        .producer_rules
        .iter()
        .map(|(_, rule)| rule)
        .chain(&cohort.published_rules)
        .try_fold(0_usize, |longest, rule| {
            Some(
                longest.max(
                    rule.seed_locator
                        .marker
                        .len()
                        .checked_add(rule.payload_locator.marker.len())?,
                ),
            )
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let scans = report_entries
        .checked_add(cohort.outputs.len())
        .and_then(|count| count.checked_add(cohort.decoded_frames.len()))
        .and_then(|count| count.checked_add(cohort.accepted_schemas.len()))
        .and_then(|count| count.checked_add(cohort.structural_evidence.len()))
        .and_then(|count| count.checked_add(sessions.checked_mul(sessions)?))
        .and_then(|count| count.checked_add(cohort.published_rules.len()))
        .and_then(|count| count.checked_mul(cohort.producer_rules.len().saturating_add(1)))
        .and_then(|count| {
            count.checked_mul(
                maximum_context
                    .checked_add(maximum_markers)?
                    .checked_add(size_of::<[usize; 8]>())?,
            )
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    cohort
        .decoded_frames
        .iter()
        .try_fold(scans, |total, frame| {
            total
                .checked_add(frame.bytes.len())?
                .checked_add(
                    frame
                        .expected_session_orders
                        .len()
                        .checked_mul(size_of::<u64>())?,
                )?
                .checked_add(frame.transformed_output_sha256.len())
        })
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}

fn validate_locator_limits(
    rule: &l2_workbench::protocol::RelationalTransformRule,
    plan: &RelationalTransformPlan,
) -> Result<(), RecoveryExecutionError> {
    use l2_workbench::protocol::RelationalCoordinateBasis;
    let limits = plan.limits;
    let seed = &rule.seed_locator;
    let payload = &rule.payload_locator;
    if seed.coordinate_basis != RelationalCoordinateBasis::MessageStartV1
        || seed
            .value_length
            .is_none_or(|length| length == 0 || length > limits.max_seed_bytes)
        || seed.value_offset > limits.max_locator_offset
        || payload.value_offset > limits.max_locator_offset
        || payload.value_length.is_some()
        || payload.declared_length.is_some()
        || [seed, payload].iter().any(|locator| {
            locator.marker.is_empty()
                || locator.marker.len() > limits.max_marker_bytes
                || locator.marker_offset > limits.max_marker_offset
        })
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}
