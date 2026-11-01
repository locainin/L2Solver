//! Continue one queued relational candidate across durable search boundaries

use super::{ActiveSearch, RelationalProgress};
use crate::workbench::recovery_executor::relational::{
    GateAssessment, PreparedRelationalCohort, RelationalDiscoveryContext, operational,
    record_gate::{
        GateStatus, SchemaCacheRestoreContext, SchemaPlanCache, verify_assessment,
        verify_structural_assessment,
    },
    search::{self, CandidateGate, FinishEvaluationContext},
};
use crate::workbench::recovery_executor::{
    Executor, RecoveryCandidateId, RecoveryError, RecoveryExecutionError,
    checkpoint as executor_checkpoint, execution_state::SchedulerCursor, resume::RecoveryResume,
};
use l2_workbench::{
    job::{MemoryBudget, MemoryClass, MemoryLease, admit_json},
    protocol::{
        RelationalCursorError, RelationalEvaluationError, RelationalReplayHistory,
        RelationalRestoreBudget, RelationalSearchSession, RelationalSearchStep,
        RelationalTransformEvaluationContext, RelationalTransformEvaluationOptions,
    },
};

// Bound the amount of search between opportunities to save a completed candidate
const SEARCH_SLICE: usize = 32;

#[cfg(test)]
#[path = "../../../../../tests/workbench/recovery_relational/live_checkpoint.rs"]
mod tests;

#[expect(
    clippy::too_many_lines,
    reason = "keep cohort preparation and history return together"
)]
pub(in crate::workbench::recovery_executor) fn prepare(
    executor: &mut Executor<'_>,
    candidate_id: RecoveryCandidateId,
    cursor: &mut SchedulerCursor,
    resume: &mut RecoveryResume<'_>,
) -> Result<(Vec<PreparedRelationalCohort>, usize, Vec<MemoryLease>), RecoveryExecutionError> {
    if cursor.active_relational.is_none() {
        cursor.active_relational = Some(RelationalProgress {
            candidate_id,
            next_context: 0,
            work_remaining: executor.coordinator.remaining_work_bytes(),
            prepared: Vec::new(),
            active: None,
        });
    }
    let (_, base_plan) = executor.relational_task_plan(candidate_id)?;
    let memory = resume.session_memory();
    let mut restore_work = restore_budget(&base_plan, resume.executor_limit())?;
    if cursor.restoration_pending {
        // Completed cohorts and the active cursor share one finite verification allowance
        let progress = cursor
            .active_relational
            .as_ref()
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        super::prepared::validate_prepared(
            executor,
            progress,
            &memory,
            &mut restore_work,
            resume.executor_limit(),
            resume.executor_limit(),
        )?;
    }
    let mut cohort_memory = Vec::new();
    loop {
        executor.check_cancelled()?;
        let progress = cursor
            .active_relational
            .as_mut()
            .ok_or(RecoveryError::InvariantFailure)?;
        let contexts = executor
            .relational_discoveries
            .get(&candidate_id)
            .ok_or(RecoveryError::InvariantFailure)?;
        if progress.next_context == contexts.len() {
            let progress = cursor
                .active_relational
                .take()
                .ok_or(RecoveryError::InvariantFailure)?;
            return Ok((progress.prepared, progress.work_remaining, cohort_memory));
        }
        let context = contexts
            .get(progress.next_context)
            .ok_or(RecoveryError::InvalidCheckpoint)?
            .clone();
        let saved = progress.active.take();
        let remaining = progress.work_remaining;
        let (mut history, history_memory) =
            take_history(executor, &context, saved.as_ref(), &memory)?;
        cursor.restored_memory.extend(history_memory);
        // The borrowed history always returns to its slot, even on cancellation or failure
        let result = prepare_one(
            executor,
            &context,
            &base_plan,
            remaining,
            history.as_mut(),
            saved,
            cursor,
            resume,
            &memory,
            &mut restore_work,
        );
        if let Some(history) = history {
            executor
                .relational_samples
                .histories
                .return_context(&context, history)?;
        }
        let (cohort, remaining, admission) = result?;
        cohort_memory
            .try_reserve(1)
            .map_err(|error| operational("relational cohort charge allocation failed", error))?;
        cohort_memory.push(admission);
        let progress = cursor
            .active_relational
            .as_mut()
            .ok_or(RecoveryError::InvariantFailure)?;
        progress
            .prepared
            .try_reserve(1)
            .map_err(|error| operational("relational report allocation failed", error))?;
        progress.prepared.push(cohort);
        progress.next_context += 1;
        progress.work_remaining = remaining;
    }
}

fn take_history(
    executor: &mut Executor<'_>,
    context: &RelationalDiscoveryContext,
    saved: Option<&ActiveSearch>,
    memory: &MemoryBudget,
) -> Result<(Option<RelationalReplayHistory>, Vec<MemoryLease>), RecoveryExecutionError> {
    let limits = executor.policy.relational_transform_plan.limits;
    if let Some(saved) = saved {
        if saved.history.is_empty() {
            return Ok((None, Vec::new()));
        }
        let (history, leases) = decode_history(&saved.history, limits.max_total_bytes, memory)?;
        let history = executor
            .relational_samples
            .histories
            .take_restored_context(context, limits.max_total_bytes, history)?;
        return Ok((Some(history), leases));
    }
    if executor.policy.relational_incremental_plan.is_some()
        && executor
            .relational_samples
            .incremental_metadata_stop
            .is_none()
    {
        return Ok((
            executor.relational_samples.histories.take_for_context(
                context,
                limits.max_cohorts,
                limits.max_total_bytes,
            ),
            Vec::new(),
        ));
    }
    Ok((None, Vec::new()))
}

fn decode_history(
    bytes: &[u8],
    maximum: usize,
    memory: &MemoryBudget,
) -> Result<(RelationalReplayHistory, Vec<MemoryLease>), RecoveryExecutionError> {
    #[derive(serde::Deserialize)]
    struct Ceiling {
        max_bytes: usize,
    }
    let admission = admit_json(bytes, memory, MemoryClass::Executor)
        .map_err(|error| operational("relational history admission failed", error))?;
    let ceiling: Ceiling =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    if ceiling.max_bytes > maximum {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    // Capacity fields can allocate independently of the encoded JSON length
    let mut capacity = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(ceiling.max_bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("relational history capacity admission failed", error))?;
    let history: RelationalReplayHistory =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    capacity
        .try_resize(
            u64::try_from(history.storage_bytes()).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("relational history capacity admission failed", error))?;
    Ok((history, vec![admission.into_retained(), capacity]))
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "keep one cohort's frozen search state together"
)]
fn prepare_one(
    executor: &Executor<'_>,
    context: &RelationalDiscoveryContext,
    base_plan: &l2_workbench::protocol::RelationalTransformPlan,
    mut remaining: usize,
    history: Option<&mut RelationalReplayHistory>,
    saved: Option<ActiveSearch>,
    cursor: &mut SchedulerCursor,
    resume: &mut RecoveryResume<'_>,
    memory: &MemoryBudget,
    restore_work: &mut RelationalRestoreBudget,
) -> Result<(PreparedRelationalCohort, usize, MemoryLease), RecoveryExecutionError> {
    let samples = search::samples_for_context(executor.case, context)?;
    let (plan, cohort_budget, sample_bytes) =
        search::configure_cohort(context, &samples, base_plan, remaining)?;
    if context.sessions_available < 2 || sample_bytes >= remaining {
        if saved.is_some() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let mut cohort = search::prepare_cohort(
            executor,
            context.clone(),
            base_plan,
            &mut remaining,
            history,
        )?;
        let admission = admit_prepared(&mut cohort, memory)?;
        return Ok((cohort, remaining, admission));
    }
    let preparation_bytes = RelationalSearchSession::preparation_memory_bytes(&samples, &plan)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let _preparation = memory
        .try_reserve(MemoryClass::Executor, preparation_bytes)
        .map_err(|error| operational("relational preparation admission failed", error))?;
    let _retained = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(plan.limits.max_total_bytes)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("relational search admission failed", error))?;
    let job = executor.job.as_ref().map(|progress| &progress.job);
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        job,
        RelationalTransformEvaluationOptions {
            max_retained_output_bytes: plan.limits.max_total_bytes,
        },
        history,
    )?;
    let mut gate = CandidateGate::new(
        &samples,
        &context.samples,
        context.key.framing_rule_json == super::super::RAW_RUN_FRAMING_RULE,
        executor.policy.record_schema_proposal_limits,
        executor.policy.artifact_validation_policy,
        job,
    )
    .with_structural_admission(memory, resume.executor_limit());
    let mut assessment_memory = Vec::new();
    let mut restored_memory = None;
    let mut search_cursor = if let Some(saved) = saved {
        let (restored, lease) = session
            .restore_checkpoint(
                &saved.cursor,
                resume.executor_limit(),
                memory,
                restore_work,
                |evaluation_context, candidate, _outputs, value, work| {
                    let (encoded, _encoded_memory) =
                        executor_checkpoint::encode(&value, resume.executor_limit(), Some(memory))
                            .map_err(RelationalCursorError::Assessment)?;
                    let admission =
                        admit_json(&encoded, memory, MemoryClass::Executor).map_err(|error| {
                            RelationalCursorError::Assessment(operational(
                                "relational assessment admission failed",
                                error,
                            ))
                        })?;
                    let assessment: GateAssessment = serde_json::from_value(value)
                        .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
                    validate_saved_assessment(search::initial_gate_status(candidate), &assessment)?;
                    if assessment.accepted_schema.is_some()
                        || assessment.structural_evidence.is_some()
                    {
                        let report = search::empty_gate_report(evaluation_context);
                        let mut validation = SchemaCacheRestoreContext {
                            raw_directional_run: context.key.framing_rule_json
                                == super::super::RAW_RUN_FRAMING_RULE,
                            samples: &samples,
                            stored_samples: &context.samples,
                            report: &report,
                            relational_limits: plan.limits,
                            schema_limits: executor.policy.record_schema_proposal_limits,
                            artifact_policy: executor.policy.artifact_validation_policy,
                            maximum_checkpoint_bytes: resume.executor_limit(),
                            maximum_workspace_bytes: resume.executor_limit(),
                            memory,
                            work,
                            job,
                        };
                        if let Some(accepted) = &assessment.accepted_schema {
                            verify_assessment(&candidate.rule, accepted, &mut validation)
                                .map_err(RelationalCursorError::Assessment)?;
                        }
                        if let Some(evidence) = &assessment.structural_evidence {
                            verify_structural_assessment(
                                &candidate.rule,
                                evidence,
                                &mut validation,
                            )
                            .map_err(RelationalCursorError::Assessment)?;
                        }
                    }
                    assessment_memory.push(admission.into_retained());
                    Ok(assessment)
                },
            )
            .map_err(|error| cursor_error(error, job))?;
        if restored.candidates_examined() != saved.candidates_examined {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let (discovery, heldout) = restored.session_partition();
        let report = search::empty_gate_report(&RelationalTransformEvaluationContext {
            discovery_sessions: discovery,
            heldout_sessions: heldout,
            work_bytes_remaining: 0,
        });
        gate.schema_plan_cache = SchemaPlanCache::restore_checkpoint(
            &saved.gate,
            SchemaCacheRestoreContext {
                raw_directional_run: context.key.framing_rule_json
                    == super::super::RAW_RUN_FRAMING_RULE,
                samples: &samples,
                stored_samples: &context.samples,
                report: &report,
                relational_limits: plan.limits,
                schema_limits: executor.policy.record_schema_proposal_limits,
                artifact_policy: executor.policy.artifact_validation_policy,
                maximum_checkpoint_bytes: resume.executor_limit(),
                maximum_workspace_bytes: resume.executor_limit(),
                memory,
                work: restore_work,
                job,
            },
        )?;
        restored_memory = Some(lease);
        #[cfg(test)]
        resume.check_relational_allocation_test_failure()?;
        cursor.restoration_pending = false;
        #[cfg(test)]
        resume.relational_restored(restored.candidates_examined(), job)?;
        Some(restored)
    } else {
        None
    };
    loop {
        let step = session
            .step(
                search_cursor.take(),
                SEARCH_SLICE,
                |evaluation_context, candidate, discovery, heldout| {
                    gate.evaluate(evaluation_context, candidate, discovery, heldout)
                },
            )
            .map_err(evaluation_error)?;
        match step {
            RelationalSearchStep::Complete(evaluation) => {
                let result = search::finish_evaluation(
                    FinishEvaluationContext {
                        context,
                        samples: &samples,
                        search_plan: &plan,
                        cohort_work_budget: cohort_budget,
                        artifact_validation_policy: executor.policy.artifact_validation_policy,
                        job,
                        gate: &gate,
                        history_complete: session
                            .history()
                            .map(RelationalReplayHistory::is_complete),
                    },
                    evaluation,
                )?;
                let mut cohort =
                    search::finish_cohort(context.clone(), result, sample_bytes, &mut remaining)?;
                let admission = admit_prepared(&mut cohort, memory)?;
                drop(restored_memory);
                drop(assessment_memory);
                return Ok((cohort, remaining, admission));
            }
            RelationalSearchStep::Paused(next) => {
                #[cfg(test)]
                let cached_plans = gate.schema_plan_cache.checkpoint_plan_count();
                #[cfg(test)]
                let forced = resume.wants_populated_checkpoint()
                    && next.candidates_examined() > 0
                    && cached_plans > 0;
                #[cfg(not(test))]
                let forced = false;
                if resume.due() || forced {
                    save_boundary(executor, cursor, resume, memory, &session, &next, &gate)?;
                    #[cfg(test)]
                    if forced {
                        resume.after_populated_checkpoint(
                            next.candidates_examined(),
                            cached_plans,
                            job,
                            session.history(),
                        )?;
                    }
                }
                search_cursor = Some(next);
            }
        }
    }
}

fn admit_prepared(
    cohort: &mut PreparedRelationalCohort,
    memory: &MemoryBudget,
) -> Result<MemoryLease, RecoveryExecutionError> {
    let limit = usize::try_from(
        memory
            .snapshot()
            .map_err(|error| operational("relational memory snapshot failed", error))?
            .limit_bytes,
    )
    .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    // Charge the retained data by its actual bounded representation, not the cohort maximum
    let (encoded, _encoded_memory) = executor_checkpoint::encode(&*cohort, limit, Some(memory))?;
    let admission = admit_json(&encoded, memory, MemoryClass::Executor)
        .map_err(|error| operational("relational cohort admission failed", error))?;
    let retained = admission.into_retained();
    cohort.producer_memory = None;
    for (_, evidence) in &mut cohort.structural_evidence {
        evidence.release_capture_admission();
    }
    Ok(retained)
}

fn save_boundary(
    executor: &Executor<'_>,
    cursor: &mut SchedulerCursor,
    resume: &mut RecoveryResume<'_>,
    memory: &MemoryBudget,
    session: &RelationalSearchSession<'_, '_>,
    search_cursor: &l2_workbench::protocol::RelationalSearchCursor<GateAssessment>,
    gate: &CandidateGate<'_>,
) -> Result<(), RecoveryExecutionError> {
    let limit = resume.executor_limit();
    let Some((encoded_cursor, cursor_memory)) =
        encode_cursor(executor, resume, memory, session, search_cursor)?
    else {
        return Ok(());
    };
    #[cfg(test)]
    let gate_limit =
        resume.inner_checkpoint_test_limit(super::super::super::resume::TestCheckpointPart::Gate);
    #[cfg(not(test))]
    let gate_limit = limit;
    let Some(description) = checkpoint_or_fallback(
        gate.schema_plan_cache.checkpoint_description(
            executor
                .policy
                .record_schema_proposal_limits
                .discovery
                .record_limits,
            gate_limit,
        ),
        executor,
        resume,
    )?
    else {
        return Ok(());
    };
    let Some((encoded_gate, gate_memory)) = checkpoint_or_fallback(
        executor_checkpoint::encode(&description, gate_limit, Some(memory)),
        executor,
        resume,
    )?
    else {
        return Ok(());
    };
    let (encoded_history, history_memory) = if let Some(history) = session.history() {
        let Some(encoded) = checkpoint_or_fallback(
            executor_checkpoint::encode(history, limit, Some(memory)),
            executor,
            resume,
        )?
        else {
            return Ok(());
        };
        encoded
    } else {
        (Vec::new(), None)
    };
    let mut leases = vec![cursor_memory];
    leases.extend(gate_memory);
    leases.extend(history_memory);
    cursor
        .active_relational
        .as_mut()
        .ok_or(RecoveryError::InvariantFailure)?
        .active = Some(ActiveSearch {
        cursor: encoded_cursor,
        gate: encoded_gate,
        history: encoded_history,
        candidates_examined: search_cursor.candidates_examined(),
        _memory: leases,
    });
    resume.save_incremental_or_fallback(executor, cursor)?;
    cursor
        .active_relational
        .as_mut()
        .ok_or(RecoveryError::InvariantFailure)?
        .active = None;
    Ok(())
}

fn encode_cursor(
    executor: &Executor<'_>,
    resume: &mut RecoveryResume<'_>,
    memory: &MemoryBudget,
    session: &RelationalSearchSession<'_, '_>,
    search_cursor: &l2_workbench::protocol::RelationalSearchCursor<GateAssessment>,
) -> Result<Option<(Vec<u8>, MemoryLease)>, RecoveryExecutionError> {
    #[cfg(test)]
    let limit =
        resume.inner_checkpoint_test_limit(super::super::super::resume::TestCheckpointPart::Cursor);
    #[cfg(not(test))]
    let limit = resume.executor_limit();
    let encoded = session.encode_checkpoint(search_cursor, limit, memory, |assessment, writer| {
        validate_saved_assessment(None, assessment)
            .map_err(|_| RecoveryError::InvalidCheckpoint)?;
        serde_json::to_writer(writer, assessment)
            .map_err(|error| operational("relational assessment encoding failed", error))
    });
    match encoded {
        Ok(value) => Ok(Some(value)),
        Err(error @ RelationalCursorError::CheckpointTooLarge) => {
            resume.unrepresentable_or_error(
                executor,
                operational("relational cursor encoding failed", error),
            )?;
            Ok(None)
        }
        Err(error) => Err(operational("relational cursor encoding failed", error)),
    }
}

fn checkpoint_or_fallback<T>(
    result: Result<T, RecoveryExecutionError>,
    executor: &Executor<'_>,
    resume: &mut RecoveryResume<'_>,
) -> Result<Option<T>, RecoveryExecutionError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if executor_checkpoint::unavailable_reason(&error)
                == Some(executor_checkpoint::CheckpointUnavailable::SizeLimit) =>
        {
            resume.unrepresentable_or_error(executor, error)?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn restore_budget(
    plan: &l2_workbench::protocol::RelationalTransformPlan,
    max_checkpoint: usize,
) -> Result<RelationalRestoreBudget, RecoveryExecutionError> {
    let verification = max_checkpoint
        .checked_mul(64)
        .and_then(|bytes| {
            plan.limits
                .max_work_bytes
                .checked_mul(4)
                .and_then(|work| bytes.checked_add(work))
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let schedule = plan
        .limits
        .max_locator_candidates
        .checked_mul(plan.limits.max_locator_candidates)
        .and_then(|pairs| pairs.checked_mul(4))
        .and_then(|pairs| {
            plan.limits
                .max_candidates
                .checked_mul(4)
                .and_then(|candidates| pairs.checked_add(candidates))
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    Ok(RelationalRestoreBudget::new(verification, schedule))
}

fn cursor_error(
    error: RelationalCursorError<RecoveryExecutionError>,
    job: Option<&l2_workbench::job::Job>,
) -> RecoveryExecutionError {
    if let Some(job) = job
        && let Err(cancelled) = job.check_cancelled()
    {
        return cancelled.into();
    }
    match error {
        RelationalCursorError::Assessment(error) => error,
        other => operational("relational cursor restoration failed", other),
    }
}

fn validate_saved_assessment(
    initial: Option<GateStatus>,
    assessment: &GateAssessment,
) -> Result<(), RelationalCursorError<RecoveryExecutionError>> {
    if initial.is_some_and(|status| status != assessment.status)
        || (assessment.status == GateStatus::ArtifactValidated)
            != assessment.accepted_schema.is_some()
        || (assessment.status == GateStatus::StructurallySupported)
            != assessment.structural_evidence.is_some()
    {
        return Err(RelationalCursorError::InvalidCheckpoint);
    }
    Ok(())
}

fn evaluation_error(
    error: RelationalEvaluationError<RecoveryExecutionError>,
) -> RecoveryExecutionError {
    match error {
        RelationalEvaluationError::Search(error) => error.into(),
        RelationalEvaluationError::Evaluator(error) => error,
        RelationalEvaluationError::EvaluatorWorkLimit { .. } => {
            super::super::invalid_policy("relational record gate exceeded its shared work budget")
        }
        _ => super::super::invalid_policy("relational candidate evaluation failed unexpectedly"),
    }
}
