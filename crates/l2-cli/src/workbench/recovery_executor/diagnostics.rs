//! Summarize completed candidate work without retaining candidate histories

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor/diagnostics.rs"]
mod tests;

use super::{RecoveryExecutionError, RecoveryOmission};
use l2_workbench::{
    evidence::Case,
    job::{
        Job, MAX_RECOVERY_FUNNEL_INPUTS, RecoveryCandidateSample, RecoveryFunnelAdmission,
        RecoveryFunnelEvent, RecoveryFunnelIdentity, RecoveryFunnelInput,
        RecoveryFunnelRegistration, RecoveryTransition, RecoveryTransitionOutcome,
        RecoveryTransitionSample, RecoveryTransitionSourceRange, RecoveryTransitionStage,
    },
    recovery::{
        RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState, RecoveryCoordinator,
        RecoveryError, RecoveryResult, RecoveryTask,
    },
};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(super) fn record_candidate(
    job: &Job,
    case: &Case,
    coordinator: &RecoveryCoordinator,
    candidate_id: RecoveryCandidateId,
    omissions: &[RecoveryOmission],
) -> Result<(), RecoveryExecutionError> {
    let candidate = coordinator
        .candidate(candidate_id)
        .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
    let (RecoveryCandidateState::Finished { result, .. }
    | RecoveryCandidateState::ContextPending { result, .. }) = candidate.state()
    else {
        return Ok(());
    };
    let stage = stage(candidate.task());
    let evidence_node_id = result
        .evidence_link_contract()
        .map(|contract| contract.node_id);
    let sample = candidate_sample(case, candidate_id, candidate, evidence_node_id)?;
    let outcome = match result {
        RecoveryResult::ObservedValidation { .. } => RecoveryTransitionOutcome::Validated,
        RecoveryResult::Derived { .. } => RecoveryTransitionOutcome::Derived,
        RecoveryResult::Hypothesis { .. } if is_discovery(candidate.task()) => {
            RecoveryTransitionOutcome::ReportRetained
        }
        RecoveryResult::Hypothesis { .. } => RecoveryTransitionOutcome::Hypothesis,
        RecoveryResult::Rejected { .. } => RecoveryTransitionOutcome::Contradicted,
        RecoveryResult::Unsupported => RecoveryTransitionOutcome::Unsupported,
        RecoveryResult::Omitted => RecoveryTransitionOutcome::WorkOmitted,
        RecoveryResult::ResourceExhausted { .. } => RecoveryTransitionOutcome::BudgetExhausted,
    };
    job.record_recovery_transition(RecoveryTransition {
        stage,
        outcome,
        sample: Some(RecoveryTransitionSample::Candidate(sample)),
    })?;
    // A merged discovery may produce a different report for each source cohort
    if candidate.task() != &RecoveryTask::RecordDiscovery
        || outcome != RecoveryTransitionOutcome::ReportRetained
    {
        let mut funnel_outcome =
            funnel_candidate_outcome(case, candidate.task(), outcome, evidence_node_id);
        if matches!(candidate.task(), RecoveryTask::AssembleRecords(_))
            && funnel_outcome == RecoveryTransitionOutcome::Derived
            && omissions
                .iter()
                .any(|omission| matches!(omission, RecoveryOmission::RecordInputRejected { .. }))
        {
            // A partial parse cannot establish assembly of the complete session
            funnel_outcome = RecoveryTransitionOutcome::ReportRetained;
        }
        record_funnel_candidate(job, case, candidate, stage, funnel_outcome, sample)?;
    }

    // A discovery receipt can describe an empty search instead of a surviving schema
    if candidate.task() == &RecoveryTask::RecordDiscovery
        && evidence_node_id
            .and_then(|id| case.node(id))
            .is_some_and(|node| {
                node.details
                    .get("result")
                    .and_then(serde_json::Value::as_str)
                    == Some("hypotheses_found")
            })
    {
        job.record_recovery_transition(RecoveryTransition {
            stage,
            outcome: RecoveryTransitionOutcome::Hypothesis,
            sample: Some(RecoveryTransitionSample::Candidate(sample)),
        })?;
    }
    record_omission_transitions(job, case, candidate, stage, sample, omissions)
}

fn funnel_candidate_outcome(
    case: &Case,
    task: &RecoveryTask,
    outcome: RecoveryTransitionOutcome,
    evidence_node_id: Option<u64>,
) -> RecoveryTransitionOutcome {
    if outcome != RecoveryTransitionOutcome::Derived {
        return outcome;
    }
    let details = evidence_node_id
        .and_then(|id| case.node(id))
        .map(|node| &node.details);
    let complete_output = match task {
        RecoveryTask::MaterializeFraming(_) => details
            .and_then(|details| details.get("frame_count"))
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|count| count > 0),
        RecoveryTask::AssembleRecords(_) => details.is_some_and(|details| {
            let groups = details
                .get("group_count")
                .and_then(serde_json::Value::as_u64);
            let complete = details
                .get("complete_group_count")
                .and_then(serde_json::Value::as_u64);
            let incomplete = details
                .get("incomplete_group_count")
                .and_then(serde_json::Value::as_u64);
            groups.is_some_and(|count| count > 0) && groups == complete && incomplete == Some(0)
        }),
        _ => true,
    };
    if complete_output {
        outcome
    } else {
        // A receipt can describe an empty output or an incomplete record group
        RecoveryTransitionOutcome::ReportRetained
    }
}

fn record_omission_transitions(
    job: &Job,
    case: &Case,
    candidate: &RecoveryCandidate,
    stage: RecoveryTransitionStage,
    sample: RecoveryCandidateSample,
    omissions: &[RecoveryOmission],
) -> Result<(), RecoveryExecutionError> {
    for omission in omissions {
        match omission {
            RecoveryOmission::RecordInputRejected {
                input_index,
                input_node_id,
                ..
            } => {
                let input = candidate
                    .inputs()
                    .get(*input_index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                if !input.origin_node_ids().contains(input_node_id) {
                    return Err(RecoveryError::InvariantFailure.into());
                }
                let rejected = RecoveryCandidateSample {
                    input_node_id: *input_node_id,
                    input_blob_sha256: parse_digest(input.blob_id())?,
                    source_range: source_range(case, *input_node_id)?,
                    ..sample
                };
                job.record_recovery_transition(RecoveryTransition {
                    stage: RecoveryTransitionStage::Assembly,
                    outcome: RecoveryTransitionOutcome::InputContradicted,
                    sample: Some(RecoveryTransitionSample::Candidate(rejected)),
                })?;
                job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
                    stage: RecoveryTransitionStage::Assembly,
                    outcome: RecoveryTransitionOutcome::InputContradicted,
                    candidate: &rejected,
                    input_nodes: &[*input_node_id],
                    parent_candidates: &[],
                    attribution_complete: true,
                    attribution: l2_workbench::job::RecoveryFunnelAttribution::ExactInputs,
                    validated_artifact_sha256: None,
                })?;
            }
            RecoveryOmission::RecordDiscoveryAnalysis {
                search_exhaustive_within_plan: false,
                ..
            }
            | RecoveryOmission::FramingDiscoveryAnalysis {
                search_exhaustive_within_plan: false,
                ..
            }
            | RecoveryOmission::TransformDiscoveryAnalysis {
                omitted_candidates: 1..,
                ..
            }
            | RecoveryOmission::XorSearchLimit { .. }
            | RecoveryOmission::XorMessageOmission { .. } => {
                job.record_recovery_transition(RecoveryTransition {
                    stage,
                    outcome: RecoveryTransitionOutcome::WorkOmitted,
                    sample: Some(RecoveryTransitionSample::Candidate(sample)),
                })?;
                if candidate.task() != &RecoveryTask::RecordDiscovery {
                    record_funnel_candidate(
                        job,
                        case,
                        candidate,
                        stage,
                        RecoveryTransitionOutcome::WorkOmitted,
                        sample,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn record_funnel_candidate(
    job: &Job,
    case: &Case,
    candidate: &RecoveryCandidate,
    stage: RecoveryTransitionStage,
    outcome: RecoveryTransitionOutcome,
    sample: RecoveryCandidateSample,
) -> Result<(), RecoveryExecutionError> {
    // A capped association list bounds diagnostic work independently of recovery work
    let mut inputs = candidate
        .inputs()
        .iter()
        .flat_map(|input| input.origin_node_ids().iter().copied())
        .take(MAX_RECOVERY_FUNNEL_INPUTS + 1)
        .collect::<Vec<_>>();
    let mut parents = candidate
        .parent_ids()
        .iter()
        .take(MAX_RECOVERY_FUNNEL_INPUTS + 1)
        .map(|id| u64::try_from(id.index()).map_err(|_| RecoveryError::InvariantFailure))
        .collect::<Result<Vec<_>, _>>()?;
    let attribution_complete =
        inputs.len() <= MAX_RECOVERY_FUNNEL_INPUTS && parents.len() <= MAX_RECOVERY_FUNNEL_INPUTS;
    inputs.truncate(MAX_RECOVERY_FUNNEL_INPUTS);
    parents.truncate(MAX_RECOVERY_FUNNEL_INPUTS);
    job.record_recovery_funnel_candidate(RecoveryFunnelEvent {
        stage,
        outcome,
        candidate: &sample,
        input_nodes: &inputs,
        parent_candidates: &parents,
        attribution_complete,
        attribution: l2_workbench::job::RecoveryFunnelAttribution::CandidateAndParents,
        validated_artifact_sha256: (outcome == RecoveryTransitionOutcome::Validated)
            .then(|| validated_full_input_digest(case, sample))
            .flatten(),
    })?;
    Ok(())
}

fn validated_full_input_digest(case: &Case, sample: RecoveryCandidateSample) -> Option<[u8; 32]> {
    if sample.input_count != 1 {
        return None;
    }
    let receipt = case.node(sample.evidence_node_id?)?;
    let range = receipt.details.get("range")?;
    let offset = range.get("offset")?.as_u64()?;
    let length = range.get("length")?.as_u64()?;
    let input = case.node(sample.input_node_id)?;
    let blob = case.blob(input.blob.as_deref()?)?;
    // A validated subrange cannot establish publication of the complete input blob
    (offset == 0 && usize::try_from(length).ok()? == blob.bytes.len())
        .then_some(sample.input_blob_sha256)
}

#[derive(Clone, Copy)]
pub(super) struct FunnelCohortKey<'a> {
    pub source_id: &'a str,
    pub scope: &'a str,
    pub endpoints: &'a str,
    pub direction: l2_workbench::protocol::Direction,
}

pub(super) fn register_funnel_cohort(
    executor: &super::Executor<'_>,
    key: FunnelCohortKey<'_>,
    inputs: impl Iterator<Item = RecoveryFunnelInput>,
    total_inputs: usize,
    result: l2_workbench::recovery::EnqueueOutcome,
) -> Result<(), RecoveryExecutionError> {
    let Some(progress) = &executor.job else {
        return Ok(());
    };
    let identity = funnel_identity(key)?;
    let inputs = inputs.take(MAX_RECOVERY_FUNNEL_INPUTS).collect::<Vec<_>>();
    let candidate_id = match result {
        l2_workbench::recovery::EnqueueOutcome::Queued(id)
        | l2_workbench::recovery::EnqueueOutcome::Merged(id)
        | l2_workbench::recovery::EnqueueOutcome::MergedNeedsContext(id) => Some(id),
        _ => None,
    };
    let candidate = candidate_id
        .map(|id| {
            let candidate = executor
                .coordinator
                .candidate(id)
                .ok_or(RecoveryError::UnknownCandidate { id })?;
            candidate_sample(executor.case, id, candidate, None)
        })
        .transpose()?;
    let admission = match result {
        l2_workbench::recovery::EnqueueOutcome::Queued(_)
        | l2_workbench::recovery::EnqueueOutcome::Merged(_)
        | l2_workbench::recovery::EnqueueOutcome::MergedNeedsContext(_) => {
            RecoveryFunnelAdmission::Admitted(
                candidate.as_ref().ok_or(RecoveryError::InvariantFailure)?,
            )
        }
        l2_workbench::recovery::EnqueueOutcome::CycleSkipped { .. } => {
            RecoveryFunnelAdmission::CycleSkipped
        }
        l2_workbench::recovery::EnqueueOutcome::ResourceExhausted { .. } => {
            RecoveryFunnelAdmission::ResourceExhausted
        }
    };
    progress
        .job
        .register_recovery_cohort(RecoveryFunnelRegistration {
            identity,
            inputs: &inputs,
            total_inputs,
            admission,
        })?;
    Ok(())
}

fn funnel_identity(
    key: FunnelCohortKey<'_>,
) -> Result<RecoveryFunnelIdentity, RecoveryExecutionError> {
    let source_sha256 = parse_digest(key.source_id)?;
    let mut digest = Sha256::new();
    digest.update(b"l2-recovery-funnel-cohort-v1\0");
    digest.update(source_sha256);
    for field in [key.scope, key.endpoints] {
        digest.update(
            u64::try_from(field.len())
                .map_err(|_| RecoveryError::InvariantFailure)?
                .to_be_bytes(),
        );
        digest.update(field.as_bytes());
    }
    let mut writer = DigestWriter(digest);
    serde_json::to_writer(&mut writer, &key.direction)
        .map_err(|_| RecoveryError::IdentityEncoding)?;
    Ok(RecoveryFunnelIdentity {
        source_sha256,
        cohort_sha256: writer.0.finalize().into(),
    })
}

#[derive(Clone, Copy)]
pub(super) struct FunnelSchemaReport<'a> {
    pub key: FunnelCohortKey<'a>,
    pub candidate_id: RecoveryCandidateId,
    pub report_node: u64,
    pub result: &'a str,
    pub reason: Option<&'a str>,
    pub exhaustive: bool,
    pub inputs: &'a [super::record_discovery::RecordFrameInput],
}

pub(super) fn record_funnel_schema_report(
    executor: &super::Executor<'_>,
    report: FunnelSchemaReport<'_>,
) -> Result<(), RecoveryExecutionError> {
    let Some(progress) = &executor.job else {
        return Ok(());
    };
    let FunnelSchemaReport {
        key,
        candidate_id,
        report_node,
        result,
        reason,
        exhaustive,
        inputs,
    } = report;
    let identity = funnel_identity(key)?;
    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
    let mut sample = candidate_sample(executor.case, candidate_id, candidate, Some(report_node))?;
    let first = inputs.first().ok_or(RecoveryError::InvariantFailure)?;
    // A family report represents its selected input batch, not the enclosing mixed batch
    sample.input_node_id = first.node_id;
    sample.input_blob_sha256 = parse_digest(&first.blob_id)?;
    sample.source_range = source_range(executor.case, first.node_id)?;
    sample.input_count =
        u64::try_from(inputs.len()).map_err(|_| RecoveryError::InvariantFailure)?;
    sample.input_batch_sha256 = input_batch_digest(
        inputs.len(),
        inputs
            .iter()
            .map(|input| (input.blob_id.as_str(), std::slice::from_ref(&input.node_id))),
    )?;
    let mut outcomes = vec![RecoveryTransitionOutcome::ReportRetained];
    if result == "hypotheses_found" {
        outcomes.push(RecoveryTransitionOutcome::Hypothesis);
    }
    match reason {
        Some("insufficient_training_messages") => {
            outcomes.push(RecoveryTransitionOutcome::InsufficientTrainingMessages);
        }
        Some("no_structural_candidate_space") => {
            outcomes.push(RecoveryTransitionOutcome::NoStructuralCandidateSpace);
        }
        Some("no_schema_survived_strict_parsing") => {
            outcomes.push(RecoveryTransitionOutcome::NoSchemaSurvivedStrictParsing);
        }
        _ => {}
    }
    outcomes.push(if exhaustive {
        RecoveryTransitionOutcome::SearchCompleteWithinPlan
    } else {
        RecoveryTransitionOutcome::WorkOmitted
    });
    for outcome in outcomes {
        progress.job.record_recovery_funnel_cohort_candidate(
            identity,
            RecoveryTransitionStage::Schema,
            outcome,
            sample,
        )?;
    }
    Ok(())
}

const fn stage(task: &RecoveryTask) -> RecoveryTransitionStage {
    match task {
        RecoveryTask::FramingDiscovery | RecoveryTask::MaterializeFraming(_) => {
            RecoveryTransitionStage::Framing
        }
        RecoveryTask::Transform(_)
        | RecoveryTask::TransformDiscovery
        | RecoveryTask::RelationalTransformDiscovery
        | RecoveryTask::RelationalTransformDiscoveryIncremental => {
            RecoveryTransitionStage::Transform
        }
        RecoveryTask::RecordDiscovery => RecoveryTransitionStage::Schema,
        RecoveryTask::AssembleRecords(_) => RecoveryTransitionStage::Assembly,
        RecoveryTask::StructuralValidation => RecoveryTransitionStage::Validation,
        RecoveryTask::EmbeddedDiscovery | RecoveryTask::RecursiveExpansion => {
            RecoveryTransitionStage::Expansion
        }
    }
}

const fn is_discovery(task: &RecoveryTask) -> bool {
    matches!(
        task,
        RecoveryTask::FramingDiscovery
            | RecoveryTask::RecordDiscovery
            | RecoveryTask::TransformDiscovery
            | RecoveryTask::RelationalTransformDiscovery
            | RecoveryTask::RelationalTransformDiscoveryIncremental
    )
}

pub(super) fn candidate_sample(
    case: &Case,
    candidate_id: RecoveryCandidateId,
    candidate: &RecoveryCandidate,
    evidence_node_id: Option<u64>,
) -> Result<RecoveryCandidateSample, RecoveryExecutionError> {
    let first = candidate
        .inputs()
        .first()
        .ok_or(RecoveryError::InvariantFailure)?;
    let input_node_id = *first
        .origin_node_ids()
        .first()
        .ok_or(RecoveryError::InvariantFailure)?;
    let batch = input_batch_digest(
        candidate.inputs().len(),
        candidate
            .inputs()
            .iter()
            .map(|input| (input.blob_id(), input.origin_node_ids())),
    )?;
    let mut task = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut task, candidate.task())
        .map_err(|_| RecoveryError::IdentityEncoding)?;
    Ok(RecoveryCandidateSample {
        candidate_index: u64::try_from(candidate_id.index())
            .map_err(|_| RecoveryError::InvariantFailure)?,
        input_node_id,
        input_blob_sha256: parse_digest(first.blob_id())?,
        input_batch_sha256: batch,
        task_sha256: task.0.finalize().into(),
        source_range: source_range(case, input_node_id)?,
        input_count: u64::try_from(candidate.inputs().len())
            .map_err(|_| RecoveryError::InvariantFailure)?,
        evidence_node_id,
    })
}

fn input_batch_digest<'a>(
    input_count: usize,
    inputs: impl Iterator<Item = (&'a str, &'a [u64])>,
) -> Result<[u8; 32], RecoveryError> {
    let mut batch = Sha256::new();
    batch.update(b"l2-recovery-input-batch-v1\0");
    batch.update(
        u64::try_from(input_count)
            .map_err(|_| RecoveryError::InvariantFailure)?
            .to_be_bytes(),
    );
    for (blob_id, origins) in inputs {
        batch.update(parse_digest(blob_id)?);
        batch.update(
            u64::try_from(origins.len())
                .map_err(|_| RecoveryError::InvariantFailure)?
                .to_be_bytes(),
        );
        for node_id in origins {
            batch.update(node_id.to_be_bytes());
        }
    }
    Ok(batch.finalize().into())
}

fn source_range(
    case: &Case,
    input_node_id: u64,
) -> Result<Option<RecoveryTransitionSourceRange>, RecoveryError> {
    let node = case
        .node(input_node_id)
        .ok_or(RecoveryError::InvariantFailure)?;
    node.ranges
        .first()
        .map(|range| {
            Ok(RecoveryTransitionSourceRange {
                source_sha256: parse_digest(&range.source)?,
                packet: range.packet,
                offset: range.offset,
                length: range.length,
            })
        })
        .transpose()
}

fn parse_digest(blob_id: &str) -> Result<[u8; 32], RecoveryError> {
    blob_id
        .strip_prefix("sha256:")
        .and_then(l2_workbench::parse_sha256_digest)
        .ok_or(RecoveryError::InvariantFailure)
}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct CohortObservation<'a> {
    pub stage: RecoveryTransitionStage,
    pub source_id: Option<&'a str>,
    pub input_node_id: Option<u64>,
    pub input_count: usize,
    pub candidate_id: Option<RecoveryCandidateId>,
    pub reason: l2_workbench::job::RecoveryCohortReason,
    pub outcome: RecoveryTransitionOutcome,
}

pub(super) fn record_cohort(
    job: &Job,
    case: &Case,
    coordinator: &RecoveryCoordinator,
    observation: CohortObservation<'_>,
) -> Result<(), RecoveryExecutionError> {
    let source_sha256 = observation
        .source_id
        .and_then(|source| source.strip_prefix("sha256:"))
        .and_then(l2_workbench::parse_sha256_digest);
    let input_blob_sha256 = observation
        .input_node_id
        .and_then(|id| case.node(id))
        .and_then(|node| node.blob.as_deref())
        .and_then(|blob| blob.strip_prefix("sha256:"))
        .and_then(l2_workbench::parse_sha256_digest);
    let candidate = observation
        .candidate_id
        .map(|id| {
            let candidate = coordinator
                .candidate(id)
                .ok_or(RecoveryError::UnknownCandidate { id })?;
            candidate_sample(case, id, candidate, None)
        })
        .transpose()?;
    let sample = l2_workbench::job::RecoveryCohortSample {
        source_sha256,
        input_node_id: observation.input_node_id,
        input_blob_sha256,
        input_count: u64::try_from(observation.input_count)
            .map_err(|_| RecoveryError::InvariantFailure)?,
        candidate_index: candidate.map(|sample| sample.candidate_index),
        input_batch_sha256: candidate.map(|sample| sample.input_batch_sha256),
        task_sha256: candidate.map(|sample| sample.task_sha256),
        reason: observation.reason,
    };
    job.record_recovery_transition(RecoveryTransition {
        stage: observation.stage,
        outcome: observation.outcome,
        sample: Some(RecoveryTransitionSample::Cohort(sample)),
    })?;
    Ok(())
}

pub(super) fn cohort_reason(reason: &str) -> l2_workbench::job::RecoveryCohortReason {
    use l2_workbench::job::RecoveryCohortReason as Reason;
    match reason {
        "missing_source" => Reason::MissingSource,
        "mixed_source" => Reason::MixedSource,
        "missing_blob" => Reason::MissingBlob,
        "invalid_run" => Reason::InvalidRun,
        "empty_run" => Reason::EmptyRun,
        "invalid_frame" => Reason::InvalidFrame,
        "missing_context" | "missing_conversation_context" => Reason::MissingContext,
        "ambiguous_context" | "ambiguous_conversation_context" => Reason::AmbiguousContext,
        "invalid_context" | "invalid_conversation_context" => Reason::InvalidContext,
        "generation_ambiguous" => Reason::GenerationAmbiguous,
        "run_too_large" => Reason::RunTooLarge,
        "too_many_samples" => Reason::TooManySamples,
        "total_bytes" => Reason::TotalBytes,
        "missing_materialization_receipt" => Reason::MissingMaterializationReceipt,
        "ambiguous_materialization_receipt" => Reason::AmbiguousMaterializationReceipt,
        "invalid_materialization_receipt" => Reason::InvalidMaterializationReceipt,
        "incomplete_framing" => Reason::IncompleteFraming,
        "missing_framing_selection_evidence" => Reason::MissingFramingSelectionEvidence,
        "ambiguous_framing_selection_evidence" => Reason::AmbiguousFramingSelectionEvidence,
        "invalid_framing_selection_evidence" => Reason::InvalidFramingSelectionEvidence,
        "missing_framing_input_link" => Reason::MissingFramingInputLink,
        "ambiguous_framing_input_link" => Reason::AmbiguousFramingInputLink,
        "duplicate_receipt_frame_index" => Reason::DuplicateReceiptFrameIndex,
        "learning_prefix_message_count_limit" => Reason::LearningPrefixMessageCountLimit,
        "learning_prefix_aggregate_byte_limit" => Reason::LearningPrefixAggregateByteLimit,
        "learning_prefix_message_and_byte_limits" => Reason::LearningPrefixMessageAndByteLimits,
        _ => Reason::Other,
    }
}

pub(super) fn record_cohort_enqueue(
    executor: &super::Executor<'_>,
    stage: RecoveryTransitionStage,
    source_id: &str,
    node_ids: &[u64],
    result: l2_workbench::recovery::EnqueueOutcome,
) -> Result<(), RecoveryExecutionError> {
    use l2_workbench::job::RecoveryCohortReason;
    use l2_workbench::recovery::EnqueueOutcome;
    let Some(progress) = &executor.job else {
        return Ok(());
    };
    let (outcome, reason, candidate_id) = match result {
        EnqueueOutcome::Queued(id)
        | EnqueueOutcome::Merged(id)
        | EnqueueOutcome::MergedNeedsContext(id) => (
            RecoveryTransitionOutcome::CohortAdmitted,
            RecoveryCohortReason::Admitted,
            Some(id),
        ),
        EnqueueOutcome::CycleSkipped { .. } => (
            RecoveryTransitionOutcome::CohortOmitted,
            RecoveryCohortReason::CoordinatorCycle,
            None,
        ),
        EnqueueOutcome::ResourceExhausted { .. } => (
            RecoveryTransitionOutcome::CohortOmitted,
            RecoveryCohortReason::CoordinatorLimit,
            None,
        ),
    };
    record_cohort(
        &progress.job,
        executor.case,
        &executor.coordinator,
        CohortObservation {
            stage,
            source_id: Some(source_id),
            input_node_id: node_ids.first().copied(),
            input_count: node_ids.len(),
            candidate_id,
            reason,
            outcome,
        },
    )
}

pub(super) fn record_cohort_omission(
    executor: &super::Executor<'_>,
    stage: RecoveryTransitionStage,
    source_id: Option<&str>,
    input_node_id: Option<u64>,
    input_count: usize,
    reason: &str,
) -> Result<(), RecoveryExecutionError> {
    let Some(progress) = &executor.job else {
        return Ok(());
    };
    let reason = cohort_reason(reason);
    let outcome = match reason {
        l2_workbench::job::RecoveryCohortReason::LearningPrefixMessageCountLimit
        | l2_workbench::job::RecoveryCohortReason::LearningPrefixAggregateByteLimit
        | l2_workbench::job::RecoveryCohortReason::LearningPrefixMessageAndByteLimits => {
            RecoveryTransitionOutcome::LearningSampleOmitted
        }
        _ => RecoveryTransitionOutcome::CohortOmitted,
    };
    record_cohort(
        &progress.job,
        executor.case,
        &executor.coordinator,
        CohortObservation {
            stage,
            source_id,
            input_node_id,
            input_count,
            candidate_id: None,
            reason,
            outcome,
        },
    )
}
