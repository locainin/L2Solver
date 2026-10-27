//! Summarize completed candidate work without retaining candidate histories

use super::{RecoveryExecutionError, RecoveryOmission};
use l2_workbench::{
    evidence::Case,
    job::{
        Job, RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionSample,
        RecoveryTransitionSourceRange, RecoveryTransitionStage,
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
    let sample = sample(case, candidate_id, candidate, evidence_node_id)?;
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
        sample: Some(sample),
    })?;

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
            sample: Some(sample),
        })?;
    }
    record_omission_transitions(job, case, candidate, stage, sample, omissions)
}

fn record_omission_transitions(
    job: &Job,
    case: &Case,
    candidate: &RecoveryCandidate,
    stage: RecoveryTransitionStage,
    sample: RecoveryTransitionSample,
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
                let rejected = RecoveryTransitionSample {
                    input_node_id: *input_node_id,
                    input_blob_sha256: parse_digest(input.blob_id())?,
                    source_range: source_range(case, *input_node_id)?,
                    ..sample
                };
                job.record_recovery_transition(RecoveryTransition {
                    stage: RecoveryTransitionStage::Assembly,
                    outcome: RecoveryTransitionOutcome::InputContradicted,
                    sample: Some(rejected),
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
            } => {
                job.record_recovery_transition(RecoveryTransition {
                    stage,
                    outcome: RecoveryTransitionOutcome::WorkOmitted,
                    sample: Some(sample),
                })?;
            }
            _ => {}
        }
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

fn sample(
    case: &Case,
    candidate_id: RecoveryCandidateId,
    candidate: &RecoveryCandidate,
    evidence_node_id: Option<u64>,
) -> Result<RecoveryTransitionSample, RecoveryExecutionError> {
    let first = candidate
        .inputs()
        .first()
        .ok_or(RecoveryError::InvariantFailure)?;
    let input_node_id = *first
        .origin_node_ids()
        .first()
        .ok_or(RecoveryError::InvariantFailure)?;
    let mut batch = Sha256::new();
    batch.update(b"l2-recovery-input-batch-v1\0");
    batch.update(
        u64::try_from(candidate.inputs().len())
            .map_err(|_| RecoveryError::InvariantFailure)?
            .to_be_bytes(),
    );
    for input in candidate.inputs() {
        batch.update(parse_digest(input.blob_id())?);
        batch.update(
            u64::try_from(input.origin_node_ids().len())
                .map_err(|_| RecoveryError::InvariantFailure)?
                .to_be_bytes(),
        );
        for node_id in input.origin_node_ids() {
            batch.update(node_id.to_be_bytes());
        }
    }
    let mut task = DigestWriter(Sha256::new());
    serde_json::to_writer(&mut task, candidate.task())
        .map_err(|_| RecoveryError::IdentityEncoding)?;
    Ok(RecoveryTransitionSample {
        candidate_index: u64::try_from(candidate_id.index())
            .map_err(|_| RecoveryError::InvariantFailure)?,
        input_node_id,
        input_blob_sha256: parse_digest(first.blob_id())?,
        input_batch_sha256: batch.finalize().into(),
        task_sha256: task.0.finalize().into(),
        source_range: source_range(case, input_node_id)?,
        input_count: u64::try_from(candidate.inputs().len())
            .map_err(|_| RecoveryError::InvariantFailure)?,
        evidence_node_id,
    })
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
