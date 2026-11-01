//! Keep the producing rules for all positive completed-cohort claims

use super::super::{application::AppliedCandidates, operational, record_gate::StructuralAdmission};
use crate::workbench::recovery_executor::RecoveryExecutionError;
use l2_workbench::{
    job::{MemoryClass, MemoryLease},
    protocol::{RelationalTransformCandidate, RelationalTransformRule},
    recovery::RecoveryError,
};
use serde_json::Value;

type Producers = Vec<(usize, RelationalTransformRule)>;

pub(in crate::workbench::recovery_executor::relational) fn collect_producer_rules(
    candidates: &[RelationalTransformCandidate],
    applications: &AppliedCandidates,
    admission: Option<StructuralAdmission<'_>>,
) -> Result<(Producers, Option<MemoryLease>), RecoveryExecutionError> {
    // One bounded slot per retained candidate avoids allocating a second rule set
    let mut slots_memory = reserve(admission, candidates.len())?;
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(candidates.len())
        .map_err(|error| operational("relational producer index allocation failed", error))?;
    resize(&mut slots_memory, selected.capacity())?;
    selected.resize(candidates.len(), false);

    for index in applications
        .outputs
        .iter()
        .map(|output| output.candidate_index)
        .chain(
            applications
                .decoded_frames
                .iter()
                .map(|frame| frame.candidate_index),
        )
        .chain(
            applications
                .accepted_schemas
                .iter()
                .map(|(index, _)| *index),
        )
        .chain(
            applications
                .structural_evidence
                .iter()
                .map(|(index, _)| *index),
        )
    {
        select(&mut selected, index)?;
    }
    select_reported_producers(&mut selected, applications)?;

    let mut count = 0_usize;
    let mut marker_bytes = 0_usize;
    for (candidate, selected) in candidates.iter().zip(&selected) {
        if *selected {
            count = count
                .checked_add(1)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
            marker_bytes = marker_bytes
                .checked_add(candidate.rule.seed_locator.marker.len())
                .and_then(|bytes| bytes.checked_add(candidate.rule.payload_locator.marker.len()))
                .ok_or(RecoveryError::InvalidCheckpoint)?;
        }
    }
    // Every marker byte and selected index requires at least one encoded byte
    if admission.is_some_and(|limit| {
        marker_bytes
            .checked_add(count)
            .is_none_or(|floor| floor > limit.maximum)
    }) {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let vector_bytes = count
        .checked_mul(size_of::<(usize, RelationalTransformRule)>())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let bytes = vector_bytes
        .checked_add(marker_bytes)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    // Reserve both rule storage and marker copies before cloning either
    let mut producers_memory = reserve(admission, bytes)?;
    let mut producers = Vec::new();
    producers
        .try_reserve_exact(count)
        .map_err(|error| operational("relational producer allocation failed", error))?;
    let actual_bytes = producers
        .capacity()
        .checked_mul(size_of::<(usize, RelationalTransformRule)>())
        .and_then(|bytes| bytes.checked_add(marker_bytes))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    resize(&mut producers_memory, actual_bytes)?;
    for (index, (candidate, selected)) in candidates.iter().zip(selected).enumerate() {
        if selected {
            producers.push((index, candidate.rule.clone()));
        }
    }
    Ok((producers, producers_memory))
}

fn select_reported_producers(
    selected: &mut [bool],
    applications: &AppliedCandidates,
) -> Result<(), RecoveryExecutionError> {
    // Positive aliases remain reportable even when their output was deduplicated or evicted
    for check in &applications.application_evidence_checks {
        let positive = matches!(
            check.get("status").and_then(Value::as_str),
            Some("artifact_validated" | "structurally_supported")
        ) || check.get("artifact_validated").and_then(Value::as_bool) == Some(true)
            || check.get("structurally_supported").and_then(Value::as_bool) == Some(true);
        if positive {
            select(selected, check_index(check)?)?;
        }
    }
    for check in &applications.aggregate_parser_checks {
        if check.get("accepted").and_then(Value::as_bool) == Some(true) {
            select(selected, check_index(check)?)?;
        }
    }
    Ok(())
}

fn select(selected: &mut [bool], index: usize) -> Result<(), RecoveryExecutionError> {
    *selected
        .get_mut(index)
        .ok_or(RecoveryError::InvariantFailure)? = true;
    Ok(())
}

fn check_index(check: &Value) -> Result<usize, RecoveryExecutionError> {
    check
        .get("candidate_index")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| RecoveryError::InvariantFailure.into())
}

fn reserve(
    admission: Option<StructuralAdmission<'_>>,
    bytes: usize,
) -> Result<Option<MemoryLease>, RecoveryExecutionError> {
    admission
        .map(|admission| {
            admission
                .memory
                .try_reserve(
                    MemoryClass::Executor,
                    u64::try_from(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
                )
                .map_err(|error| operational("relational producer admission failed", error))
        })
        .transpose()
}

fn resize(lease: &mut Option<MemoryLease>, bytes: usize) -> Result<(), RecoveryExecutionError> {
    if let Some(lease) = lease {
        lease
            .try_resize(u64::try_from(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?)
            .map_err(|error| operational("relational producer admission failed", error))?;
    }
    Ok(())
}
