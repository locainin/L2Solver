use super::{
    EnqueueOutcome, RecoveryCandidateId, RecoveryInput, RecoveryResource, RecoveryResourcePolicy,
    RecoveryResult, RecoveryResultEvidenceContract,
};
use crate::evidence::{Blob, Case, EvidenceStatus};
use std::collections::HashSet;

/// Checked input references remain tied to the caller's Case
pub(super) struct PreparedInputs<'case> {
    pub(super) inputs: Vec<RecoveryInput>,
    pub(super) blobs: Vec<&'case Blob>,
}

/// Input batch either resolves completely or reports the first exhausted budget
pub(super) enum InputPreparation<'case> {
    Ready(PreparedInputs<'case>),
    Exhausted(EnqueueOutcome),
}

pub(super) fn input_count_exhaustion(
    input_count: usize,
    resources: RecoveryResourcePolicy,
) -> Option<EnqueueOutcome> {
    (input_count > resources.max_inputs_per_candidate).then_some(
        EnqueueOutcome::ResourceExhausted {
            resource: RecoveryResource::InputCount,
            limit: resources.max_inputs_per_candidate,
            used: 0,
            requested: input_count,
        },
    )
}

pub(super) fn prepare_inputs<'case>(
    case: &'case Case,
    node_ids: &[u64],
    resources: RecoveryResourcePolicy,
) -> Result<InputPreparation<'case>, super::RecoveryError> {
    if node_ids.is_empty() {
        return Err(super::RecoveryError::EmptyInputBatch);
    }
    if let Some(outcome) = input_count_exhaustion(node_ids.len(), resources) {
        return Ok(InputPreparation::Exhausted(outcome));
    }

    let mut inputs = Vec::with_capacity(node_ids.len());
    let mut blobs = Vec::with_capacity(node_ids.len());
    let mut total_input_bytes = 0_usize;
    for node_id in node_ids {
        let blob = evidence_blob(case, *node_id)?;
        if blob.bytes.len() > resources.max_input_bytes_per_item {
            return Ok(InputPreparation::Exhausted(
                EnqueueOutcome::ResourceExhausted {
                    resource: RecoveryResource::InputBytesPerItem,
                    limit: resources.max_input_bytes_per_item,
                    used: 0,
                    requested: blob.bytes.len(),
                },
            ));
        }
        // The sum invariant keeps this subtraction and following addition exact
        let remaining = resources.max_total_input_bytes_per_candidate - total_input_bytes;
        if blob.bytes.len() > remaining {
            return Ok(InputPreparation::Exhausted(
                EnqueueOutcome::ResourceExhausted {
                    resource: RecoveryResource::TotalInputBytes,
                    limit: resources.max_total_input_bytes_per_candidate,
                    used: total_input_bytes,
                    requested: blob.bytes.len(),
                },
            ));
        }
        total_input_bytes += blob.bytes.len();
        inputs.push(RecoveryInput {
            blob_id: blob.id.clone(),
            origin_node_ids: vec![*node_id],
            origin_node_id_set: HashSet::from([*node_id]),
        });
        blobs.push(blob);
    }
    Ok(InputPreparation::Ready(PreparedInputs { inputs, blobs }))
}

pub(super) fn evidence_blob(case: &Case, node_id: u64) -> Result<&Blob, super::RecoveryError> {
    let blob_id = case
        .node(node_id)
        .ok_or(super::RecoveryError::UnknownEvidenceNode { node_id })?
        .blob
        .as_deref()
        .ok_or(super::RecoveryError::InputBlobMissing { node_id })?;
    case.blob(blob_id)
        .filter(|blob| blob.id == blob_id)
        .ok_or(super::RecoveryError::InvariantFailure)
}

pub(super) fn input_blob<'case>(
    case: &'case Case,
    input: &RecoveryInput,
) -> Result<&'case Blob, super::RecoveryError> {
    if input.origin_node_ids.is_empty() {
        return Err(super::RecoveryError::InvariantFailure);
    }
    let blob = case
        .blob(input.blob_id())
        .filter(|blob| blob.id == input.blob_id())
        .ok_or(super::RecoveryError::InvariantFailure)?;
    for origin_node_id in &input.origin_node_ids {
        let resolved = evidence_blob(case, *origin_node_id)?;
        if resolved.id != input.blob_id() {
            return Err(super::RecoveryError::InvariantFailure);
        }
    }
    Ok(blob)
}

pub(super) fn input_key(
    inputs: &[RecoveryInput],
    include_origin_context: bool,
) -> Result<String, super::RecoveryError> {
    // Origin IDs stand in for canonical message context until Case provides one
    let ordered_inputs = inputs
        .iter()
        .map(|input| {
            let mut origins = if include_origin_context {
                input.origin_node_id_set.iter().copied().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            origins.sort_unstable();
            (input.blob_id(), origins)
        })
        .collect::<Vec<_>>();
    let encoded =
        serde_json::to_vec(&ordered_inputs).map_err(|_| super::RecoveryError::IdentityEncoding)?;
    Ok(crate::sha256(&encoded))
}

pub(super) fn same_origin_context(left: &[RecoveryInput], right: &[RecoveryInput]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.origin_node_id_set == right.origin_node_id_set)
}

pub(super) fn same_input_bytes(case: &Case, inputs: &[RecoveryInput], blobs: &[&Blob]) -> bool {
    inputs.len() == blobs.len()
        && inputs.iter().zip(blobs).all(|(input, incoming)| {
            input.blob_id() == incoming.id
                && case
                    .blob(input.blob_id())
                    .filter(|blob| blob.id == input.blob_id())
                    .is_some_and(|saved| saved.bytes == incoming.bytes)
        })
}

pub(super) fn validate_derived_inputs(
    case: &Case,
    parent_id: RecoveryCandidateId,
    parent_result_node_id: u64,
    node_ids: &[u64],
) -> Result<(), super::RecoveryError> {
    for node_id in node_ids {
        let _ = evidence_blob(case, *node_id)?;
        if !case.has_edge(
            *node_id,
            parent_result_node_id,
            "derived_from",
            EvidenceStatus::Observed,
        ) {
            return Err(super::RecoveryError::UnlinkedDerivedInput {
                parent_candidate_id: parent_id,
                child_node_id: *node_id,
            });
        }
    }
    Ok(())
}

pub(super) fn validate_validated_inputs(
    case: &Case,
    parent_id: RecoveryCandidateId,
    validation_node_id: u64,
    node_ids: &[u64],
) -> Result<(), super::RecoveryError> {
    for node_id in node_ids {
        let _ = evidence_blob(case, *node_id)?;
        if !case.has_edge(
            *node_id,
            validation_node_id,
            "validated_range",
            EvidenceStatus::Observed,
        ) {
            return Err(super::RecoveryError::UnlinkedValidatedInput {
                parent_candidate_id: parent_id,
                child_node_id: *node_id,
            });
        }
    }
    Ok(())
}

pub(super) fn validated_origin_aliases(
    case: &Case,
    parent_id: RecoveryCandidateId,
    parent_inputs: &[RecoveryInput],
    validation_node_id: u64,
    node_ids: &[u64],
) -> Result<Vec<Vec<u64>>, super::RecoveryError> {
    let mut aliases_by_input = Vec::new();
    aliases_by_input
        .try_reserve_exact(node_ids.len())
        .map_err(|_| super::RecoveryError::AllocationFailed)?;
    for node_id in node_ids {
        let exact_blob = evidence_blob(case, *node_id)?;
        let Some(parent_input) = parent_inputs
            .iter()
            .find(|input| input.blob_id() == exact_blob.id)
        else {
            aliases_by_input.push(Vec::new());
            continue;
        };

        let _ = input_blob(case, parent_input)?;
        for origin in parent_input.origin_node_ids() {
            let origin_blob = evidence_blob(case, *origin)?;
            if origin_blob.id != exact_blob.id
                || !case.has_edge(
                    validation_node_id,
                    *origin,
                    "recovery_result",
                    EvidenceStatus::ConstraintSatisfied,
                )
            {
                return Err(super::RecoveryError::UnlinkedValidatedInput {
                    parent_candidate_id: parent_id,
                    child_node_id: *origin,
                });
            }
        }
        let mut aliases = Vec::new();
        aliases
            .try_reserve_exact(parent_input.origin_node_ids().len())
            .map_err(|_| super::RecoveryError::AllocationFailed)?;
        aliases.extend_from_slice(parent_input.origin_node_ids());
        aliases_by_input.push(aliases);
    }
    Ok(aliases_by_input)
}

pub(super) fn append_input_origin_aliases(
    case: &Case,
    inputs: &mut [RecoveryInput],
    aliases_by_input: &[Vec<u64>],
) -> Result<(), super::RecoveryError> {
    if inputs.len() != aliases_by_input.len() {
        return Err(super::RecoveryError::InvariantFailure);
    }
    for (input, aliases) in inputs.iter_mut().zip(aliases_by_input) {
        input
            .origin_node_ids
            .try_reserve(aliases.len())
            .map_err(|_| super::RecoveryError::AllocationFailed)?;
        input
            .origin_node_id_set
            .try_reserve(aliases.len())
            .map_err(|_| super::RecoveryError::AllocationFailed)?;
        for alias in aliases {
            let blob = evidence_blob(case, *alias)?;
            if blob.id != input.blob_id() {
                return Err(super::RecoveryError::InvariantFailure);
            }
            if input.origin_node_id_set.insert(*alias) {
                input.origin_node_ids.push(*alias);
            }
        }
        input.origin_node_ids.sort_unstable();
    }
    Ok(())
}

pub(super) fn missing_result_origins(
    case: &Case,
    inputs: &[RecoveryInput],
    result: &RecoveryResult,
) -> Result<Vec<u64>, super::RecoveryError> {
    missing_result_origins_for_origins(
        case,
        result,
        inputs
            .iter()
            .flat_map(|input| input.origin_node_ids.iter().copied()),
    )
}

pub(super) fn missing_result_origins_after_merge(
    case: &Case,
    existing_origins: &HashSet<u64>,
    incoming_inputs: &[RecoveryInput],
    result: &RecoveryResult,
) -> Result<Vec<u64>, super::RecoveryError> {
    missing_result_origins_for_origins(
        case,
        result,
        incoming_inputs
            .iter()
            .flat_map(|input| input.origin_node_ids.iter().copied())
            .filter(|origin_node_id| !existing_origins.contains(origin_node_id)),
    )
}

fn missing_result_origins_for_origins(
    case: &Case,
    result: &RecoveryResult,
    origin_node_ids: impl Iterator<Item = u64>,
) -> Result<Vec<u64>, super::RecoveryError> {
    let Some(contract) = result.evidence_link_contract() else {
        return Ok(Vec::new());
    };
    if contract.requires_blob {
        let _ = evidence_blob(case, contract.node_id)?;
    } else if case.node(contract.node_id).is_none() {
        return Err(super::RecoveryError::UnknownEvidenceNode {
            node_id: contract.node_id,
        });
    }
    let mut seen = HashSet::new();
    let mut missing = Vec::new();
    for origin_node_id in origin_node_ids {
        if seen.insert(origin_node_id) && !result_linked_to_origin(case, contract, origin_node_id) {
            missing.push(origin_node_id);
        }
    }
    Ok(missing)
}

pub(super) fn validate_result_node(
    case: &Case,
    candidate_id: RecoveryCandidateId,
    inputs: &[RecoveryInput],
    result: &RecoveryResult,
) -> Result<(), super::RecoveryError> {
    if let Some(origin_node_id) = missing_result_origins(case, inputs, result)?
        .first()
        .copied()
    {
        return Err(super::RecoveryError::UnlinkedResultEvidence {
            candidate_id,
            evidence_node_id: result
                .evidence_link_contract()
                .ok_or(super::RecoveryError::InvariantFailure)?
                .node_id,
            origin_node_id,
        });
    }
    Ok(())
}

fn result_linked_to_origin(
    case: &Case,
    contract: RecoveryResultEvidenceContract,
    origin_node_id: u64,
) -> bool {
    case.has_edge(
        contract.node_id,
        origin_node_id,
        contract.relation,
        contract.status,
    )
}

#[cfg(test)]
#[path = "../../tests/recovery/case_refs.rs"]
mod tests;
