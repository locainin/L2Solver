use super::{
    Constraint, DerivationError, OperandLocation, OperandProvenance, OperandRef, OperandSlot,
    Recipe, SecretBytes,
};
use crate::{derivation::Operation, evidence::Case};

pub(super) struct ResolvedOperands {
    pub(super) recipe: Recipe,
    pub(super) step_provenance: Vec<Vec<OperandProvenance>>,
    pub(super) constraint_provenance: Vec<Vec<OperandProvenance>>,
}

/// Resolve retained-node and selected-input ranges against one validated evidence case
pub(super) fn resolve(
    recipe: &Recipe,
    case: &Case,
    selected_input_node: Option<u64>,
) -> Result<ResolvedOperands, DerivationError> {
    let mut resolved = recipe.clone();
    let step_provenance = resolve_steps(&mut resolved.steps, case, selected_input_node)?;
    let constraint_provenance =
        resolve_constraints(&mut resolved.constraints, case, selected_input_node)?;

    Ok(ResolvedOperands {
        recipe: resolved,
        step_provenance,
        constraint_provenance,
    })
}

fn resolve_steps(
    steps: &mut [Operation],
    case: &Case,
    selected_input_node: Option<u64>,
) -> Result<Vec<Vec<OperandProvenance>>, DerivationError> {
    let mut step_provenance = Vec::new();
    step_provenance
        .try_reserve_exact(steps.len())
        .map_err(|_| DerivationError::AllocationFailed)?;

    for (step_index, operation) in steps.iter_mut().enumerate() {
        let location = OperandLocation::Step { step_index };
        let mut operands = Vec::new();
        match operation {
            Operation::Sha256CounterXor { seed, .. } => {
                resolve_operand(
                    case,
                    selected_input_node,
                    location,
                    seed,
                    OperandSlot::Seed,
                    &mut operands,
                )?;
            }
            Operation::AesGcmDecrypt {
                key,
                nonce,
                associated_data,
                ..
            } => {
                resolve_operand(
                    case,
                    selected_input_node,
                    location,
                    key,
                    OperandSlot::Key,
                    &mut operands,
                )?;
                resolve_operand(
                    case,
                    selected_input_node,
                    location,
                    nonce,
                    OperandSlot::Nonce,
                    &mut operands,
                )?;
                resolve_operand(
                    case,
                    selected_input_node,
                    location,
                    associated_data,
                    OperandSlot::AssociatedData,
                    &mut operands,
                )?;
            }
            Operation::ScryptDerive { salt, .. } => {
                resolve_operand(
                    case,
                    selected_input_node,
                    location,
                    salt,
                    OperandSlot::Salt,
                    &mut operands,
                )?;
            }
            _ => {}
        }
        step_provenance.push(operands);
    }
    Ok(step_provenance)
}

fn resolve_constraints(
    constraints: &mut [Constraint],
    case: &Case,
    selected_input_node: Option<u64>,
) -> Result<Vec<Vec<OperandProvenance>>, DerivationError> {
    let mut constraint_provenance = Vec::new();
    constraint_provenance
        .try_reserve_exact(constraints.len())
        .map_err(|_| DerivationError::AllocationFailed)?;
    for (constraint_index, constraint) in constraints.iter_mut().enumerate() {
        let location = OperandLocation::Constraint { constraint_index };
        let mut operands = Vec::new();
        if let Constraint::AesGcm {
            key,
            nonce,
            associated_data,
        } = constraint
        {
            resolve_operand(
                case,
                selected_input_node,
                location,
                key,
                OperandSlot::Key,
                &mut operands,
            )?;
            resolve_operand(
                case,
                selected_input_node,
                location,
                nonce,
                OperandSlot::Nonce,
                &mut operands,
            )?;
            resolve_operand(
                case,
                selected_input_node,
                location,
                associated_data,
                OperandSlot::AssociatedData,
                &mut operands,
            )?;
        }
        constraint_provenance.push(operands);
    }
    Ok(constraint_provenance)
}

fn resolve_operand(
    case: &Case,
    selected_input_node: Option<u64>,
    location: OperandLocation,
    operand: &mut OperandRef,
    slot: OperandSlot,
    provenance: &mut Vec<OperandProvenance>,
) -> Result<(), DerivationError> {
    let (requested_node, requested_offset, requested_length) = match operand {
        OperandRef::Literal(_) => return Ok(()),
        OperandRef::NodeRange {
            node_id,
            offset,
            length,
        } => (*node_id, *offset, *length),
        OperandRef::SelectedInputRange { offset, length } => (
            selected_input_node.ok_or(DerivationError::SelectedInputRequired { location })?,
            *offset,
            *length,
        ),
    };
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == requested_node)
        .ok_or(DerivationError::OperandNodeMissing {
            location,
            node_id: requested_node,
        })?;
    let blob_id = node
        .blob
        .as_deref()
        .ok_or(DerivationError::OperandBlobMissing {
            location,
            node_id: requested_node,
        })?;
    let blob = case.blobs().iter().find(|blob| blob.id == blob_id).ok_or(
        DerivationError::OperandBlobMissing {
            location,
            node_id: requested_node,
        },
    )?;
    let end = requested_offset.checked_add(requested_length).ok_or(
        DerivationError::OperandRangeOverflow {
            location,
            offset: requested_offset,
            length: requested_length,
        },
    )?;
    let start = usize::try_from(requested_offset).ok();
    let end = usize::try_from(end).ok();
    let Some((start, end)) = start.zip(end) else {
        return Err(DerivationError::OperandRangeOutOfBounds {
            location,
            offset: requested_offset,
            length: requested_length,
            blob_length: blob.bytes.len(),
        });
    };
    let Some(bytes) = blob.bytes.get(start..end) else {
        return Err(DerivationError::OperandRangeOutOfBounds {
            location,
            offset: requested_offset,
            length: requested_length,
            blob_length: blob.bytes.len(),
        });
    };

    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| DerivationError::AllocationFailed)?;
    retained.extend_from_slice(bytes);
    *operand = OperandRef::Literal(SecretBytes::new(retained));
    provenance.push(OperandProvenance {
        slot,
        provider_node: requested_node,
        provider_blob: blob_id.to_owned(),
        offset: requested_offset,
        length: requested_length,
        sha256: crate::sha256(bytes),
    });
    Ok(())
}

pub(super) fn first_external_reference(recipe: &Recipe) -> Option<OperandLocation> {
    recipe
        .steps
        .iter()
        .position(operation_has_external_reference)
        .map(|step_index| OperandLocation::Step { step_index })
        .or_else(|| {
            recipe
                .constraints
                .iter()
                .position(constraint_has_external_reference)
                .map(|constraint_index| OperandLocation::Constraint { constraint_index })
        })
}

pub(super) fn first_selected_input_reference(recipe: &Recipe) -> Option<OperandLocation> {
    recipe
        .steps
        .iter()
        .position(operation_has_selected_input_reference)
        .map(|step_index| OperandLocation::Step { step_index })
        .or_else(|| {
            first_selected_input_constraint(&recipe.constraints)
                .map(|constraint_index| OperandLocation::Constraint { constraint_index })
        })
}

pub(super) fn first_selected_input_constraint(constraints: &[Constraint]) -> Option<usize> {
    constraints
        .iter()
        .position(constraint_has_selected_input_reference)
}

pub(super) fn first_external_constraint(constraints: &[Constraint]) -> Option<usize> {
    constraints
        .iter()
        .position(constraint_has_external_reference)
}

fn operation_has_external_reference(operation: &Operation) -> bool {
    match operation {
        Operation::Sha256CounterXor { seed, .. } => !is_literal(seed),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            ..
        } => !is_literal(key) || !is_literal(nonce) || !is_literal(associated_data),
        Operation::ScryptDerive { salt, .. } => !is_literal(salt),
        _ => false,
    }
}

fn operation_has_selected_input_reference(operation: &Operation) -> bool {
    match operation {
        Operation::Sha256CounterXor { seed, .. } => is_selected_input(seed),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            ..
        } => [key, nonce, associated_data]
            .into_iter()
            .any(is_selected_input),
        Operation::ScryptDerive { salt, .. } => is_selected_input(salt),
        _ => false,
    }
}

fn constraint_has_external_reference(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::AesGcm {
            key,
            nonce,
            associated_data,
        } => !is_literal(key) || !is_literal(nonce) || !is_literal(associated_data),
        _ => false,
    }
}

fn constraint_has_selected_input_reference(constraint: &Constraint) -> bool {
    match constraint {
        Constraint::AesGcm {
            key,
            nonce,
            associated_data,
        } => [key, nonce, associated_data]
            .into_iter()
            .any(is_selected_input),
        _ => false,
    }
}

const fn is_selected_input(operand: &OperandRef) -> bool {
    matches!(operand, OperandRef::SelectedInputRange { .. })
}

fn is_literal(operand: &OperandRef) -> bool {
    operand.as_literal_bytes().is_some()
}
