//! Explicit byte transformations with bounded work and retained failure evidence

mod constraints;
mod execute;
mod identity;
mod model;
mod operands;
mod transform;

pub use execute::{DerivationError, run, run_with_case, run_with_limits, run_with_selected_input};
pub use model::{
    AesGcmTagLayout, Base64Alphabet, Base64Padding, BitRemainder, ChecksumByteOrder, Constraint,
    ConstraintFailure, ConstraintReport, ConstraintStatus, CounterByteOrder, CounterWidth,
    DerivationLimits, DerivationReport, DerivationStatus, HexCase, OperandLocation,
    OperandProvenance, OperandRef, OperandSlot, Operation, Recipe, SecretBytes, SeedCounterOrder,
    StepFailure, StepReport, StepStatus,
};

pub(crate) fn validate_recipe_identity(recipe: &Recipe) -> Result<(), DerivationError> {
    execute::validate_recipe_identity(recipe)
}

/// Maximum caller-supplied input size
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum result size after any single operation
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum number of configured operations in one recipe
pub const MAX_STEPS: usize = 32;
/// Maximum number of explicit result checks in one recipe
pub const MAX_CONSTRAINTS: usize = 32;
/// Maximum sum of successful intermediate and final operation outputs
pub const MAX_INTERMEDIATE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum encoded size of all caller-supplied variable-length recipe parameters
pub const MAX_RECIPE_PARAMETER_BYTES: usize = 4 * 1024 * 1024;
/// Default cumulative bytes charged across configured transformation work
pub const DEFAULT_MAX_WORK_BYTES: usize = MAX_INPUT_BYTES * MAX_STEPS + MAX_INTERMEDIATE_BYTES;

pub(crate) use identity::OperationIdentity;
pub(crate) use transform::{
    preview_sha256_counter_xor, select_bit_plane_chunks, sha256_counter_xor_work,
    validate_sha256_counter_xor_capacity,
};

/// Report whether one recipe binds any operand to its selected input node
pub(crate) fn has_selected_input_reference(recipe: &Recipe) -> bool {
    operands::first_selected_input_reference(recipe).is_some()
}

/// Evaluate caller-supplied checks over an already bounded output without imposing the
/// per-operation input ceiling used by ordinary derivation recipes
pub(crate) fn check_constraints(
    bytes: &[u8],
    constraints: &[Constraint],
) -> Result<Vec<ConstraintReport>, DerivationError> {
    if constraints.len() > MAX_CONSTRAINTS {
        return Err(DerivationError::TooManyConstraints {
            count: constraints.len(),
            limit: MAX_CONSTRAINTS,
        });
    }
    if let Some(constraint_index) = operands::first_selected_input_constraint(constraints) {
        return Err(DerivationError::SelectedInputRequired {
            location: OperandLocation::Constraint { constraint_index },
        });
    }
    if let Some(constraint_index) = operands::first_external_constraint(constraints) {
        return Err(DerivationError::EvidenceCaseRequired {
            location: OperandLocation::Constraint { constraint_index },
        });
    }
    execute::validate_constraint_parameter_size(constraints)?;
    Ok(constraints::evaluate(
        constraints,
        bytes,
        &crate::sha256(bytes),
        None,
        MAX_OUTPUT_BYTES,
    ))
}
