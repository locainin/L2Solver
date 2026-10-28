//! Reject recipes whose literal operands cannot be safely restored

use super::super::super::RecoveryTask;
use super::super::{RecoveryError, identity::canonical_recipe_identity_bytes};
use crate::derivation::{Constraint, OperandRef, Operation, Recipe};

pub(super) fn validate_task(task: &RecoveryTask) -> Result<(), RecoveryError> {
    if let RecoveryTask::Transform(recipe) = task {
        validate_recipe(recipe)?;
    }
    Ok(())
}

pub(super) fn validate_association(bytes: &[u8]) -> Result<(), RecoveryError> {
    // Redacted literal operands fail decoding, while XOR literals remain identifiable
    let task: RecoveryTask =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::CheckpointSecret)?;
    let RecoveryTask::Transform(recipe) = task else {
        return Err(RecoveryError::InvalidCheckpoint);
    };
    validate_recipe(&recipe)?;
    if canonical_recipe_identity_bytes(&recipe)? != bytes {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    Ok(())
}

pub(super) fn validate_recipe(recipe: &Recipe) -> Result<(), RecoveryError> {
    for step in &recipe.steps {
        let contains_secret = match step {
            Operation::XorRepeat { .. } => true,
            Operation::Sha256CounterXor { seed, .. } => is_literal(seed),
            Operation::AesGcmDecrypt {
                key,
                nonce,
                associated_data,
                ..
            } => is_literal(key) || is_literal(nonce) || is_literal(associated_data),
            Operation::ScryptDerive { salt, .. } => is_literal(salt),
            Operation::HexDecode {}
            | Operation::HexEncode { .. }
            | Operation::Base64Decode { .. }
            | Operation::Base64Encode { .. }
            | Operation::ByteAdd { .. }
            | Operation::RotateBits { .. }
            | Operation::Slice { .. }
            | Operation::Select { .. }
            | Operation::SelectBits { .. }
            | Operation::SelectBitRange { .. }
            | Operation::Reverse {}
            | Operation::Permute { .. }
            | Operation::GzipDecompress {}
            | Operation::ZlibDecompress {} => false,
        };
        if contains_secret {
            return Err(RecoveryError::CheckpointSecret);
        }
    }
    for constraint in &recipe.constraints {
        let contains_secret = match constraint {
            Constraint::AesGcm {
                key,
                nonce,
                associated_data,
            } => is_literal(key) || is_literal(nonce) || is_literal(associated_data),
            Constraint::Length { .. }
            | Constraint::Prefix { .. }
            | Constraint::Sha256 { .. }
            | Constraint::Utf8 {}
            | Constraint::Json {}
            | Constraint::Crc32 { .. } => false,
        };
        if contains_secret {
            return Err(RecoveryError::CheckpointSecret);
        }
    }
    Ok(())
}

const fn is_literal(operand: &OperandRef) -> bool {
    matches!(operand, OperandRef::Literal(_))
}
