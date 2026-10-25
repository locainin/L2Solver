use super::{Constraint, ConstraintFailure, ConstraintReport, ConstraintStatus};
use crate::validation::{ValidationFailure, ValidationOutcome, Validator};

pub(super) fn evaluate(
    constraints: &[Constraint],
    bytes: &[u8],
    output_sha256: &str,
    failed_step: Option<usize>,
    max_output_bytes: usize,
) -> Vec<ConstraintReport> {
    constraints
        .iter()
        .map(|constraint| ConstraintReport {
            constraint: constraint.clone(),
            operand_provenance: Vec::new(),
            status: failed_step.map_or_else(
                || evaluate_one(constraint, bytes, output_sha256, max_output_bytes),
                |after_step| ConstraintStatus::NotEvaluated { after_step },
            ),
        })
        .collect()
}

fn evaluate_one(
    constraint: &Constraint,
    bytes: &[u8],
    output_sha256: &str,
    max_output_bytes: usize,
) -> ConstraintStatus {
    let failure = match constraint {
        Constraint::Length { bytes: expected } => {
            if bytes.len() == *expected {
                return ConstraintStatus::Satisfied;
            }
            ConstraintFailure::LengthMismatch {
                expected: *expected,
                actual: bytes.len(),
            }
        }
        Constraint::Prefix { bytes: prefix } => {
            if prefix.len() > max_output_bytes {
                return ConstraintStatus::Invalid {
                    reason: ConstraintFailure::PrefixTooLong {
                        length: prefix.len(),
                        limit: max_output_bytes,
                    },
                };
            }
            if bytes.starts_with(prefix) {
                return ConstraintStatus::Satisfied;
            }
            ConstraintFailure::PrefixMismatch
        }
        Constraint::Sha256 { expected_hex } => {
            if !is_sha256_hex(expected_hex) {
                return ConstraintStatus::Invalid {
                    reason: ConstraintFailure::InvalidSha256Expectation,
                };
            }
            if expected_hex.eq_ignore_ascii_case(output_sha256) {
                return ConstraintStatus::Satisfied;
            }
            ConstraintFailure::Sha256Mismatch {
                actual_hex: output_sha256.to_owned(),
            }
        }
        Constraint::Utf8 {} => return evaluate_validator(bytes, Validator::Utf8),
        Constraint::Json {} => return evaluate_validator(bytes, Validator::Json),
        Constraint::Crc32 {
            data_offset,
            data_length,
            checksum_offset,
            byte_order,
        } => {
            return evaluate_validator(
                bytes,
                Validator::Crc32 {
                    data_offset: *data_offset,
                    data_length: *data_length,
                    checksum_offset: *checksum_offset,
                    byte_order: *byte_order,
                },
            );
        }
        Constraint::AesGcm {
            key,
            nonce,
            associated_data,
        } => return evaluate_aes_gcm(bytes, key, nonce, associated_data),
    };
    ConstraintStatus::Violated { reason: failure }
}

fn evaluate_aes_gcm(
    bytes: &[u8],
    key: &super::OperandRef,
    nonce: &super::OperandRef,
    associated_data: &super::OperandRef,
) -> ConstraintStatus {
    let Some(key) = key.as_literal_bytes() else {
        return operand_case_required();
    };
    let Some(nonce) = nonce.as_literal_bytes() else {
        return operand_case_required();
    };
    let Some(associated_data) = associated_data.as_literal_bytes() else {
        return operand_case_required();
    };
    evaluate_validator(
        bytes,
        Validator::AesGcm {
            key,
            nonce,
            associated_data,
        },
    )
}

const fn operand_case_required() -> ConstraintStatus {
    ConstraintStatus::Invalid {
        reason: ConstraintFailure::OperandRequiresCase,
    }
}

fn evaluate_validator(bytes: &[u8], validator: Validator<'_>) -> ConstraintStatus {
    match crate::validation::validate(bytes, &validator) {
        ValidationOutcome::Satisfied => ConstraintStatus::Satisfied,
        ValidationOutcome::Violated { reason } => ConstraintStatus::Violated {
            reason: map_validation_failure(reason),
        },
        ValidationOutcome::Invalid { reason } => ConstraintStatus::Invalid {
            reason: map_validation_failure(reason),
        },
    }
}

const fn map_validation_failure(reason: ValidationFailure) -> ConstraintFailure {
    match reason {
        ValidationFailure::InvalidUtf8 => ConstraintFailure::InvalidUtf8,
        ValidationFailure::InvalidJson => ConstraintFailure::InvalidJson,
        ValidationFailure::InvalidChecksumParameters => {
            ConstraintFailure::InvalidChecksumParameters
        }
        ValidationFailure::ChecksumMismatch { expected, actual } => {
            ConstraintFailure::ChecksumMismatch { expected, actual }
        }
        ValidationFailure::InvalidAesGcmParameters => ConstraintFailure::InvalidAesGcmParameters,
        ValidationFailure::AuthenticatedDecryptionFailed => {
            ConstraintFailure::AuthenticatedDecryptionFailed
        }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
