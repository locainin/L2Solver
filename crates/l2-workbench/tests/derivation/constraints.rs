use l2_workbench::{
    derivation::{
        ChecksumByteOrder, Constraint, ConstraintFailure, ConstraintStatus, DerivationStatus,
        MAX_INPUT_BYTES, Operation, Recipe, StepStatus, run,
    },
    hypothesis::{self, CandidateStatus, Family, SearchPlan},
};
use std::error::Error;

#[test]
fn explicit_constraints_only_declared_predicates() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: vec![
            Constraint::Length { bytes: 4 },
            Constraint::Prefix {
                bytes: b"pass".to_vec(),
            },
            Constraint::Sha256 {
                expected_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
            },
            Constraint::Utf8 {},
            Constraint::Json {},
        ],
    };
    let report = run(b"70617373", &recipe)?;

    assert_eq!(report.status, DerivationStatus::Completed);
    assert!(matches!(
        report.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));
    assert!(matches!(
        report.constraints.get(1).map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));
    assert!(matches!(
        report.constraints.get(2).map(|item| &item.status),
        Some(ConstraintStatus::Violated { .. })
    ));
    assert!(matches!(
        report.constraints.get(3).map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));
    assert!(matches!(
        report.constraints.get(4).map(|item| &item.status),
        Some(ConstraintStatus::Violated { .. })
    ));
    Ok(())
}

#[test]
fn json_constraint_without_assigning_meaning() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![Operation::HexDecode {}],
        constraints: vec![Constraint::Json {}],
    };
    let report = run(b"7b226f6b223a747275657d", &recipe)?;

    assert!(matches!(
        report.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));
    Ok(())
}

#[test]
fn failed_transform_constraints_not_evaluated() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: vec![
            Operation::Slice {
                start: 0,
                length: Some(3),
            },
            Operation::HexDecode {},
            Operation::Reverse {},
        ],
        constraints: vec![Constraint::Length { bytes: 2 }],
    };
    let report = run(b"abcde", &recipe)?;

    assert_eq!(report.status, DerivationStatus::Failed { step_index: 1 });
    assert_eq!(report.output, b"abc");
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Applied)
    ));
    assert!(matches!(
        report.steps.get(2).map(|step| &step.status),
        Some(StepStatus::Skipped { after_step: 1 })
    ));

    assert!(matches!(
        report.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::NotEvaluated { after_step: 1 })
    ));
    Ok(())
}

#[test]
fn mismatched_explicit_constraints_remain_visible() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![
            Constraint::Length { bytes: 3 },
            Constraint::Prefix {
                bytes: b"other".to_vec(),
            },
        ],
    };
    let report = run(b"bytes", &recipe)?;

    assert!(matches!(
        report.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Violated { .. })
    ));
    assert!(matches!(
        report.constraints.get(1).map(|item| &item.status),
        Some(ConstraintStatus::Violated { .. })
    ));
    Ok(())
}

#[test]
fn prefix_limit_includes_exact_boundary() -> Result<(), Box<dyn Error>> {
    let boundary = vec![b'a'; MAX_INPUT_BYTES];
    let accepted = run(
        &boundary,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![Constraint::Prefix {
                bytes: boundary.clone(),
            }],
        },
    )?;
    assert!(matches!(
        accepted.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));

    let oversized = vec![b'a'; MAX_INPUT_BYTES + 1];
    let rejected = run(
        b"a",
        &Recipe {
            steps: Vec::new(),
            constraints: vec![Constraint::Prefix { bytes: oversized }],
        },
    )?;
    assert!(matches!(
        rejected.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Invalid {
            reason: ConstraintFailure::PrefixTooLong { .. }
        })
    ));
    Ok(())
}

#[test]
fn sha256_expectations_64_hexadecimal_bytes() -> Result<(), Box<dyn Error>> {
    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![
            Constraint::Sha256 {
                expected_hex: "0".repeat(63),
            },
            Constraint::Sha256 {
                expected_hex: "g".repeat(64),
            },
        ],
    };
    let report = run(b"bytes", &recipe)?;

    assert!(report.constraints.iter().all(|item| matches!(
        &item.status,
        ConstraintStatus::Invalid {
            reason: ConstraintFailure::InvalidSha256Expectation
        }
    )));
    Ok(())
}

#[test]
fn crc32_constraint_disjoint_range_field() -> Result<(), Box<dyn Error>> {
    let mut bytes = b"123456789\xcb\xf4\x39\x26".to_vec();
    let constraint = Constraint::Crc32 {
        data_offset: 0,
        data_length: 9,
        checksum_offset: 9,
        byte_order: ChecksumByteOrder::BigEndian,
    };
    let valid = run(
        &bytes,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![constraint.clone()],
        },
    )?;
    assert!(matches!(
        valid.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));

    if let Some(first_byte) = bytes.first_mut() {
        *first_byte = b'X';
    }
    let mismatch = run(
        &bytes,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![constraint],
        },
    )?;
    assert!(matches!(
        mismatch.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Violated {
            reason: ConstraintFailure::ChecksumMismatch {
                expected: 0xcbf4_3926,
                actual,
            }
        }) if *actual != 0xcbf4_3926
    ));

    let overlapping = run(
        b"abcd",
        &Recipe {
            steps: Vec::new(),
            constraints: vec![Constraint::Crc32 {
                data_offset: 0,
                data_length: 4,
                checksum_offset: 2,
                byte_order: ChecksumByteOrder::BigEndian,
            }],
        },
    )?;
    assert!(matches!(
        overlapping.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Invalid {
            reason: ConstraintFailure::InvalidChecksumParameters
        })
    ));
    Ok(())
}

fn aes_gcm_fixture() -> ([u8; 32], Constraint) {
    (
        [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
            0xfe, 0x78, 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2,
            0x12, 0x57, 0xbd, 0xdf,
        ],
        Constraint::AesGcm {
            key: vec![0; 16].into(),
            nonce: vec![0; 12].into(),
            associated_data: Vec::new().into(),
        },
    )
}

#[test]
fn aes_gcm_valid_authentication_tag() -> Result<(), Box<dyn Error>> {
    let (ciphertext_and_tag, constraint) = aes_gcm_fixture();
    let valid = run(
        &ciphertext_and_tag,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![constraint.clone()],
        },
    )?;
    assert!(matches!(
        valid.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Satisfied)
    ));

    let mut invalid_tag = ciphertext_and_tag;
    if let Some(tag_byte) = invalid_tag.last_mut() {
        *tag_byte ^= 1;
    }
    let rejected = run(
        &invalid_tag,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![constraint],
        },
    )?;
    assert!(matches!(
        rejected.constraints.first().map(|item| &item.status),
        Some(ConstraintStatus::Violated {
            reason: ConstraintFailure::AuthenticatedDecryptionFailed
        })
    ));

    let invalid_parameters = run(
        &ciphertext_and_tag,
        &Recipe {
            steps: Vec::new(),
            constraints: vec![Constraint::AesGcm {
                key: vec![0; 24].into(),
                nonce: vec![0; 12].into(),
                associated_data: Vec::new().into(),
            }],
        },
    )?;
    assert!(matches!(
        invalid_parameters
            .constraints
            .first()
            .map(|item| &item.status),
        Some(ConstraintStatus::Invalid {
            reason: ConstraintFailure::InvalidAesGcmParameters
        })
    ));
    Ok(())
}

#[test]
fn search_qualifies_gcm_constraint_results() -> Result<(), Box<dyn Error>> {
    let (ciphertext_and_tag, constraint) = aes_gcm_fixture();
    let valid_search =
        hypothesis::search(&ciphertext_and_tag, &aead_search_plan(constraint.clone()))?;
    assert_eq!(
        valid_search
            .candidates
            .first()
            .map(|candidate| candidate.status),
        Some(CandidateStatus::ConstraintsSatisfied)
    );
    assert!(
        valid_search
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("supplied key, nonce, and associated data") })
    );

    let mut invalid_tag = ciphertext_and_tag;
    if let Some(tag_byte) = invalid_tag.last_mut() {
        *tag_byte ^= 1;
    }
    let invalid_search = hypothesis::search(&invalid_tag, &aead_search_plan(constraint))?;
    assert_eq!(
        invalid_search
            .candidates
            .first()
            .map(|candidate| candidate.status),
        Some(CandidateStatus::ConstraintFailed)
    );
    assert!(
        invalid_search
            .limitations
            .iter()
            .any(|limitation| { limitation.contains("supplied key, nonce, and associated data") })
    );
    Ok(())
}

fn aead_search_plan(constraint: Constraint) -> SearchPlan {
    SearchPlan {
        families: vec![Family::Reverse],
        constraints: vec![constraint],
        max_depth: 1,
        max_candidates: 2,
    }
}
