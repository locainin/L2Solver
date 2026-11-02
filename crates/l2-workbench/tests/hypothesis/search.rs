use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use l2_workbench::{
    derivation::{self, Constraint},
    hypothesis::{
        CandidateStatus, Family, KeyTestStatus, SearchLimits, SearchPlan, search,
        search_with_limits,
    },
};
use std::{error::Error, io::Write};

const fn plan(families: Vec<Family>, constraints: Vec<Constraint>) -> SearchPlan {
    SearchPlan {
        families,
        constraints,
        max_depth: 3,
        max_candidates: 128,
    }
}

#[test]
fn layered_encoding_steps_explicit_constraints() -> Result<(), Box<dyn Error>> {
    let plain = b"{\"message\":\"measured evidence\"}";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(plain)?;
    let input = STANDARD.encode(encoder.finish()?);
    let report = search(
        input.as_bytes(),
        &plan(
            vec![Family::Base64, Family::Gzip],
            vec![Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(plain),
            }],
        ),
    )?;
    let found = report
        .candidates
        .iter()
        .find(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
        .ok_or("pipeline was not found")?;
    assert_eq!(found.recipe.steps.len(), 2);
    assert_eq!(
        derivation::run(input.as_bytes(), &found.recipe)?.output,
        plain
    );
    assert_eq!(found.output_sha256, l2_workbench::sha256(plain));
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn wrong_constraints_failed_operations_visible() -> Result<(), Box<dyn Error>> {
    let report = search(
        b"wrong",
        &plan(
            vec![Family::Hex],
            vec![Constraint::Prefix {
                bytes: b"required".to_vec(),
            }],
        ),
    )?;
    assert_eq!(
        report.candidates.first().map(|candidate| candidate.status),
        Some(CandidateStatus::ConstraintFailed)
    );
    assert!(report.limitations.iter().any(|limitation| {
        limitation.contains("No authenticated-decryption constraint was supplied")
    }));
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.status == CandidateStatus::OperationFailed)
    );
    assert!(
        !report
            .candidates
            .iter()
            .any(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
    );
    Ok(())
}

#[test]
fn known_plaintext_inferred_key_period() -> Result<(), Box<dyn Error>> {
    let plain = b"file-format:file-format:body";
    let key = [7_u8, 91, 223];
    let input: Vec<_> = plain
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key)| byte ^ key)
        .collect();
    let family = Family::KnownPlaintextXor {
        offset: 0,
        bytes: plain.get(..12).ok_or("fixture extent")?.to_vec(),
        key_lengths: vec![2, 3],
    };
    let report = search(
        &input,
        &plan(
            vec![family],
            vec![Constraint::Sha256 {
                expected_hex: l2_workbench::sha256(plain),
            }],
        ),
    )?;
    assert!(
        report
            .key_tests
            .iter()
            .any(|test| test.key_length == 2 && test.status == KeyTestStatus::Contradicted)
    );
    let recovery = report
        .key_tests
        .iter()
        .find(|test| test.key_length == 3 && test.status == KeyTestStatus::Consistent)
        .ok_or("missing key consistency test")?;
    assert_eq!(recovery.inferred_key, key);
    assert_eq!(recovery.inference_bytes, 3);
    assert_eq!(recovery.holdout_bytes, 9);
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
    );
    Ok(())
}

#[test]
fn unavailable_known_plaintext_ranges_untestable() -> Result<(), Box<dyn Error>> {
    let family = Family::KnownPlaintextXor {
        offset: 10,
        bytes: vec![0; 6],
        key_lengths: vec![3],
    };
    let report = search(b"short", &plan(vec![family], vec![Constraint::Utf8 {}]))?;
    assert_eq!(
        report.key_tests.first().map(|test| test.status),
        Some(KeyTestStatus::Untestable)
    );
    assert!(
        report
            .key_tests
            .first()
            .is_some_and(|test| test.inferred_key.is_empty())
    );
    assert!(!report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn explicit_search_above_legacy_default() -> Result<(), Box<dyn Error>> {
    let input = vec![b'a'; 70_000];
    let plan = plan(
        vec![Family::Reverse],
        vec![Constraint::Length { bytes: input.len() }],
    );
    let limits = SearchLimits {
        max_input_bytes: 100_000,
        max_work_bytes: 300_000,
        ..SearchLimits::default()
    };

    let report = search_with_limits(&input, &plan, limits)?;

    assert_eq!(report.input_length, input.len());
    assert_eq!(report.resources, limits);
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}

#[test]
fn configured_depth_no_upper_ceiling() -> Result<(), Box<dyn Error>> {
    let report = search_with_limits(
        b"not hex",
        &SearchPlan {
            families: vec![Family::Hex],
            constraints: vec![Constraint::Prefix {
                bytes: b"required".to_vec(),
            }],
            max_depth: 4,
            max_candidates: 1_025,
        },
        SearchLimits::default(),
    )?;

    assert_eq!(report.plan.max_depth, 4);
    assert_eq!(report.plan.max_candidates, 1_025);
    assert!(report.candidates.len() < 1_025);
    Ok(())
}

#[test]
fn failed_later_indices_constraint_receipts() -> Result<(), Box<dyn Error>> {
    let report = search(
        b"6162",
        &plan(vec![Family::Hex, Family::Gzip], vec![Constraint::Utf8 {}]),
    )?;
    let failed = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.recipe.steps
                == vec![
                    derivation::Operation::HexDecode {},
                    derivation::Operation::GzipDecompress {},
                ]
        })
        .ok_or("missing failed layered hypothesis")?;
    assert_eq!(
        failed.constraints.first().map(|check| &check.status),
        Some(&derivation::ConstraintStatus::NotEvaluated { after_step: 1 })
    );
    Ok(())
}

#[test]
fn candidate_budget_without_exhaustive_search() -> Result<(), Box<dyn Error>> {
    let mut bounded = plan(
        vec![Family::SingleByteXor],
        vec![Constraint::Prefix {
            bytes: b"match".to_vec(),
        }],
    );
    bounded.max_candidates = 2;
    let report = search(b"input", &bounded)?;
    assert_eq!(report.candidates.len(), 2);
    assert!(!report.search_exhaustive_within_plan);
    assert_ne!(report.limits.len(), 0);
    let cycles = search(
        b"abba",
        &plan(vec![Family::Reverse], vec![Constraint::Length { bytes: 4 }]),
    )?;
    assert_eq!(cycles.candidates.len(), 2);
    assert_eq!(
        cycles
            .candidates
            .last()
            .and_then(|candidate| candidate.duplicate_of),
        Some(0)
    );
    Ok(())
}

#[test]
fn aggregate_search_never_byte_budget() -> Result<(), Box<dyn Error>> {
    let bounded = SearchPlan {
        families: vec![Family::SingleByteXor],
        constraints: vec![Constraint::Utf8 {}],
        max_depth: 1,
        max_candidates: 1024,
    };
    // This size leaves enough budget for one input but not its same-size XOR output
    let report = search(&vec![0_u8; 64_750], &bounded)?;
    assert!(report.work_bytes <= l2_workbench::hypothesis::MAX_WORK_BYTES);
    assert!(!report.search_exhaustive_within_plan);
    assert!(
        report
            .limits
            .contains(&l2_workbench::hypothesis::SearchLimit::WorkBytes)
    );
    assert_eq!(report.candidates.len(), 130);
    Ok(())
}

#[test]
fn unconstrained_zero_larger_depth_allowed() {
    assert!(search(b"bytes", &plan(vec![Family::Reverse], vec![])).is_err());
    let invalid = plan(
        vec![Family::Reverse],
        vec![Constraint::Sha256 {
            expected_hex: "invalid".into(),
        }],
    );
    assert!(search(b"bytes", &invalid).is_err());
    let mut configurable_depth = plan(vec![Family::Reverse], vec![Constraint::Utf8 {}]);
    configurable_depth.max_depth = 4;
    assert!(search(b"bytes", &configurable_depth).is_ok());
    let mut invalid_budget = plan(vec![Family::Reverse], vec![Constraint::Utf8 {}]);
    invalid_budget.max_candidates = 0;
    assert!(search(b"bytes", &invalid_budget).is_err());
    let insufficient = Family::KnownPlaintextXor {
        offset: 0,
        bytes: vec![0; 5],
        key_lengths: vec![3],
    };
    assert!(
        search(
            b"bytes",
            &plan(vec![insufficient], vec![Constraint::Utf8 {}])
        )
        .is_err()
    );
}

#[test]
fn serialized_plan_budget_variable_parameters() -> Result<(), Box<dyn Error>> {
    let mut bounded = plan(
        vec![Family::Reverse],
        vec![Constraint::Prefix { bytes: Vec::new() }],
    );
    let overhead = serde_json::to_vec(&bounded)?.len();
    let capacity = (8192 - overhead).div_ceil(2);
    bounded.constraints = vec![Constraint::Prefix {
        bytes: vec![0; capacity],
    }];
    assert!(serde_json::to_vec(&bounded)?.len() <= 8192);
    assert!(search(b"input", &bounded).is_ok());
    bounded.constraints = vec![Constraint::Prefix {
        bytes: vec![0; capacity + 1],
    }];
    assert!(serde_json::to_vec(&bounded)?.len() > 8192);
    assert!(search(b"input", &bounded).is_err());
    Ok(())
}

#[test]
fn byte_search_json_prefix_control() -> Result<(), Box<dyn Error>> {
    let prefix = b"{\"packet\":{\"type\":\"hello\",\"seq\":42},\"body\":\"";
    let body = "x".repeat(2_048 - prefix.len() - 2);
    let plain = format!("{}{}\"}}", String::from_utf8_lossy(prefix), body);
    let plain = plain.as_bytes();
    let value = 137_u8;
    let input: Vec<_> = plain.iter().map(|byte| byte.wrapping_sub(value)).collect();
    let mut bounded = plan(
        vec![Family::ByteAdd],
        vec![
            Constraint::Prefix {
                bytes: prefix.to_vec(),
            },
            Constraint::Json {},
        ],
    );
    bounded.max_depth = 1;
    bounded.max_candidates = 1_024;
    let report = search(&input, &bounded)?;
    let recovered = report
        .candidates
        .iter()
        .find(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
        .ok_or("shifted JSON payload was not recovered")?;
    assert_eq!(
        recovered.recipe.steps,
        vec![derivation::Operation::ByteAdd { value }]
    );
    assert_eq!(derivation::run(&input, &recovered.recipe)?.output, plain);
    assert_eq!(report.candidates.len(), 257);
    assert_eq!(report.work_bytes, 256 * input.len() * 2);
    assert!(report.search_exhaustive_within_plan);

    let mut malformed = prefix.to_vec();
    malformed.extend_from_slice(b"broken\\q\"}}");
    let malformed_input: Vec<_> = malformed
        .iter()
        .map(|byte| byte.wrapping_sub(value))
        .collect();
    let control = search(&malformed_input, &bounded)?;
    assert!(
        !control
            .candidates
            .iter()
            .any(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
    );
    let prefix_only = control
        .candidates
        .iter()
        .find(|candidate| candidate.recipe.steps == vec![derivation::Operation::ByteAdd { value }])
        .ok_or("prefix-only control hypothesis was not generated")?;
    assert_eq!(prefix_only.status, CandidateStatus::ConstraintFailed);
    assert_eq!(
        prefix_only.constraints.first().map(|check| &check.status),
        Some(&derivation::ConstraintStatus::Satisfied)
    );
    assert_eq!(
        prefix_only.constraints.get(1).map(|check| &check.status),
        Some(&derivation::ConstraintStatus::Violated {
            reason: derivation::ConstraintFailure::InvalidJson,
        })
    );
    Ok(())
}

#[test]
fn rotate_bits_json_independent_constraints() -> Result<(), Box<dyn Error>> {
    let plain = br#"{"packet":{"type":"control","seq":19}}"#;
    let prefix = b"{\"packet\":{";
    let count = 5_u8;
    let input: Vec<_> = plain
        .iter()
        .map(|byte| byte.rotate_right(u32::from(count)))
        .collect();
    let mut bounded = plan(
        vec![Family::RotateBits],
        vec![
            Constraint::Prefix {
                bytes: prefix.to_vec(),
            },
            Constraint::Json {},
        ],
    );
    bounded.max_depth = 1;
    let report = search(&input, &bounded)?;
    let recovered = report
        .candidates
        .iter()
        .find(|candidate| candidate.status == CandidateStatus::ConstraintsSatisfied)
        .ok_or("rotated JSON payload was not recovered")?;
    assert_eq!(
        recovered.recipe.steps,
        vec![derivation::Operation::RotateBits { count }]
    );
    assert_eq!(derivation::run(&input, &recovered.recipe)?.output, plain);
    assert_eq!(report.candidates.len(), 9);
    assert_eq!(report.work_bytes, 8 * input.len() * 2);
    assert!(report.search_exhaustive_within_plan);
    Ok(())
}
