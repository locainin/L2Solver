use l2_workbench::experiment::{
    ExperimentMode, ExperimentOutcome, MAX_INPUT_BYTES, MAX_MUTATIONS, MAX_OUTPUT_BYTES,
    MAX_TOTAL_BYTES, Mutation, MutationFailure, MutationPlan, run,
};
use std::error::Error;

#[test]
fn input_plan_limits_rejected_analysis() {
    let empty_plan = MutationPlan {
        mutations: Vec::new(),
    };
    let oversized = vec![0_u8; MAX_INPUT_BYTES + 1];
    assert!(run(&oversized, &empty_plan, ExperimentMode::Offline).is_err());

    let too_many = MutationPlan {
        mutations: vec![Mutation::Truncate { length: 0 }; MAX_MUTATIONS + 1],
    };
    assert!(run(b"data", &too_many, ExperimentMode::Offline).is_err());
}

#[test]
fn strict_plan_entries_unknown_fields() {
    let mutation = r#"{"operation":"truncate","length":0}"#;
    let plan_json = format!(
        "{{\"mutations\":[{}]}}",
        vec![mutation; MAX_MUTATIONS + 1].join(",")
    );
    assert!(serde_json::from_str::<MutationPlan>(&plan_json).is_err());
    assert!(serde_json::from_str::<MutationPlan>(r#"{"mutations":[],"extra":true}"#).is_err());
    assert!(
        serde_json::from_str::<Mutation>(r#"{"operation":"truncate","length":1,"extra":true}"#)
            .is_err()
    );
}

#[test]
fn oversized_invalid_explicit_step_failures() -> Result<(), Box<dyn Error>> {
    let insert = Mutation::Insert {
        offset: 0,
        bytes_hex: "aa".repeat(MAX_OUTPUT_BYTES + 1),
    };
    let invalid_key = Mutation::XorRange {
        offset: 0,
        length: 1,
        key_hex: String::from("zz"),
    };
    let report = run(
        b"x",
        &MutationPlan {
            mutations: vec![insert, invalid_key],
        },
        ExperimentMode::Offline,
    )?;

    assert!(matches!(
        report.steps.get(1).map(|step| &step.outcome),
        Some(ExperimentOutcome::Failed {
            reason: MutationFailure::OutputTooLarge
        })
    ));
    assert!(matches!(
        report.steps.get(2).map(|step| &step.outcome),
        Some(ExperimentOutcome::Failed {
            reason: MutationFailure::InvalidHex
        })
    ));
    assert_eq!(report.final_sha256, l2_workbench::sha256(b"x"));
    Ok(())
}

#[test]
fn xor_keys_empty_oversized() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: [
            String::new(),
            "ff".repeat(256),
            "ff".repeat(257),
            String::from("0"),
        ]
        .into_iter()
        .map(|key_hex| Mutation::XorRange {
            offset: 0,
            length: 1,
            key_hex,
        })
        .collect(),
    };
    let report = run(b"x", &plan, ExperimentMode::Offline)?;
    let outcomes = report
        .steps
        .iter()
        .skip(1)
        .map(|step| &step.outcome)
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        vec![
            &ExperimentOutcome::Failed {
                reason: MutationFailure::InvalidKeyLength
            },
            &ExperimentOutcome::Applied,
            &ExperimentOutcome::Failed {
                reason: MutationFailure::InvalidKeyLength
            },
            &ExperimentOutcome::Failed {
                reason: MutationFailure::InvalidHex
            },
        ]
    );
    assert_eq!(report.final_sha256, l2_workbench::sha256(&[b'x' ^ 0xff]));
    Ok(())
}

#[test]
fn insert_output_capacity() -> Result<(), Box<dyn Error>> {
    let exact = Mutation::Insert {
        offset: 0,
        bytes_hex: "aa".repeat(MAX_OUTPUT_BYTES),
    };
    let accepted = run(
        b"",
        &MutationPlan {
            mutations: vec![exact],
        },
        ExperimentMode::Offline,
    )?;
    assert_eq!(
        accepted.steps.get(1).map(|step| step.output_length),
        Some(MAX_OUTPUT_BYTES)
    );
    assert!(matches!(
        accepted.steps.get(1).map(|step| &step.outcome),
        Some(ExperimentOutcome::Applied)
    ));

    let rejected = run(
        b"x",
        &MutationPlan {
            mutations: vec![Mutation::Insert {
                offset: 0,
                bytes_hex: "aa".repeat(MAX_OUTPUT_BYTES),
            }],
        },
        ExperimentMode::Offline,
    )?;
    assert!(matches!(
        rejected.steps.get(1).map(|step| &step.outcome),
        Some(ExperimentOutcome::Failed {
            reason: MutationFailure::OutputTooLarge
        })
    ));
    assert_eq!(rejected.final_sha256, l2_workbench::sha256(b"x"));
    Ok(())
}

#[test]
fn invalid_bit_explicit_step_failures() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: vec![
            Mutation::FlipBit { offset: 0, bit: 8 },
            Mutation::XorRange {
                offset: usize::MAX,
                length: 2,
                key_hex: String::from("01"),
            },
            Mutation::Delete {
                offset: usize::MAX,
                length: 2,
            },
        ],
    };

    let report = run(b"input", &plan, ExperimentMode::Offline)?;

    for (step, reason) in report.steps.iter().skip(1).zip([
        MutationFailure::InvalidBit,
        MutationFailure::RangeOutOfBounds,
        MutationFailure::RangeOutOfBounds,
    ]) {
        assert_eq!(
            step.outcome,
            ExperimentOutcome::Failed { reason },
            "sequence {}",
            step.sequence
        );
    }
    assert_eq!(report.final_sha256, l2_workbench::sha256(b"input"));
    Ok(())
}

#[test]
fn empty_out_mutations_current_bytes() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: vec![
            Mutation::Delete {
                offset: 0,
                length: 0,
            },
            Mutation::Insert {
                offset: 2,
                bytes_hex: String::from("01"),
            },
            Mutation::Truncate { length: 2 },
        ],
    };

    let report = run(b"x", &plan, ExperimentMode::Offline)?;

    for (step, reason) in report.steps.iter().skip(1).zip([
        MutationFailure::EmptyRange,
        MutationFailure::RangeOutOfBounds,
        MutationFailure::InvalidTruncateLength,
    ]) {
        assert_eq!(step.outcome, ExperimentOutcome::Failed { reason });
        assert_eq!(step.input_sha256, l2_workbench::sha256(b"x"));
        assert_eq!(step.output_sha256, l2_workbench::sha256(b"x"));
    }
    assert_eq!(report.final_sha256, l2_workbench::sha256(b"x"));
    Ok(())
}

#[test]
fn cumulative_inspection_later_operation_failed() -> Result<(), Box<dyn Error>> {
    let input = vec![b'a'; MAX_INPUT_BYTES];
    let plan = MutationPlan {
        mutations: vec![Mutation::FlipBit { offset: 0, bit: 0 }; MAX_TOTAL_BYTES / MAX_INPUT_BYTES],
    };

    let report = run(&input, &plan, ExperimentMode::Offline)?;

    let last = report.steps.last().ok_or("last experiment step missing")?;
    assert!(matches!(
        last.outcome,
        ExperimentOutcome::Failed {
            reason: MutationFailure::TotalBytesExceeded
        }
    ));
    assert!(report.inspected_bytes <= MAX_TOTAL_BYTES);
    assert_eq!(
        report.status,
        l2_workbench::experiment::ExperimentStatus::Partial
    );
    Ok(())
}

#[test]
fn parser_budget_omission_experiment_partial() -> Result<(), Box<dyn Error>> {
    let input = b"NOOP\r\n".repeat(l2_workbench::application::MAX_ENTRIES + 1);
    let report = run(
        &input,
        &MutationPlan {
            mutations: Vec::new(),
        },
        ExperimentMode::Offline,
    )?;

    let parser = report
        .steps
        .first()
        .and_then(|step| step.parser.as_ref())
        .ok_or("baseline parser summary missing")?;
    assert!(parser.ftp.budget_omissions > 0);
    assert_eq!(
        report.status,
        l2_workbench::experiment::ExperimentStatus::Partial
    );
    Ok(())
}
