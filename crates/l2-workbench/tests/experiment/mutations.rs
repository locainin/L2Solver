use l2_workbench::{
    application::ParseStatus,
    experiment::{ExperimentMode, ExperimentOutcome, Mutation, MutationPlan, run},
    sha256,
};
use std::error::Error;

#[test]
fn explicit_mutations_chain_baseline_derivation() -> Result<(), Box<dyn Error>> {
    let input = b"abc";
    let plan = MutationPlan {
        mutations: vec![
            Mutation::FlipBit { offset: 0, bit: 0 },
            Mutation::XorRange {
                offset: 1,
                length: 1,
                key_hex: String::from("02"),
            },
            Mutation::Insert {
                offset: 2,
                bytes_hex: String::from("21"),
            },
            Mutation::Delete {
                offset: 1,
                length: 1,
            },
            Mutation::Truncate { length: 2 },
        ],
    };

    let report = run(input, &plan, ExperimentMode::Offline)?;

    assert_eq!(report.steps.len(), 6);
    assert_eq!(report.input_sha256, sha256(input));
    assert_eq!(report.final_sha256, sha256(b"`!"));
    assert_eq!(report.inspected_bytes, 3 + 3 + 3 + 4 + 3 + 2);
    assert!(matches!(
        report.steps.first().map(|step| step.outcome),
        Some(ExperimentOutcome::Baseline)
    ));
    assert!(matches!(
        report.steps.get(1).map(|step| step.outcome),
        Some(ExperimentOutcome::Applied)
    ));
    assert_eq!(
        report.steps.get(3).map(|step| step.output_sha256.as_str()),
        Some(sha256(b"``!c").as_str())
    );
    assert_eq!(report.steps.last().map(|step| step.output_length), Some(2));
    assert!(report.steps.iter().all(|step| step.transport.is_none()));
    Ok(())
}

#[test]
fn invalid_operation_without_later_input() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: vec![
            Mutation::FlipBit { offset: 3, bit: 0 },
            Mutation::FlipBit { offset: 0, bit: 0 },
        ],
    };

    let report = run(b"a", &plan, ExperimentMode::Offline)?;

    assert!(matches!(
        report.steps.get(1).map(|step| &step.outcome),
        Some(ExperimentOutcome::Failed { .. })
    ));
    assert_eq!(
        report.steps.get(1).map(|step| step.input_sha256.as_str()),
        Some(sha256(b"a").as_str())
    );
    assert_eq!(report.final_sha256, sha256(b"`"));
    assert!(matches!(
        report.steps.get(2).map(|step| step.outcome),
        Some(ExperimentOutcome::Applied)
    ));
    Ok(())
}

#[test]
fn repeating_xor_range_offset_zero() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: vec![Mutation::XorRange {
            offset: 1,
            length: 4,
            key_hex: String::from("0102"),
        }],
    };

    let report = run(b"abcdef", &plan, ExperimentMode::Offline)?;

    assert_eq!(report.final_sha256, sha256(b"acaegf"));
    let step = report.steps.get(1).ok_or("XOR step missing")?;
    assert_eq!(step.output_length, 6);
    assert_eq!(step.output_sha256, sha256(b"acaegf"));
    Ok(())
}

#[test]
fn uppercase_lowercase_hex_digits() -> Result<(), Box<dyn Error>> {
    let plan = MutationPlan {
        mutations: vec![Mutation::Insert {
            offset: 1,
            bytes_hex: String::from("4A6b"),
        }],
    };

    let report = run(b"x", &plan, ExperimentMode::Offline)?;

    assert_eq!(report.final_sha256, sha256(b"xJk"));
    Ok(())
}

#[test]
fn baseline_mutation_parser_candidate_summaries() -> Result<(), Box<dyn Error>> {
    let input = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let plan = MutationPlan {
        mutations: Vec::new(),
    };

    let report = run(input, &plan, ExperimentMode::Offline)?;

    let parser = report
        .steps
        .first()
        .and_then(|step| step.parser.as_ref())
        .ok_or("baseline parser summary missing")?;
    assert_eq!(parser.http.finding_count, 1);
    assert_eq!(parser.http.status, ParseStatus::Ambiguous);
    assert!(parser.ftp.finding_count <= 256);
    assert_eq!(
        report.status,
        l2_workbench::experiment::ExperimentStatus::Complete
    );
    assert!(
        report
            .steps
            .first()
            .is_some_and(|step| step.transport.is_none())
    );
    Ok(())
}
