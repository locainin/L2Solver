use l2_workbench::derivation::{
    Constraint, DerivationError, DerivationLimits, DerivationStatus, MAX_CONSTRAINTS,
    MAX_INPUT_BYTES, MAX_INTERMEDIATE_BYTES, MAX_OUTPUT_BYTES, MAX_RECIPE_PARAMETER_BYTES,
    MAX_STEPS, Operation, Recipe, StepStatus, run, run_with_limits,
};
use std::error::Error;

#[test]
fn oversized_input_steps_constraints_execution() {
    let too_large = vec![0_u8; MAX_INPUT_BYTES + 1];
    let empty_recipe = Recipe {
        steps: Vec::new(),
        constraints: Vec::new(),
    };
    assert_eq!(
        run(&too_large, &empty_recipe),
        Err(DerivationError::InputTooLong {
            length: MAX_INPUT_BYTES + 1,
            limit: MAX_INPUT_BYTES,
        })
    );

    let recipe = Recipe {
        steps: vec![Operation::Reverse {}; MAX_STEPS + 1],
        constraints: Vec::new(),
    };
    assert_eq!(
        run(b"input", &recipe),
        Err(DerivationError::TooManySteps {
            count: MAX_STEPS + 1,
            limit: MAX_STEPS,
        })
    );

    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![Constraint::Utf8 {}; MAX_CONSTRAINTS + 1],
    };
    assert_eq!(
        run(b"input", &recipe),
        Err(DerivationError::TooManyConstraints {
            count: MAX_CONSTRAINTS + 1,
            limit: MAX_CONSTRAINTS,
        })
    );
}

#[test]
fn aggregate_recipe_parameter_limit_execution() {
    let index_count = MAX_RECIPE_PARAMETER_BYTES / std::mem::size_of::<usize>() + 1;
    {
        let recipe = Recipe {
            steps: vec![Operation::Select {
                indices: vec![0; index_count],
            }],
            constraints: Vec::new(),
        };
        assert_eq!(
            run(b"", &recipe),
            Err(DerivationError::RecipeParametersTooLarge {
                limit: MAX_RECIPE_PARAMETER_BYTES,
            })
        );
    }

    let prefix_length = MAX_RECIPE_PARAMETER_BYTES / 2 + 1;
    let recipe = Recipe {
        steps: Vec::new(),
        constraints: vec![
            Constraint::Prefix {
                bytes: vec![0; prefix_length],
            },
            Constraint::Prefix {
                bytes: vec![0; prefix_length],
            },
        ],
    };
    assert_eq!(
        run(b"", &recipe),
        Err(DerivationError::RecipeParametersTooLarge {
            limit: MAX_RECIPE_PARAMETER_BYTES,
        })
    );
}

#[test]
fn cumulative_intermediate_budget_later_steps() -> Result<(), Box<dyn Error>> {
    let input = vec![b'x'; MAX_OUTPUT_BYTES];
    let step_count = MAX_INTERMEDIATE_BYTES / MAX_OUTPUT_BYTES + 1;
    let recipe = Recipe {
        steps: vec![Operation::Reverse {}; step_count],
        constraints: Vec::new(),
    };
    let report = run(&input, &recipe)?;

    assert_eq!(
        report.status,
        DerivationStatus::Failed {
            step_index: step_count - 1
        }
    );
    assert_eq!(report.intermediate_bytes, MAX_INTERMEDIATE_BYTES);
    assert_eq!(report.output.len(), MAX_OUTPUT_BYTES);
    assert_eq!(report.steps.len(), step_count);
    assert!(
        report
            .steps
            .iter()
            .take(step_count - 1)
            .all(|step| matches!(&step.status, StepStatus::Applied))
    );
    assert!(matches!(
        report.steps.last().map(|step| &step.status),
        Some(StepStatus::Failed { .. })
    ));
    Ok(())
}

#[test]
fn explicit_runtime_still_bound_decompression() -> Result<(), Box<dyn Error>> {
    let input = vec![b'x'; MAX_OUTPUT_BYTES + 1];
    let limits = DerivationLimits {
        max_input_bytes: input.len(),
        max_output_bytes: input.len(),
        max_intermediate_bytes: input.len(),
        ..DerivationLimits::default()
    };
    let recipe = Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: vec![Constraint::Length { bytes: input.len() }],
    };

    let report = run_with_limits(&input, &recipe, limits)?;

    assert_eq!(
        report.output,
        input.iter().rev().copied().collect::<Vec<_>>()
    );
    assert!(matches!(
        report.constraints.first().map(|check| &check.status),
        Some(l2_workbench::derivation::ConstraintStatus::Satisfied)
    ));

    let compressed = gzip(&vec![b'a'; 4096])?;
    let constrained = DerivationLimits {
        max_input_bytes: compressed.len(),
        max_output_bytes: 1024,
        max_intermediate_bytes: 4096,
        ..DerivationLimits::default()
    };
    let report = run_with_limits(
        &compressed,
        &Recipe {
            steps: vec![Operation::GzipDecompress {}],
            constraints: vec![Constraint::Length { bytes: 4096 }],
        },
        constrained,
    )?;
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: l2_workbench::derivation::StepFailure::OutputLimitExceeded { limit: 1024 }
        })
    ));
    Ok(())
}

#[test]
fn work_budget_charged_input_bytes() -> Result<(), Box<dyn Error>> {
    let limits = DerivationLimits {
        max_work_bytes: 6,
        ..DerivationLimits::default()
    };
    let report = run_with_limits(
        b"four",
        &Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        },
        limits,
    )?;

    assert_eq!(report.work_bytes, 4);
    assert_eq!(report.output, b"four");
    assert!(matches!(
        report.steps.first().map(|step| &step.status),
        Some(StepStatus::Failed {
            error: l2_workbench::derivation::StepFailure::WorkBudgetExceeded { limit: 6 }
        })
    ));
    Ok(())
}

fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}
