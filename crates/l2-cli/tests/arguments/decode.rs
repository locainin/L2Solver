use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::derivation::{DEFAULT_MAX_WORK_BYTES, DerivationLimits, MAX_OUTPUT_BYTES};

const COMMAND: &[&str] = &[
    "decode",
    "case.json",
    "--node",
    "1",
    "--recipe",
    "recipe.json",
];

fn expected_defaults() -> [NumericDefault; 13] {
    let limits = DerivationLimits::default();
    [
        ("--max-recipe-bytes", "65536".to_owned()),
        ("--max-input-bytes", limits.max_input_bytes.to_string()),
        ("--max-output-bytes", limits.max_output_bytes.to_string()),
        (
            "--max-intermediate-bytes",
            limits.max_intermediate_bytes.to_string(),
        ),
        ("--max-work-bytes", limits.max_work_bytes.to_string()),
        ("--max-steps", limits.max_steps.to_string()),
        ("--max-constraints", limits.max_constraints.to_string()),
        (
            "--max-recipe-parameter-bytes",
            limits.max_recipe_parameter_bytes.to_string(),
        ),
        // Command-wide defaults are private to the argument module
        ("--max-items", "64".to_owned()),
        ("--max-total-input-bytes", (16 * 1024 * 1024).to_string()),
        (
            "--max-total-work-bytes",
            (DEFAULT_MAX_WORK_BYTES * 4).to_string(),
        ),
        (
            "--max-total-output-bytes",
            (MAX_OUTPUT_BYTES * 16).to_string(),
        ),
        ("--max-total-report-bytes", (4 * 1024 * 1024).to_string()),
    ]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::Decode(options) = workbench(COMMAND)? else {
        return Err("decode command was not selected".into());
    };
    assert_eq!(
        [
            ("--max-recipe-bytes", options.max_recipe_bytes.to_string()),
            ("--max-input-bytes", options.max_input_bytes.to_string()),
            ("--max-output-bytes", options.max_output_bytes.to_string()),
            (
                "--max-intermediate-bytes",
                options.max_intermediate_bytes.to_string()
            ),
            ("--max-work-bytes", options.max_work_bytes.to_string()),
            ("--max-steps", options.max_steps.to_string()),
            ("--max-constraints", options.max_constraints.to_string()),
            (
                "--max-recipe-parameter-bytes",
                options.max_recipe_parameter_bytes.to_string()
            ),
            ("--max-items", options.max_items.to_string()),
            (
                "--max-total-input-bytes",
                options.max_total_input_bytes.to_string()
            ),
            (
                "--max-total-work-bytes",
                options.max_total_work_bytes.to_string()
            ),
            (
                "--max-total-output-bytes",
                options.max_total_output_bytes.to_string()
            ),
            (
                "--max-total-report-bytes",
                options.max_total_report_bytes.to_string()
            ),
        ],
        expected_defaults()
    );
    Ok(())
}

#[test]
fn rejects_zero_budgets() {
    reject_zero(COMMAND, &expected_defaults());
}

#[test]
fn help_shows_numeric_defaults() -> TestResult {
    help_defaults(COMMAND, &expected_defaults())
}
