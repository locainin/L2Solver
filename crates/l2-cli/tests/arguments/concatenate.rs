use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES;

const COMMAND: &[&str] = &["concatenate", "case.json", "--node", "1"];

fn expected_defaults() -> [NumericDefault; 1] {
    [("--max-output-bytes", MAX_BLOB_TOTAL_BYTES.to_string())]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::Concatenate(options) = workbench(COMMAND)? else {
        return Err("concatenate command was not selected".into());
    };
    assert_eq!(
        [("--max-output-bytes", options.max_output_bytes.to_string())],
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
