use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::protocol::RecordLimits;

const COMMAND: &[&str] = &[
    "records",
    "case.json",
    "--node",
    "1",
    "--schema",
    "schema.json",
];

fn expected_defaults() -> [NumericDefault; 8] {
    let limits = RecordLimits::default();
    [
        ("--max-schema-bytes", "1048576".to_owned()),
        ("--max-input-bytes", limits.max_input_bytes.to_string()),
        ("--max-records", limits.max_records.to_string()),
        (
            "--max-identifier-bytes",
            limits.max_identifier_bytes.to_string(),
        ),
        ("--max-report-bytes", limits.max_report_bytes.to_string()),
        ("--max-groups", limits.max_groups.to_string()),
        ("--max-output-bytes", limits.max_output_bytes.to_string()),
        (
            "--max-issue-examples",
            limits.max_issue_examples.to_string(),
        ),
    ]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::Records(options) = workbench(COMMAND)? else {
        return Err("records command was not selected".into());
    };
    assert_eq!(
        [
            ("--max-schema-bytes", options.max_schema_bytes.to_string()),
            ("--max-input-bytes", options.max_input_bytes.to_string()),
            ("--max-records", options.max_records.to_string()),
            (
                "--max-identifier-bytes",
                options.max_identifier_bytes.to_string()
            ),
            ("--max-report-bytes", options.max_report_bytes.to_string()),
            ("--max-groups", options.max_groups.to_string()),
            ("--max-output-bytes", options.max_output_bytes.to_string()),
            (
                "--max-issue-examples",
                options.max_issue_examples.to_string()
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
