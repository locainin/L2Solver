use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::{
    artifact::zip::{MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_EXPANDED_BYTES, MAX_ZIP_TOTAL_EXPANDED_BYTES},
    evidence::{MAX_BLOB_TOTAL_BYTES, MAX_NODES},
};

const COMMAND: &[&str] = &["expand", "case.json", "--node", "1"];

fn expected_defaults() -> [NumericDefault; 6] {
    [
        ("--max-objects", MAX_NODES.to_string()),
        ("--max-input-bytes", MAX_BLOB_TOTAL_BYTES.to_string()),
        ("--max-archive-entries", MAX_ZIP_ENTRIES.to_string()),
        (
            "--max-member-bytes",
            MAX_ZIP_ENTRY_EXPANDED_BYTES.to_string(),
        ),
        (
            "--max-zip-work-bytes",
            MAX_ZIP_TOTAL_EXPANDED_BYTES.to_string(),
        ),
        ("--max-retained-bytes", MAX_BLOB_TOTAL_BYTES.to_string()),
    ]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::Expand(options) = workbench(COMMAND)? else {
        return Err("expand command was not selected".into());
    };
    assert_eq!(
        [
            ("--max-objects", options.max_objects.to_string()),
            ("--max-input-bytes", options.max_input_bytes.to_string()),
            (
                "--max-archive-entries",
                options.max_archive_entries.to_string()
            ),
            ("--max-member-bytes", options.max_member_bytes.to_string()),
            (
                "--max-zip-work-bytes",
                options.max_zip_work_bytes.to_string()
            ),
            (
                "--max-retained-bytes",
                options.max_retained_bytes.to_string()
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
