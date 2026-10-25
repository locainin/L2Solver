use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::reconstruction::Limits;

const COMMAND: &[&str] = &["build", "capture.pcapng"];

fn expected_defaults() -> [NumericDefault; 8] {
    let limits = Limits::default();
    [
        ("--max-frames", limits.frames.to_string()),
        ("--max-bytes", limits.bytes.to_string()),
        ("--max-units", limits.units.to_string()),
        ("--max-sessions", limits.sessions.to_string()),
        ("--max-datagrams", limits.datagrams.to_string()),
        ("--max-range-bytes", limits.range_bytes.to_string()),
        (
            "--max-range-observations",
            limits.range_observations.to_string(),
        ),
        (
            "--max-range-retained-bytes",
            limits.range_retained_bytes.to_string(),
        ),
    ]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::Build { resources, .. } = workbench(COMMAND)? else {
        return Err("build command was not selected".into());
    };
    // The public conversion carries every private argument field to its consumer
    assert_eq!(resources.limits(), Limits::default());
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
