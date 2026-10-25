use super::support::{path_arg, run};
use l2_workbench::{evidence::Case, sha256};
use serde_json::{Value, json};
use std::{error::Error, fs};

#[test]
fn timestamps_command_without_elevating_caller() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let events = directory.path().join("events.json");
    let bytes = br#"{"schema_version":1,"clock":{"id":"source-clock","epoch":"1601-01-01T00:00:00Z","radix":10,"exponent":7,"offset_seconds":0},"events":[{"id":"event-a","kind":"file_creation_time_change","file":{"identity":"file-a","path":"sample.bin"},"process":{"identity":"process-a","pid":7,"image":"worker.exe"},"source_event":{"provider":"endpoint-adapter","event_id":"time-change","record_id":"record-a"},"before_ticks":200,"after_ticks":100,"origin_claim":"claimed_validated_on_disk"}]}"#;
    fs::write(&events, bytes)?;
    let output = run(
        &["timestamps", "-", "--events", path_arg(&events)?],
        &Case::new().to_json()?,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/endpoint_events/source_sha256"),
        Some(&json!(sha256(bytes)))
    );
    assert_eq!(
        report.pointer("/endpoint_events/events/0/comparison"),
        Some(&json!("decreased"))
    );
    assert_eq!(
        report.pointer("/endpoint_events/events/0/validation"),
        Some(&json!("not_validated_by_workbench"))
    );
    assert_eq!(
        report.pointer("/endpoint_events/events/0/origin_claim"),
        Some(&json!("claimed_validated_on_disk"))
    );
    Ok(())
}

#[test]
fn timestamps_command_partial_status() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.mark_incomplete("Some source records were omitted")?;
    let output = run(&["timestamps", "-"], &case.to_json()?)?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("complete"), Some(&json!(false)));
    Ok(())
}
