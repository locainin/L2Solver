use std::{error::Error, sync::atomic::AtomicBool};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, Cli, execute};

#[test]
fn cancelled_capability_query_does_not_open_the_selected_interface() -> Result<(), Box<dyn Error>> {
    let options = Cli::try_parse_from([
        "l2solver-active",
        "capabilities",
        "--interface",
        "l2s-no-test",
        "--format",
        "json",
    ])?;
    let mut output = Vec::new();
    let outcome = execute(&options.active, &AtomicBool::new(true), &mut output)?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    assert_eq!(
        report
            .pointer("/scope/interface")
            .and_then(serde_json::Value::as_str),
        Some("l2s-no-test")
    );
    Ok(())
}

#[test]
fn cancellation_before_preflight_does_not_open_the_selected_interface() -> Result<(), Box<dyn Error>>
{
    let options = Cli::try_parse_from([
        "l2solver-active",
        "arp",
        "probe",
        "--interface",
        "l2s-no-test",
        "--target",
        "192.0.2.1",
        "--format",
        "json",
    ])?;
    let mut output = Vec::new();
    let outcome = execute(&options.active, &AtomicBool::new(true), &mut output)?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    let scope = report.get("scope").ok_or("missing scope")?;
    assert_eq!(
        scope.get("interface").and_then(serde_json::Value::as_str),
        Some("l2s-no-test")
    );
    assert_eq!(
        scope.get("target").and_then(serde_json::Value::as_str),
        Some("192.0.2.1")
    );
    let tx = report.get("tx").ok_or("missing transmit status")?;
    assert_eq!(
        tx.get("attempt_scope").and_then(serde_json::Value::as_str),
        Some("link_send_call")
    );
    assert_eq!(
        tx.get("attempted").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let cleanup = report.get("cleanup").ok_or("missing cleanup status")?;
    assert_eq!(
        cleanup.get("state").and_then(serde_json::Value::as_str),
        Some("not_started")
    );
    Ok(())
}
