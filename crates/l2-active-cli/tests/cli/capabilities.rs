#![cfg(target_os = "linux")]

use std::{error::Error, process::Command};

#[test]
fn loopback_inventory_does_not_claim_wireless_or_unchecked_features() -> Result<(), Box<dyn Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["capabilities", "--interface", "lo", "--format", "json"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let status = report
        .get("wireless_status")
        .and_then(serde_json::Value::as_str);
    assert!(
        matches!(status, Some("not_reported" | "unknown")),
        "{report}"
    );
    assert!(
        report
            .get("wireless_reason")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    assert_eq!(
        report
            .get("monitor_mode")
            .and_then(serde_json::Value::as_str),
        Some("unknown")
    );
    assert_eq!(
        report
            .get("wireless_injection")
            .and_then(serde_json::Value::as_str),
        Some("unknown")
    );
    assert_eq!(
        report
            .get("hardware_timestamps")
            .and_then(serde_json::Value::as_str),
        Some("not_assessed")
    );
    assert_eq!(
        report
            .get("vlan_offload")
            .and_then(serde_json::Value::as_str),
        Some("not_assessed")
    );
    Ok(())
}
