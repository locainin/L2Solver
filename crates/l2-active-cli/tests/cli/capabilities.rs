#![cfg(target_os = "linux")]

use std::{error::Error, process::Command};

#[test]
fn loopback_inventory_reports_only_available_wireless_and_ethernet_evidence()
-> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["capabilities", "--interface", "lo", "--format", "json"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("vlan"), Some(&serde_json::Value::Null));
    assert_eq!(
        report
            .get("scope_validation")
            .and_then(serde_json::Value::as_str),
        Some("sampled")
    );
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
    assert_vlan_offloads(&report)?;
    assert_timestamp_capabilities(&report)?;
    assert_eq!(
        report
            .get("raw_packet_permission")
            .and_then(serde_json::Value::as_str),
        Some("not_checked")
    );
    Ok(())
}

fn reported(value: &serde_json::Value) -> bool {
    let status = value.get("status").and_then(serde_json::Value::as_str);
    assert!(
        matches!(
            status,
            Some("reported" | "unsupported" | "denied" | "unknown")
        ),
        "{value}"
    );
    status == Some("reported")
}

fn assert_vlan_offloads(report: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let offloads = report
        .get("vlan_offload")
        .ok_or("missing VLAN offload evidence")?;
    for feature in [
        "ctag_rx",
        "ctag_tx",
        "ctag_filter",
        "stag_rx",
        "stag_tx",
        "stag_filter",
    ] {
        let value = offloads.get(feature).ok_or("missing VLAN feature")?;
        if reported(value) {
            let flags = value.get("value").ok_or("missing VLAN flags")?;
            for flag in ["hw", "wanted", "active"] {
                assert!(
                    flags.get(flag).is_some_and(serde_json::Value::is_boolean),
                    "{report}"
                );
            }
        }
    }
    Ok(())
}

fn assert_timestamp_capabilities(report: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let timestamps = report
        .get("hardware_timestamps")
        .ok_or("missing timestamp evidence")?;
    for feature in [
        "tx_software",
        "rx_software",
        "tx_hardware",
        "rx_hardware",
        "phc_index",
    ] {
        let value = timestamps
            .get(feature)
            .ok_or("missing timestamp capability")?;
        if reported(value) {
            let result = value.get("value").ok_or("missing timestamp value")?;
            if feature == "phc_index" {
                assert!(result.is_null() || result.is_u64(), "{report}");
            } else {
                assert!(result.is_boolean(), "{report}");
            }
        }
    }
    Ok(())
}

#[test]
fn loopback_text_reports_sampled_non_vlan_scope() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["capabilities", "--interface", "lo"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("VLAN: none on selected interface"), "{text}");
    assert!(text.contains("Scope validation: sampled"), "{text}");
    Ok(())
}
