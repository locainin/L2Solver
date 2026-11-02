use std::{error::Error, process::Command, sync::atomic::AtomicBool};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, Cli, execute};

#[test]
fn dhcp_discovery_requires_a_selected_interface_and_valid_limits() -> Result<(), Box<dyn Error>> {
    for (args, expected) in [
        (&["dhcp", "probe"][..], "interface"),
        (
            &[
                "dhcp",
                "probe",
                "--interface",
                "test0",
                "--expected-server",
                "224.0.0.1",
            ][..],
            "expected-server",
        ),
        (
            &["dhcp", "probe", "--interface", "test0", "--timeout-ms", "0"][..],
            "timeout",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
            .args(args)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
    Ok(())
}

#[test]
fn cancelled_dhcp_discovery_does_not_open_an_interface_or_send() -> Result<(), Box<dyn Error>> {
    let options = Cli::try_parse_from([
        "l2solver-active",
        "dhcp",
        "probe",
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
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        report
            .pointer("/cleanup/state")
            .and_then(serde_json::Value::as_str),
        Some("not_started")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup() -> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("dhcp")? {
        return owned_namespace_child_asserts_cli_offer();
    }
    let helper = crate::namespace::matching_helper()?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/dhcp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "dhcp::dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup",
        ])
        .env("L2_ACTIVE_CLI_TEST_CHILD", "dhcp")
        .env("L2_TEST_ACTIVE_HELPER", helper)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true offer_captured=true")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn owned_namespace_child_asserts_cli_offer() -> Result<(), Box<dyn Error>> {
    let interface = std::env::var("L2_TEST_DHCP_INTERFACE")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let output = crate::namespace::command()
        .args([
            "dhcp",
            "probe",
            "--interface",
            &interface,
            "--expected-server",
            "192.0.2.1",
            "--timeout-ms",
            "1500",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper)
        .output()?;
    let report = crate::namespace::completed(&output, "dhcp_probe")?;
    crate::namespace::accepted(&report, 342);
    let offers = report
        .get("offers")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing offers")?;
    assert!(offers.iter().any(|offer| {
        offer
            .get("server_identifier")
            .and_then(serde_json::Value::as_str)
            == Some("192.0.2.1")
            && offer
                .get("offered_address")
                .and_then(serde_json::Value::as_str)
                == Some("192.0.2.10")
            && offer
                .get("matches_expected")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    }));
    Ok(())
}
