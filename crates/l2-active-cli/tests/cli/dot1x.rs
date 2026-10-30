use std::{error::Error, process::Command, sync::atomic::AtomicBool};

use clap::Parser;
use l2_active_cli::{ActiveCommand, ActiveOutcome, Cli, Dot1xCommand, execute};

#[test]
fn eapol_start_requires_explicit_disruption_acknowledgement() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["dot1x", "probe", "--interface", "l2s-no-test"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("allow-eapol-start"));
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args([
            "dot1x",
            "probe",
            "--interface",
            "l2s-no-test",
            "--allow-eapol-start",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("dedicated-interface"));
    Ok(())
}

#[test]
fn library_rejects_a_missing_acknowledgement_before_interface_discovery()
-> Result<(), Box<dyn Error>> {
    let mut cli = Cli::try_parse_from([
        "l2solver-active",
        "dot1x",
        "probe",
        "--interface",
        "l2s-no-test",
        "--allow-eapol-start",
        "--dedicated-interface",
    ])?;
    let ActiveCommand::Dot1x {
        command: Dot1xCommand::Probe(options),
    } = &mut cli.active.command
    else {
        return Err("expected 802.1X probe".into());
    };
    options.dedicated_interface = false;
    let error = execute(&cli.active, &AtomicBool::new(false), &mut Vec::new())
        .err()
        .ok_or("missing error")?;
    assert_eq!(error.code(), "permission_denied");
    assert_eq!(error.stage(), "scope");
    let ActiveCommand::Dot1x {
        command: Dot1xCommand::Probe(options),
    } = &mut cli.active.command
    else {
        return Err("expected 802.1X probe".into());
    };
    options.dedicated_interface = true;
    options.allow_eapol_start = false;
    let error = execute(&cli.active, &AtomicBool::new(false), &mut Vec::new())
        .err()
        .ok_or("missing error")?;
    assert_eq!(error.code(), "permission_denied");
    Ok(())
}

#[test]
fn cancelled_acknowledged_probe_does_not_open_or_transmit() -> Result<(), Box<dyn Error>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "dot1x",
        "probe",
        "--interface",
        "l2s-no-test",
        "--allow-eapol-start",
        "--dedicated-interface",
        "--format",
        "json",
    ])?;
    let mut output = Vec::new();
    assert_eq!(
        execute(&cli.active, &AtomicBool::new(true), &mut output)?,
        ActiveOutcome::Cancelled
    );
    let report: serde_json::Value = serde_json::from_slice(&output)?;
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
#[ignore = "uses a verified isolated veth namespace and a built active helper"]
fn dot1x_cli_observes_owned_veth_request_and_confirms_cleanup() -> Result<(), Box<dyn Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/dot1x/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "dot1x::owned_namespace_child_asserts_cli_request",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("start_captured=true request_captured=true")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "invoked only by the verified owned veth fixture"]
fn owned_namespace_child_asserts_cli_request() -> Result<(), Box<dyn Error>> {
    crate::namespace::assert_owned()?;
    let interface = std::env::var("L2_TEST_DOT1X_INTERFACE")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let output = Command::new(crate::namespace::binary())
        .args([
            "dot1x",
            "probe",
            "--interface",
            &interface,
            "--allow-eapol-start",
            "--dedicated-interface",
            "--timeout-ms",
            "1500",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper)
        .output()?;
    let report = crate::namespace::completed(&output, "dot1x_probe")?;
    crate::namespace::accepted(&report, 60);
    assert_eq!(
        report
            .pointer("/requests/0/identifier")
            .and_then(serde_json::Value::as_u64),
        Some(41)
    );
    assert_eq!(
        report
            .pointer("/requests/0/request_type")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        report
            .get("authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}
