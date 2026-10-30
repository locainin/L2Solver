use std::{error::Error, process::Command, sync::atomic::AtomicBool};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, Cli, execute};

#[test]
fn ndp_probe_requires_explicit_interface_and_ipv6_target() -> Result<(), Box<dyn Error>> {
    for (args, missing) in [
        (&["ndp", "probe", "--target", "fe80::2"][..], "interface"),
        (&["ndp", "probe", "--interface", "test0"][..], "target"),
        (
            &[
                "ndp",
                "probe",
                "--interface",
                "test0",
                "--target",
                "bad-address",
            ][..],
            "target",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
            .args(args)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(missing));
    }
    Ok(())
}

#[test]
fn cancelled_ndp_probe_reports_no_send_without_opening_the_interface() -> Result<(), Box<dyn Error>>
{
    let options = Cli::try_parse_from([
        "l2solver-active",
        "ndp",
        "probe",
        "--interface",
        "l2s-no-test",
        "--target",
        "fe80::2",
        "--format",
        "json",
    ])?;
    let mut bytes = Vec::new();
    let outcome = execute(&options.active, &AtomicBool::new(true), &mut bytes)?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let report: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        report
            .pointer("/scope/target")
            .and_then(serde_json::Value::as_str),
        Some("fe80::2")
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
fn global_target_is_reported_unsupported_without_opening_the_helper() -> Result<(), Box<dyn Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args([
            "ndp",
            "probe",
            "--interface",
            "lo",
            "--target",
            "2001:db8::1",
            "--format",
            "json",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        error.get("stage").and_then(serde_json::Value::as_str),
        Some("scope")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "uses a verified isolated veth namespace and a built active helper"]
fn ndp_cli_observes_owned_veth_advertisement_and_confirms_cleanup() -> Result<(), Box<dyn Error>> {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/ndp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "ndp::owned_namespace_child_asserts_cli_advertisement",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("request_captured=true advertisement_captured=true")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "invoked only by the verified owned veth fixture"]
fn owned_namespace_child_asserts_cli_advertisement() -> Result<(), Box<dyn Error>> {
    crate::namespace::assert_owned()?;
    let interface = std::env::var("L2_TEST_NDP_INTERFACE")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let output = Command::new(crate::namespace::binary())
        .args([
            "ndp",
            "probe",
            "--interface",
            &interface,
            "--source-ip",
            "fe80::1",
            "--target",
            "fe80::2",
            "--expected-mac",
            "02:00:00:00:00:02",
            "--timeout-ms",
            "1500",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper)
        .output()?;
    let report = crate::namespace::completed(&output, "ndp_probe")?;
    crate::namespace::accepted(&report, 86);
    assert_eq!(
        report
            .pointer("/replies/0/mac")
            .and_then(serde_json::Value::as_str),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(
        report
            .pointer("/replies/0/matches_expected")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(())
}
