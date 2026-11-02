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
fn ndp_help_explains_global_route_requirement() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["ndp", "probe", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("direct route"), "{help}");
    assert!(!help.contains("link-local IPv6 neighbor"), "{help}");
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

#[test]
fn global_target_parses_as_a_candidate_requiring_route_authorization() -> Result<(), Box<dyn Error>>
{
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "ndp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "2001:db8:1::2",
    ])?;
    let l2_active_cli::ActiveCommand::Ndp {
        command: l2_active_cli::NdpCommand::Probe(options),
    } = cli.active.command
    else {
        return Err("expected NDP probe".into());
    };
    assert_eq!(options.target.to_string(), "2001:db8:1::2");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn global_ndp_cli_requires_a_direct_route_and_observes_the_reply() -> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("global_ndp")? {
        return owned_global_namespace_child();
    }
    let helper = crate::namespace::matching_helper()?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/ndp/fixtures/global_veth.py");
    for case in ["direct", "no_route"] {
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--")
            .arg(std::env::current_exe()?)
            .args([
                "--exact",
                "ndp::global_ndp_cli_requires_a_direct_route_and_observes_the_reply",
            ])
            .env("L2_ACTIVE_CLI_TEST_CHILD", "global_ndp")
            .env("L2_TEST_NDP_GLOBAL_CASE", case)
            .env("L2_TEST_ACTIVE_HELPER", &helper)
            .output()?;
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("route_case_confirmed=true cleanup_confirmed=true")
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn owned_global_namespace_child() -> Result<(), Box<dyn Error>> {
    let case = std::env::var("L2_TEST_NDP_GLOBAL_CASE")?;
    let interface = std::env::var("L2_TEST_NDP_INTERFACE")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let output = crate::namespace::command()
        .args([
            "ndp",
            "probe",
            "--interface",
            &interface,
            "--source-ip",
            "2001:db8:1::1",
            "--target",
            "2001:db8:1::2",
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
    if case == "no_route" {
        assert_eq!(output.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        let code = error.get("code").and_then(serde_json::Value::as_str);
        assert!(
            matches!(
                code,
                Some("network_unreachable" | "host_unreachable" | "unsupported")
            ),
            "{error}"
        );
        assert_eq!(
            error.get("stage").and_then(serde_json::Value::as_str),
            Some("helper")
        );
        return Ok(());
    }
    let report = crate::namespace::completed(&output, "ndp_probe")?;
    crate::namespace::accepted(&report, 86);
    assert_eq!(
        report
            .pointer("/scope/source_ip")
            .and_then(serde_json::Value::as_str),
        Some("2001:db8:1::1")
    );
    assert_eq!(
        report
            .pointer("/replies/0/mac")
            .and_then(serde_json::Value::as_str),
        Some("02:00:00:00:00:02")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn ndp_cli_observes_owned_veth_advertisement_and_confirms_cleanup() -> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("ndp")? {
        return owned_namespace_child_asserts_cli_advertisement();
    }
    let helper = crate::namespace::matching_helper()?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../l2-active/tests/ndp/fixtures/veth.py");
    let output = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "ndp::ndp_cli_observes_owned_veth_advertisement_and_confirms_cleanup",
        ])
        .env("L2_ACTIVE_CLI_TEST_CHILD", "ndp")
        .env("L2_TEST_ACTIVE_HELPER", helper)
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
fn owned_namespace_child_asserts_cli_advertisement() -> Result<(), Box<dyn Error>> {
    let interface = std::env::var("L2_TEST_NDP_INTERFACE")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let output = crate::namespace::command()
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
