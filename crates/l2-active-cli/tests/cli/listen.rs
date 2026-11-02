use std::{error::Error, process::Command, sync::atomic::AtomicBool};

use clap::Parser;
use l2_active_cli::{ActiveOutcome, Cli, execute};

#[test]
fn receive_only_commands_require_explicit_interface_and_bounded_limits()
-> Result<(), Box<dyn Error>> {
    for protocol in ["stp", "discovery"] {
        let missing = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
            .args([protocol, "observe"])
            .output()?;
        assert_eq!(missing.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("interface"));
        let invalid = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
            .args([
                protocol,
                "observe",
                "--interface",
                "test0",
                "--timeout-ms",
                "0",
            ])
            .output()?;
        assert_eq!(invalid.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&invalid.stderr).contains("timeout"));
    }
    Ok(())
}

#[test]
fn cancelled_receive_only_commands_do_not_open_or_send() -> Result<(), Box<dyn Error>> {
    for protocol in ["stp", "discovery"] {
        let cli = Cli::try_parse_from([
            "l2solver-active",
            protocol,
            "observe",
            "--interface",
            "l2s-no-test",
            "--format",
            "json",
        ])?;
        let mut bytes = Vec::new();
        assert_eq!(
            execute(&cli.active, &AtomicBool::new(true), &mut bytes)?,
            ActiveOutcome::Cancelled
        );
        let report: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            report.get("operation").and_then(serde_json::Value::as_str),
            Some(format!("{protocol}_observe").as_str())
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
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn receive_only_cli_commands_observe_owned_veth_frames_and_release_memberships()
-> Result<(), Box<dyn Error>> {
    if let Some(mode) = std::env::var_os("L2_ACTIVE_CLI_TEST_CHILD") {
        if mode == "stp" && crate::namespace::child_mode("stp")? {
            return stp_namespace_child();
        }
        if mode == "discovery" && crate::namespace::child_mode("discovery")? {
            return discovery_namespace_child();
        }
        return Err("unexpected private child mode".into());
    }
    crate::namespace::child_mode("stp")?;
    let helper = crate::namespace::matching_helper()?;
    for (fixture, mode, marker) in [
        (
            "../l2-active-linux/tests/stp/namespace.py",
            "stp",
            "stp_observed=true",
        ),
        (
            "../l2-active-linux/tests/listen/namespace.py",
            "discovery",
            "cdp_sent=1",
        ),
    ] {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture);
        let output = Command::new("python3")
            .arg(fixture)
            .arg("--")
            .arg(std::env::current_exe()?)
            .args(["--exact", "listen::receive_only_cli_commands_observe_owned_veth_frames_and_release_memberships"])
            .env("L2_ACTIVE_CLI_TEST_CHILD", mode)
            .env("L2_TEST_ACTIVE_HELPER", &helper)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(marker));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn stp_namespace_child() -> Result<(), Box<dyn Error>> {
    observe_fixture("stp", "STP", "0180c2000000")
}

#[cfg(target_os = "linux")]
fn discovery_namespace_child() -> Result<(), Box<dyn Error>> {
    observe_fixture("discovery", "DISCOVERY", "0180c200000e")
}

#[cfg(target_os = "linux")]
fn observe_fixture(protocol: &str, prefix: &str, group: &str) -> Result<(), Box<dyn Error>> {
    use std::{fs, process::Stdio};

    let interface = std::env::var(format!("L2_TEST_{prefix}_INTERFACE"))?;
    let ready =
        std::env::var_os(format!("L2_TEST_{prefix}_READY")).ok_or("missing readiness path")?;
    let observed =
        std::env::var_os(format!("L2_TEST_{prefix}_OBSERVED")).ok_or("missing observation path")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let index: u32 = fs::read_to_string(
        std::path::Path::new("/sys/class/net")
            .join(&interface)
            .join("ifindex"),
    )?
    .trim()
    .parse()?;
    let baseline = crate::namespace::memberships(index, group)?;
    let mut child = crate::namespace::command()
        .args([
            protocol,
            "observe",
            "--interface",
            &interface,
            "--timeout-ms",
            "2000",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Err(error) = crate::namespace::await_membership(&mut child, index, group, baseline)
        .and_then(|()| fs::write(ready, "ready").map_err(Into::into))
    {
        let _ = child.kill();
        let output = child.wait_with_output()?;
        return Err(format!("{error}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let output = child.wait_with_output()?;
    let report = crate::namespace::completed(&output, &format!("{protocol}_observe"))?;
    assert_eq!(
        report
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    verify_observations(protocol, &report)?;
    fs::write(observed, "observed")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_observations(protocol: &str, report: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let observations = report
        .get("observations")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing observations")?;
    assert_ne!(observations.as_slice(), [] as [serde_json::Value; 0]);
    if protocol == "discovery" {
        assert!(
            observations
                .iter()
                .any(
                    |item| item.get("protocol").and_then(serde_json::Value::as_str) == Some("lldp")
                )
        );
        assert!(
            observations
                .iter()
                .any(
                    |item| item.get("protocol").and_then(serde_json::Value::as_str) == Some("cdp")
                )
        );
    } else {
        assert!(observations.iter().any(|item| {
            item.get("disposition").and_then(serde_json::Value::as_str) == Some("decoded")
        }));
    }
    Ok(())
}
