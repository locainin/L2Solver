#![cfg(target_os = "linux")]

use std::{
    error::Error,
    path::Path,
    process::{Command, Output, Stdio},
};

#[test]
fn real_dtp_cli_observes_claims_without_transmission_or_raw_disclosure()
-> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("dtp")? {
        return dtp_namespace_child();
    }
    exercise(
        "dtp",
        "../l2-active/tests/switching/fixtures/veth.py",
        "switching_delivered=true no_client_send=true",
    )
}

#[test]
fn real_vtp_cli_observes_claims_without_transmission_or_raw_disclosure()
-> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("vtp")? {
        return vtp_namespace_child();
    }
    exercise(
        "vtp",
        "../l2-active/tests/switching/fixtures/veth.py",
        "switching_delivered=true no_client_send=true",
    )
}

#[test]
fn real_isl_cli_observes_claims_without_transmission_or_raw_disclosure()
-> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("isl")? {
        return isl_namespace_child();
    }
    exercise(
        "isl",
        "../l2-active/tests/isl/fixtures/veth.py",
        "isl_delivered=true no_client_send=true",
    )
}

fn exercise(protocol: &str, fixture: &str, marker: &str) -> Result<(), Box<dyn Error>> {
    let helper = crate::namespace::matching_helper()?;
    let parent_test = match protocol {
        "dtp" => "switching::real_dtp_cli_observes_claims_without_transmission_or_raw_disclosure",
        "vtp" => "switching::real_vtp_cli_observes_claims_without_transmission_or_raw_disclosure",
        "isl" => "switching::real_isl_cli_observes_claims_without_transmission_or_raw_disclosure",
        _ => return Err("unknown switching fixture".into()),
    };
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture);
    for raw in [false, true] {
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--")
            .arg(std::env::current_exe()?)
            .args(["--exact", parent_test])
            .env("L2_ACTIVE_CLI_TEST_CHILD", protocol)
            .env("L2_TEST_INCLUDE_RAW", if raw { "1" } else { "0" })
            .env("L2_TEST_ACTIVE_HELPER", &helper)
            .output()?;
        assert!(
            output.status.success(),
            "private {protocol} fixture failed; raw={raw}"
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(stdout.contains(marker) && stdout.contains("cleanup_confirmed=true"));
    }
    Ok(())
}

fn dtp_namespace_child() -> Result<(), Box<dyn Error>> {
    observe("dtp", "SWITCHING", "01000ccccccc", "dtp.bin")
}

fn vtp_namespace_child() -> Result<(), Box<dyn Error>> {
    observe("vtp", "SWITCHING", "01000ccccccc", "vtp-summary.bin")
}

fn isl_namespace_child() -> Result<(), Box<dyn Error>> {
    observe("isl", "ISL", "01000c000003", "valid.bin")
}

fn observe(
    protocol: &str,
    prefix: &str,
    group: &str,
    expected_file: &str,
) -> Result<(), Box<dyn Error>> {
    let interface = std::env::var(format!("L2_TEST_{prefix}_INTERFACE"))?;
    let fixture_key = if prefix == "SWITCHING" {
        "L2_TEST_SWITCHING_FIXTURES".to_owned()
    } else {
        format!("L2_TEST_{prefix}_FIXTURE")
    };
    let fixture = std::env::var_os(fixture_key).ok_or("missing fixture directory")?;
    let sync =
        std::env::var_os(format!("L2_TEST_{prefix}_SYNC_DIR")).ok_or("missing sync directory")?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let include_raw = std::env::var("L2_TEST_INCLUDE_RAW")? == "1";
    let index =
        std::fs::read_to_string(Path::new("/sys/class/net").join(&interface).join("ifindex"))?
            .trim()
            .parse::<u32>()?;
    let baseline = crate::namespace::memberships(index, group)?;
    let mut command = crate::namespace::command();
    command
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
        .stderr(Stdio::piped());
    if include_raw {
        command.arg("--include-raw");
    }
    let mut child = command.spawn()?;
    if let Err(error) = crate::namespace::await_membership(&mut child, index, group, baseline) {
        let _ = child.kill();
        child.wait_with_output()?;
        return Err(error);
    }
    std::fs::write(Path::new(&sync).join("ready"), "ready")?;
    let output = child.wait_with_output()?;
    let expected = std::fs::read(Path::new(&fixture).join(expected_file))?;
    verify_output(protocol, output, &expected, include_raw)?;
    assert_eq!(
        crate::namespace::memberships(index, group)?,
        baseline,
        "multicast membership leaked"
    );
    Ok(())
}

fn verify_output(
    protocol: &str,
    output: Output,
    expected: &[u8],
    include_raw: bool,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(3),
        "incomplete collection should report exit status 3"
    );
    let stderr = String::from_utf8(output.stderr)?;
    assert_no_private_data(&stderr);
    let text = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        report.pointer("/cleanup/confirmed"),
        Some(&serde_json::Value::Bool(true))
    );
    assert_eq!(
        report.pointer("/tx/attempted"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(
        report
            .pointer("/scope/scope_validation")
            .and_then(serde_json::Value::as_str),
        Some("sampled")
    );
    verify_claims(protocol, &report)?;
    verify_disclosure(&report, &text, expected, include_raw)?;
    Ok(())
}

fn verify_claims(protocol: &str, report: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let observations = report
        .get("observations")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing observations")?;
    let (count, first, last) = match protocol {
        "dtp" => (2, "unsupported_version", "advertisement"),
        "vtp" => (2, "malformed", "message"),
        "isl" => (3, "malformed", "frame"),
        _ => return Err("unknown switching protocol".into()),
    };
    assert_eq!(observations.len(), count);
    assert_eq!(
        observations
            .first()
            .and_then(|item| item.get("disposition"))
            .and_then(serde_json::Value::as_str),
        Some(first)
    );
    assert_eq!(
        observations
            .last()
            .and_then(|item| item.get("disposition"))
            .and_then(serde_json::Value::as_str),
        Some(last)
    );
    if protocol == "isl" {
        assert_eq!(
            report
                .pointer("/details/admitted_media")
                .and_then(serde_json::Value::as_str),
            Some("ethernet_only")
        );
        assert_eq!(
            report
                .pointer("/details/crc_validation")
                .and_then(serde_json::Value::as_str),
            Some("not_performed")
        );
    }
    Ok(())
}

fn verify_disclosure(
    report: &serde_json::Value,
    text: &str,
    expected: &[u8],
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    use std::fmt::Write as _;

    let observations = report
        .get("observations")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing observations")?;
    let mut hex = String::new();
    for byte in expected {
        write!(&mut hex, "{byte:02x}")?;
    }
    if raw {
        assert!(observations.iter().any(|item| {
            item.get("frame_hex").and_then(serde_json::Value::as_str) == Some(hex.as_str())
        }));
    } else {
        assert!(
            observations
                .iter()
                .all(|item| item.get("frame_hex").is_none())
        );
        assert_no_private_data(text);
    }
    Ok(())
}

fn assert_no_private_data(text: &str) {
    for secret in [
        "DIGEST-SECRET",
        "PADDING-SECRET",
        "PRIVATE-USER-CONTENT",
        "4449474553542d534543524554212121",
        "50414444494e472d534543524554",
        "505249564154452d555345522d434f4e54454e54",
    ] {
        assert!(!text.contains(secret), "private data leaked into output");
    }
}
