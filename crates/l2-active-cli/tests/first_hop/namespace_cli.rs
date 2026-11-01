#![cfg(target_os = "linux")]

use std::{
    error::Error,
    path::Path,
    process::{Command, Stdio},
};

#[test]
#[ignore = "requires a matching helper and a verified isolated veth namespace"]
fn real_vrrp_cli_observes_claims_without_transmitting_or_leaking_by_default()
-> Result<(), Box<dyn Error>> {
    exercise_fixture("vrrp", "advertisements_delivered=true no_client_send=true")
}

#[test]
#[ignore = "requires a matching helper and a verified isolated veth namespace"]
fn real_hsrp_cli_observes_claims_without_transmitting_or_leaking_by_default()
-> Result<(), Box<dyn Error>> {
    exercise_fixture("hsrp", "messages_delivered=true no_client_send=true")
}

fn exercise_fixture(protocol: &str, expected: &str) -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../l2-active/tests/first_hop/{protocol}/fixtures/veth.py"
    ));
    for raw in [false, true] {
        let output = Command::new("python3")
            .arg(&fixture)
            .arg("--")
            .arg(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                &format!("first_hop::{protocol}_namespace_child"),
            ])
            .env("L2_TEST_INCLUDE_RAW", if raw { "1" } else { "0" })
            .output()?;
        assert!(
            output.status.success(),
            "{protocol} fixture failed; raw={raw}"
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains(expected) && stdout.contains("cleanup_confirmed=true"),
            "missing private-network cleanup proof"
        );
    }
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved VRRP veth fixture"]
fn vrrp_namespace_child() -> Result<(), Box<dyn Error>> {
    observe("vrrp", "VRRP", "01005e000012", "--vrid", "42", "valid.bin")
}

#[test]
#[ignore = "invoked only by the proved HSRP veth fixture"]
fn hsrp_namespace_child() -> Result<(), Box<dyn Error>> {
    observe(
        "hsrp",
        "HSRP",
        "01005e000002",
        "--group",
        "0",
        "advertisement.bin",
    )
}

fn observe(
    protocol: &str,
    prefix: &str,
    group: &str,
    filter: &str,
    value: &str,
    fixture: &str,
) -> Result<(), Box<dyn Error>> {
    crate::namespace::assert_owned()?;
    let interface = std::env::var(format!("L2_TEST_{prefix}_INTERFACE"))?;
    let fixture_dir =
        std::env::var_os(format!("L2_TEST_{prefix}_FIXTURE")).ok_or("missing fixtures")?;
    let sync_dir =
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
            filter,
            value,
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
    std::fs::write(Path::new(&sync_dir).join("ready"), "ready")?;
    let output = child.wait_with_output()?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "unexpected observer exit status"
    );
    let stderr = String::from_utf8(output.stderr)?;
    assert_no_secrets(&stderr);
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
    verify_disclosure(
        &report,
        &text,
        &std::fs::read(Path::new(&fixture_dir).join(fixture))?,
        include_raw,
    )?;
    assert_eq!(
        crate::namespace::memberships(index, group)?,
        baseline,
        "multicast membership leaked"
    );
    Ok(())
}

fn verify_disclosure(
    report: &serde_json::Value,
    text: &str,
    expected: &[u8],
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    let observations = report
        .get("observations")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing observations")?;
    assert!(!observations.is_empty());
    let hex = expected
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
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
        assert_no_secrets(text);
    }
    Ok(())
}

fn assert_no_secrets(text: &str) {
    for secret in [
        "AuthP@ss",
        "PAD-SECRET",
        "VRRPauth",
        "4175746850407373",
        "5041442d534543524554",
        "5652525061757468",
    ] {
        assert!(!text.contains(secret), "sensitive data leaked into output");
    }
}
