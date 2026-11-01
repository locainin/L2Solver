use std::{
    error::Error,
    ffi::OsStr,
    path::Path,
    process::{Command, Output},
};

#[test]
#[ignore = "requires a matching helper and a proved private network namespace"]
fn real_vlan_canary_assessment_observes_forwarding_and_keeps_silence_inconclusive()
-> Result<(), Box<dyn Error>> {
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing active helper")?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan_assessment/namespace.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(std::env::current_exe()?)
        .arg(helper)
        .output()?;
    assert!(
        output.status.success(),
        "isolated VLAN canary fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::str::from_utf8(&output.stdout)?;
    assert!(text.contains("forwarded_case=true"));
    assert!(text.contains("forwarded_raw_case=true"));
    assert!(text.contains("isolated_case=true"));
    assert!(text.contains("cleanup_confirmed=true"));
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved private VLAN canary fixture"]
fn owned_vlan_canary_assessment_child() -> Result<(), Box<dyn Error>> {
    crate::namespace::assert_owned()?;
    let helper = std::env::var_os("L2_TEST_ACTIVE_HELPER").ok_or("missing helper")?;
    let case = std::env::var("L2_TEST_VLAN_ASSESSMENT_CASE")?;
    let output = run_cli(&case, &helper)?;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    check_status(&report, output.status.code(), &case)?;
    check_scope(&report)?;
    check_phases(&report, &case)
}

fn run_cli(case: &str, helper: &OsStr) -> Result<Output, Box<dyn Error>> {
    let mut command = crate::namespace::command();
    command
        .args([
            "vlan",
            "assess",
            "--control-interface",
            "l2ctrl0",
            "--interface",
            "l2test0",
            "--target",
            "192.0.2.3",
            "--expected-mac",
            "02:00:00:00:00:09",
            "--control-source-ip",
            "192.0.2.1",
            "--source-ip",
            "192.0.2.2",
            "--timeout-ms",
            "3600",
            "--max-received-packets",
            "128",
            "--max-received-bytes",
            "65536",
            "--format",
            "json",
            "--helper",
        ])
        .arg(helper);
    if case == "forwarded_raw" {
        command.arg("--include-raw");
    }
    Ok(command.output()?)
}

fn check_status(
    report: &serde_json::Value,
    exit: Option<i32>,
    case: &str,
) -> Result<(), Box<dyn Error>> {
    let status = report.get("status").and_then(serde_json::Value::as_str);
    match case {
        "forwarded" | "forwarded_raw" => {
            assert_eq!(status, Some("expected_claim_observed"), "{report}");
            assert_eq!(exit, Some(4), "{report}");
        }
        "isolated" => {
            assert_eq!(status, Some("inconclusive"), "{report}");
            assert_eq!(exit, Some(3), "{report}");
            assert_eq!(
                report.get("completion").and_then(serde_json::Value::as_str),
                Some("incomplete")
            );
        }
        _ => return Err("unknown private fixture case".into()),
    }
    assert_eq!(
        report
            .get("authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        report
            .get("control_claims_observed")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "{report}"
    );
    Ok(())
}

fn check_scope(report: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        report
            .pointer("/scope/control/vlan/id")
            .and_then(serde_json::Value::as_u64),
        Some(37)
    );
    assert_eq!(
        report
            .pointer("/scope/test/vlan/id")
            .and_then(serde_json::Value::as_u64),
        Some(38)
    );
    let control_index = std::fs::read_to_string("/sys/class/net/l2ctrl0/ifindex")?
        .trim()
        .parse::<u64>()?;
    let test_index = std::fs::read_to_string("/sys/class/net/l2test0/ifindex")?
        .trim()
        .parse::<u64>()?;
    assert_ne!(control_index, test_index);
    assert_eq!(
        report
            .pointer("/scope/control/ifindex")
            .and_then(serde_json::Value::as_u64),
        Some(control_index)
    );
    assert_eq!(
        report
            .pointer("/scope/test/ifindex")
            .and_then(serde_json::Value::as_u64),
        Some(test_index)
    );
    Ok(())
}

fn check_phases(report: &serde_json::Value, case: &str) -> Result<(), Box<dyn Error>> {
    for phase in ["control_before", "test", "control_after"] {
        let value = report.get(phase).ok_or("missing assessment phase")?;
        assert_eq!(
            value.get("state").and_then(serde_json::Value::as_str),
            Some("collected"),
            "{report}"
        );
        assert_eq!(
            value
                .pointer("/tx/accepted_packets")
                .and_then(serde_json::Value::as_u64),
            Some(1),
            "{report}"
        );
        for reply in value
            .get("replies")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing replies")?
        {
            assert_eq!(
                reply.get("frame_hex").is_some(),
                case == "forwarded_raw",
                "{report}"
            );
        }
        assert_eq!(
            value
                .pointer("/cleanup/confirmed")
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "{report}"
        );
    }
    for (field, limit) in [("total_packets", 128_u64), ("total_bytes", 65_536)] {
        let before = report
            .pointer(&format!("/control_before/rx/{field}"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing control usage")?;
        let after = report
            .pointer(&format!("/control_after/rx/{field}"))
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing control usage")?;
        assert!(
            before
                .checked_add(after)
                .is_some_and(|total| total <= limit)
        );
    }
    Ok(())
}
