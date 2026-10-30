#![cfg(target_os = "linux")]

use std::{error::Error, io::ErrorKind, process::Command};

use l2_active_cli::{Error as ActiveError, OutputFormat, write_error};
use l2_active_linux::{InterfaceSelector, discover};

#[test]
fn json_errors_preserve_runtime_error_categories() -> Result<(), Box<dyn Error>> {
    for (kind, expected) in [
        (ErrorKind::PermissionDenied, "permission_denied"),
        (ErrorKind::Unsupported, "unsupported"),
        (ErrorKind::TimedOut, "timeout"),
        (ErrorKind::Interrupted, "cancelled"),
        (ErrorKind::NetworkUnreachable, "network_unreachable"),
        (ErrorKind::HostUnreachable, "host_unreachable"),
    ] {
        let error = ActiveError::Helper(std::io::Error::new(kind, "detail"));
        let mut output = Vec::new();
        write_error(&error, OutputFormat::Json, &mut output)?;
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            value.get("code").and_then(serde_json::Value::as_str),
            Some(expected)
        );
        assert_eq!(
            value.get("stage").and_then(serde_json::Value::as_str),
            Some("helper")
        );
        if kind == ErrorKind::PermissionDenied {
            let message = value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .ok_or("missing error message")?;
            assert!(message.contains("CAP_NET_RAW"), "{message}");
        }
    }
    Ok(())
}

#[test]
fn missing_interface_produces_a_structured_not_found_error_without_transmitting()
-> Result<(), Box<dyn Error>> {
    let mut selected = None;
    for number in 0..100 {
        let name = format!("l2s-test-{number}");
        let selector = InterfaceSelector::new(&name)?;
        match discover(&selector) {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                selected = Some(name);
                break;
            }
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let name = selected.ok_or("could not select an absent test interface")?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(["capabilities", "--interface", &name, "--format", "json"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error.get("status").and_then(serde_json::Value::as_str),
        Some("error")
    );
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("not_found")
    );
    assert!(
        error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    assert!(output.stdout.is_empty());
    Ok(())
}
