use std::{error::Error, process::Command};

#[test]
fn active_help_shows_only_supported_native_operations() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["active", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for operation in [
        "capabilities",
        "arp",
        "dhcp",
        "ndp",
        "stp",
        "discovery",
        "dot1x",
        "vrrp",
        "hsrp",
        "dtp",
        "vtp",
        "mpls",
        "isl",
        "vlan",
    ] {
        assert!(help.contains(operation), "missing {operation}: {help}");
    }
    Ok(())
}

#[test]
fn active_protocol_observers_require_an_interface_and_explain_raw_disclosure()
-> Result<(), Box<dyn Error>> {
    for protocol in ["vrrp", "hsrp", "dtp", "vtp", "mpls", "isl"] {
        let missing = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["active", protocol, "observe"])
            .output()?;
        assert_eq!(missing.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("interface"));
        let help = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["active", protocol, "observe", "--help"])
            .output()?;
        assert!(help.status.success());
        assert!(String::from_utf8_lossy(&help.stdout).contains("--include-raw"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn active_protocol_observer_discovery_errors_preserve_codes_and_omit_details()
-> Result<(), Box<dyn Error>> {
    let interface = format!("l2s-{}", std::process::id());
    assert!(
        !std::path::Path::new("/sys/class/net")
            .join(&interface)
            .exists()
    );
    for protocol in ["vrrp", "hsrp", "dtp", "vtp", "mpls", "isl"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "active",
                protocol,
                "observe",
                "--interface",
                &interface,
                "--format",
                "json",
            ])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(
            error.get("code").and_then(serde_json::Value::as_str),
            Some("not_found")
        );
        assert_eq!(
            error.get("stage").and_then(serde_json::Value::as_str),
            Some("discovery")
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&interface));
        assert_eq!(output.stdout.len(), 0);
    }
    Ok(())
}

#[test]
fn active_arp_requires_an_explicit_interface_and_target() -> Result<(), Box<dyn Error>> {
    for arguments in [
        &["active", "arp", "probe", "--target", "192.0.2.10"][..],
        &["active", "arp", "probe", "--interface", "test0"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(2));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn active_missing_interface_renders_the_runtime_error_as_json() -> Result<(), Box<dyn Error>> {
    let interface = format!("l2s-{}", std::process::id());
    assert!(
        !std::path::Path::new("/sys/class/net")
            .join(&interface)
            .exists()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "active",
            "capabilities",
            "--interface",
            &interface,
            "--format",
            "json",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("not_found")
    );
    assert_eq!(
        error.get("stage").and_then(serde_json::Value::as_str),
        Some("discovery")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn active_buffer_flush_failure_renders_a_json_output_error() -> Result<(), Box<dyn Error>> {
    use std::{fs::OpenOptions, process::Stdio};

    let full = OpenOptions::new().write(true).open("/dev/full")?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "active",
            "capabilities",
            "--interface",
            "lo",
            "--format",
            "json",
        ])
        .stdout(Stdio::from(full))
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error.get("stage").and_then(serde_json::Value::as_str),
        Some("output")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn active_closed_stdout_preserves_success_and_error_outcomes() -> Result<(), Box<dyn Error>> {
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };

    for (interface, expected) in [
        ("lo".to_owned(), 0),
        (format!("l2s-{}", std::process::id()), 1),
    ] {
        let (reader, writer) = UnixStream::pair()?;
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([
                "active",
                "capabilities",
                "--interface",
                &interface,
                "--format",
                "json",
            ])
            .stdout(Stdio::from(OwnedFd::from(writer)))
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
