#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs,
    os::{
        fd::OwnedFd,
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

struct SilentHelper(PathBuf);

impl SilentHelper {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!("l2-active-test-{}", std::process::id()));
        fs::create_dir(&path)?;
        let helper = Self(path);
        fs::write(helper.executable(), "#!/bin/sh\nexec sleep 30\n")?;
        fs::set_permissions(helper.executable(), fs::Permissions::from_mode(0o700))?;
        Ok(helper)
    }

    fn executable(&self) -> PathBuf {
        self.0.join("silent-helper")
    }
}

impl Drop for SilentHelper {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.executable());
        let _ = fs::remove_dir(&self.0);
    }
}

fn run_timeout_fixture(child: &str) -> Result<Output, Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli/fixtures/silent_helper_veth.py");
    Ok(Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args(["--exact", child])
        .env("L2_ACTIVE_CLI_TEST_CHILD", "silent_helper")
        .output()?)
}

#[test]
fn helper_timeout_fixture_rejects_a_missing_child() -> Result<(), Box<dyn Error>> {
    let output = run_timeout_fixture("missing_namespace_child")?;
    assert!(
        !output.status.success(),
        "zero executed child tests were accepted"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected one child test"));
    Ok(())
}

#[test]
fn helper_timeout_fixture_detects_a_client_send() -> Result<(), Box<dyn Error>> {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cli/fixtures/silent_helper_veth.py");
    let sender = r"
import os
import socket
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as link:
    link.bind((os.environ['L2_TEST_ACTIVE_INTERFACE'], 0))
    link.send(bytes.fromhex('ffffffffffff0200000000010800') + bytes(46))
";
    let output = Command::new("python3")
        .arg(fixture)
        .args(["--", "python3", "-c", sender])
        .output()?;
    assert!(!output.status.success(), "client transmission was accepted");
    assert!(String::from_utf8_lossy(&output.stderr).contains("silent-helper test sent a packet"));
    Ok(())
}

#[test]
fn helper_open_timeout_is_incomplete_without_claiming_which_deadline_expired()
-> Result<(), Box<dyn Error>> {
    if crate::namespace::child_mode("silent_helper")? {
        return owned_namespace_helper_open_timeout();
    }
    let output = run_timeout_fixture(
        "helper_timeout::helper_open_timeout_is_incomplete_without_claiming_which_deadline_expired",
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("silent_helper_no_send=true cleanup_confirmed=true")
    );
    Ok(())
}

fn owned_namespace_helper_open_timeout() -> Result<(), Box<dyn Error>> {
    let interface = std::env::var("L2_TEST_ACTIVE_INTERFACE")?;
    let target = std::env::var("L2_TEST_ACTIVE_TARGET")?;
    let helper = SilentHelper::new()?;
    for (timeout, closed) in [("250", false), ("7000", false), ("250", true)] {
        let mut command = crate::namespace::command();
        command
            .args([
                "arp",
                "probe",
                "--interface",
                &interface,
                "--target",
                &target,
            ])
            .args(["--timeout-ms", timeout, "--format", "json", "--helper"])
            .arg(helper.executable());
        if closed {
            let (reader, writer) = UnixStream::pair()?;
            drop(reader);
            command.stdout(Stdio::from(OwnedFd::from(writer)));
        }
        let output = command.output()?;
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if closed {
            continue;
        }
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            result
                .get("stop_reason")
                .and_then(serde_json::Value::as_str),
            Some("helper_open_timeout")
        );
        assert_eq!(
            result.get("stage").and_then(serde_json::Value::as_str),
            Some("helper_open")
        );
        assert_eq!(
            result
                .pointer("/tx/attempted")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            result
                .pointer("/cleanup/state")
                .and_then(serde_json::Value::as_str),
            Some("unconfirmed")
        );
    }
    Ok(())
}
