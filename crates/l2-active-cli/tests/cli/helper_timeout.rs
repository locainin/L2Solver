#![cfg(target_os = "linux")]

use std::{
    error::Error,
    fs,
    os::{
        fd::OwnedFd,
        unix::{fs::PermissionsExt, net::UnixStream},
    },
    path::PathBuf,
    process::{Command, Stdio},
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

#[test]
#[ignore = "requires L2_TEST_ACTIVE_INTERFACE and L2_TEST_ACTIVE_TARGET; silent helper sends no traffic"]
fn helper_open_timeout_is_incomplete_without_claiming_which_deadline_expired()
-> Result<(), Box<dyn Error>> {
    let interface = std::env::var("L2_TEST_ACTIVE_INTERFACE")?;
    let target = std::env::var("L2_TEST_ACTIVE_TARGET")?;
    let helper = SilentHelper::new()?;
    let binary = std::env::var_os("L2_TEST_ACTIVE_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_l2solver-active").into());
    for (timeout, closed) in [("250", false), ("7000", false), ("250", true)] {
        let mut command = Command::new(&binary);
        if std::env::var_os("L2_TEST_ACTIVE_MAIN").is_some() {
            command.arg("active");
        }
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
