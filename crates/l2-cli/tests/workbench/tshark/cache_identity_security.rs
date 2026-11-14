use super::identity_for_path;
use l2_workbench::job::Job;
use serde_json::Value;
use std::{
    error::Error,
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
};

fn script(path: &Path, body: &str) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(path, Permissions::from_mode(0o755))?;
    Ok(())
}

fn identity(directory: &Path, job: Option<&Job>) -> Value {
    identity_for_path(Some(directory.as_os_str()), job)
}

#[test]
fn unqualified_versions() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("tshark");
    for version in ["4.4.18", "4.6.8", "4.7.4", "4.6.9-rc1"] {
        script(&executable, &format!("printf 'TShark {version}\\n'"))?;
        let result = identity(directory.path(), None);
        assert_eq!(
            result.pointer("/version/status"),
            Some(&Value::from("unavailable")),
            "version {version}: {result}"
        );
        assert_eq!(
            result.pointer("/version/reason"),
            Some(&Value::from("unsupported_version")),
            "version {version}: {result}"
        );
    }
    Ok(())
}

#[test]
fn unsafe_executable_gate() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("tshark");
    let marker = directory.path().join("ran");
    script(
        &executable,
        &format!(
            "printf ran > '{}'; printf 'TShark 4.4.20\\n'",
            marker.display()
        ),
    )?;
    fs::set_permissions(&executable, Permissions::from_mode(0o777))?;
    let result = identity(directory.path(), None);
    assert_eq!(
        result.pointer("/version/status"),
        Some(&Value::from("unavailable")),
        "{result}"
    );
    assert!(!marker.exists(), "unsafe executable was launched");
    Ok(())
}

#[test]
fn unsafe_parent_gate() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let parent = directory.path().join("unsafe");
    fs::create_dir(&parent)?;
    let executable = parent.join("tshark");
    let marker = directory.path().join("ran");
    script(
        &executable,
        &format!(
            "printf ran > '{}'; printf 'TShark 4.4.20\\n'",
            marker.display()
        ),
    )?;
    fs::set_permissions(&parent, Permissions::from_mode(0o777))?;
    let result = identity(&parent, None);
    assert_eq!(
        result.pointer("/version/status"),
        Some(&Value::from("unavailable")),
        "{result}"
    );
    assert!(
        !marker.exists(),
        "executable from unsafe parent was launched"
    );
    Ok(())
}

#[test]
fn probe_filesystem_isolation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let private_file = directory.path().join("private");
    fs::write(&private_file, b"private")?;
    let executable = directory.path().join("tshark");
    script(
        &executable,
        &format!(
            "if [ -r '{}' ]; then printf 'TShark 4.4.20 host-visible\\n'; else printf 'TShark 4.4.20\\n'; fi",
            private_file.display()
        ),
    )?;
    let result = identity(directory.path(), None);
    assert_eq!(
        result.pointer("/version/status"),
        Some(&Value::from("available")),
        "{result}"
    );
    assert_eq!(
        result.pointer("/version/public_version"),
        Some(&Value::from("TShark 4.4.20")),
        "{result}"
    );
    Ok(())
}

#[test]
fn cancelled_probe() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("tshark");
    let marker = directory.path().join("ran");
    script(
        &executable,
        &format!(
            "printf ran > '{}'; printf 'TShark 4.4.20\\n'",
            marker.display()
        ),
    )?;
    let job = Job::new("cancelled version probe");
    job.request_cancel();
    let result = identity(directory.path(), Some(&job));
    assert_eq!(
        result.pointer("/version/status"),
        Some(&Value::from("cancelled")),
        "{result}"
    );
    assert!(!marker.exists(), "cancelled probe was launched");
    Ok(())
}

#[test]
fn privileged_probe_gate() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "L2_CACHE_IDENTITY_PRIVILEGED_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = Path::new(&directory);
        let status = fs::read_to_string("/proc/self/status")?;
        let capabilities = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .ok_or("effective capabilities missing")?;
        assert_ne!(u64::from_str_radix(capabilities.trim(), 16)?, 0);
        let result = identity(directory, None);
        assert_eq!(
            result.pointer("/version/status"),
            Some(&Value::from("unavailable")),
            "{result}"
        );
        assert_eq!(
            result.pointer("/version/reason"),
            Some(&Value::from("privileged_context")),
            "{result}"
        );
        assert!(
            !directory.join("ran").exists(),
            "privileged probe was launched"
        );
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let executable = directory.path().join("tshark");
    let marker = directory.path().join("ran");
    script(
        &executable,
        &format!(
            "printf ran > '{}'; printf 'TShark 4.4.20\\n'",
            marker.display()
        ),
    )?;
    let module = module_path!()
        .split_once("::")
        .ok_or("test module path missing")?
        .1;
    let test_name = format!("{module}::privileged_probe_gate");
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe()?)
        .args(["--exact", &test_name, "--nocapture"])
        .env(CHILD, directory.path())
        .output()?;
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "privileged child test did not run"
    );
    assert!(!marker.exists(), "privileged probe was launched");
    Ok(())
}
