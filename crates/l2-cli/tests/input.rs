#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use std::{
    error::Error,
    io::Write,
    process::{Command, Stdio},
};

fn directory(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("l2solver-{name}-{}", std::process::id()))
}

#[test]
fn open_error_names_path() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing capture.pcap");
    let workbench_output = directory.path().join("bundle");

    for arguments in [
        vec!["inspect".into(), missing.as_os_str().to_owned()],
        vec!["assess".into(), missing.as_os_str().to_owned()],
        vec![
            "workbench".into(),
            "stream".into(),
            missing.as_os_str().to_owned(),
            "--directory".into(),
            workbench_output.as_os_str().to_owned(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr)?;
        let path = missing.display().to_string();
        assert!(stderr.contains(&path));
        assert_eq!(stderr.matches(&path).count(), 1, "{stderr}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn read_error_names_path() -> Result<(), Box<dyn Error>> {
    let path = std::path::Path::new("/proc/self/mem");
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("inspect")
        .arg(path)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("failed to read"), "{stderr}");
    assert!(stderr.contains("/proc/self/mem"), "{stderr}");
    Ok(())
}

#[test]
fn offline_operands_reject_directories() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let root = directory("non-regular-input");
    std::fs::create_dir(&root)?;

    for command in ["inspect", "json", "observe"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg(command)
            .arg(&root)
            .output()?;
        assert_eq!(output.status.code(), Some(1), "{command}");
        assert!(String::from_utf8(output.stderr)?.contains("regular file"));
    }
    for format in ["text", "json", "html"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("survey")
            .arg(&root)
            .args(["--format", format])
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8(output.stderr)?.contains("regular file"));
    }

    let baseline_create = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "create"])
        .arg(&root)
        .arg(root.join("created.json"))
        .output()?;
    assert_eq!(baseline_create.status.code(), Some(1));
    assert!(String::from_utf8(baseline_create.stderr)?.contains("regular file"));

    let baseline_compare = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["baseline", "compare"])
        .arg(&root)
        .arg(&root)
        .output()?;
    assert_eq!(baseline_compare.status.code(), Some(1));
    assert!(String::from_utf8(baseline_compare.stderr)?.contains("regular file"));

    let policy = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("survey")
        .arg(fixtures.path("lldp.pcap"))
        .arg("--policy")
        .arg(&root)
        .output()?;
    assert_eq!(policy.status.code(), Some(1));
    assert!(String::from_utf8(policy.stderr)?.contains("regular file"));

    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn run_with_stdin(
    arguments: &[&str],
    bytes: &[u8],
) -> Result<std::process::Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin pipe unavailable")?
        .write_all(bytes)?;
    Ok(child.wait_with_output()?)
}

#[test]
fn capture_dash_reads_bounded_stdin() -> Result<(), Box<dyn Error>> {
    let capture = crate::captures::LLDP;
    for arguments in [["inspect", "-"], ["json", "-"], ["observe", "-"]] {
        let output = run_with_stdin(&arguments, capture)?;
        assert!(output.status.success(), "stdin mode failed: {arguments:?}");
        assert_ne!(output.stdout.len(), 0);
    }

    let survey = run_with_stdin(&["survey", "-", "--format", "json"], capture)?;
    assert!(survey.status.success());
    let report: serde_json::Value = serde_json::from_slice(&survey.stdout)?;
    assert_eq!(report.get("schema_version"), Some(&serde_json::json!(8)));
    assert_eq!(
        report.get("assessment_profile"),
        Some(&serde_json::json!("opportunistic"))
    );

    for command in ["assess", "survey"] {
        let named = run_with_stdin(&[command, "-"], capture)?;
        assert!(named.status.success(), "named stdin mode failed: {command}");
        assert_ne!(named.stdout.len(), 0);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn named_pipes_reject_without_waiting() -> Result<(), Box<dyn Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let root = directory("named-pipe-input");
    std::fs::create_dir(&root)?;
    let pipe = root.join("pipe");
    assert!(Command::new("mkfifo").arg(&pipe).status()?.success());
    let capture = fixtures.path("lldp.pcap");

    for arguments in [
        vec!["inspect".into(), pipe.as_os_str().to_owned()],
        vec!["json".into(), pipe.as_os_str().to_owned()],
        vec!["observe".into(), pipe.as_os_str().to_owned()],
        vec!["survey".into(), pipe.as_os_str().to_owned()],
        vec![
            "survey".into(),
            capture.as_os_str().to_owned(),
            "--policy".into(),
            pipe.as_os_str().to_owned(),
        ],
        vec![
            "baseline".into(),
            "compare".into(),
            pipe.as_os_str().to_owned(),
            capture.as_os_str().to_owned(),
        ],
    ] {
        // The outer timeout makes a regression fail in bounded test time
        let output = Command::new("timeout")
            .arg("2s")
            .arg(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8(output.stderr)?.contains("regular file"));
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}
