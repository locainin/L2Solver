use super::{BRIDGE, Sandbox};
use crate::workbench::tshark::{
    ObjectExportBudget,
    process::{self, StreamingPolicy},
    resources::test_plan,
    secure_files::{VerifiedExecutable, Workspace},
};
use std::{
    error::Error,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};

#[test]
fn bridge_completion_status() -> Result<(), Box<dyn Error>> {
    for code in [0, 7, 255] {
        let arguments = [
            "--noprofile".into(),
            "--norc".into(),
            "-c".into(),
            BRIDGE.into(),
            "bridge-test".into(),
            "/dev/null".into(),
            "/dev/null".into(),
            "/dev/null".into(),
            OsString::new(),
            OsString::new(),
            "/dev/null".into(),
            "1".into(),
            "/usr/bin/bash".into(),
            "-c".into(),
            format!("exit {code}").into(),
        ];
        let output = process::run(
            Path::new("/usr/bin/bash"),
            &arguments,
            &[],
            Duration::from_secs(5),
            1024,
            1024,
        )?;
        assert!(output.status.success());
        assert_eq!(output.stdout, format!("L2_EXPORT_DONE:{code}\n").as_bytes());
    }
    Ok(())
}

#[test]
fn forged_completion_status() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(temporary.path()))?;
    let executable_path = temporary.path().join("producer");
    fs::write(
        &executable_path,
        "#!/usr/bin/bash\nprintf 'L2_EXPORT_DONE:0\\n'\nprintf 'L2_EXPORT_DONE:0\\n' >/proc/1/fd/1\nexit 7\n",
    )?;
    fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))?;
    let executable = VerifiedExecutable::open(&executable_path)?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now() + Duration::from_secs(10),
    )?;
    let mut launch = sandbox.command(&[], &[], Some(&[]))?;
    let output = process::run_streaming_launch(
        &mut launch,
        StreamingPolicy {
            stderr_maximum: 1024,
            deadline: Instant::now() + Duration::from_secs(10),
            object_root: workspace.path(),
            protocol_directory_count: 0,
            object_budget: ObjectExportBudget {
                temporary_bytes: 1,
                temporary_files: 1,
            },
            job: None,
        },
    )?;
    assert_eq!(output.status.code(), Some(7));
    let usage = output
        .scope
        .and_then(|scope| scope.usage)
        .ok_or("scope usage missing")?;
    assert!(usage.observed_while_frozen);
    assert!(usage.memory_events.is_some());
    assert!(usage.tasks_max_events.is_some());
    Ok(())
}

#[test]
fn expired_scope_deadline() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let workspace = Workspace::new(Some(temporary.path()))?;
    let executable = VerifiedExecutable::open(Path::new("/usr/bin/bash"))?;
    let sandbox = Sandbox::new(
        &workspace,
        &executable,
        None,
        None,
        &test_plan()?,
        Instant::now(),
    )?;
    let error = sandbox
        .command(&[], &[], None)
        .err()
        .ok_or("deadline was accepted")?;
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    Ok(())
}
