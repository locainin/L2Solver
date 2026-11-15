use super::super::{
    ProcessError, process_group_has_live_members, validate_proc_mount, validate_proc_view,
    wait_for_group_stop,
};
use l2_workbench::job::Job;
use std::{
    error::Error,
    fs, io,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn group_stop_errors() {
    let deadline = std::time::Instant::now();
    for (cleanup, process_timeout) in [
        (deadline, false),
        (deadline + Duration::from_secs(1), true),
        (deadline + Duration::from_secs(2), true),
    ] {
        let result = super::super::group_stop_result(
            Err(ProcessError::TimedOut),
            cleanup,
            deadline + Duration::from_secs(1),
        );
        if process_timeout {
            assert!(matches!(result, Err(ProcessError::TimedOut)));
        } else {
            assert!(
                matches!(result, Err(ProcessError::Read(error)) if error.kind() == io::ErrorKind::TimedOut)
            );
        }
    }
    assert!(super::super::group_stop_result(Ok(()), deadline, deadline).is_ok());
    assert!(matches!(
        super::super::group_stop_result(Err(ProcessError::Cancelled), deadline, deadline),
        Err(ProcessError::Cancelled)
    ));
}

#[test]
fn process_stat_read_error() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir_all(directory.path().join("123/stat"))?;
    let result = super::super::process_group_has_live_members(
        directory.path(),
        123,
        Instant::now() + Duration::from_secs(5),
        None,
    );
    assert!(
        matches!(result, Err(ProcessError::Read(error)) if error.kind() == io::ErrorKind::IsADirectory),
        "a failed stat read was treated as an absent process"
    );
    Ok(())
}
fn write_stat(
    root: &Path,
    pid: u32,
    name: &str,
    state: char,
    group: u32,
    threads: u32,
) -> io::Result<()> {
    let directory = root.join(pid.to_string());
    fs::create_dir_all(&directory)?;
    fs::write(
        directory.join("stat"),
        format!("{pid} ({name}) {state} 1 {group} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {threads}\n"),
    )
}

#[test]
fn live_group_members() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    write_stat(root, 101, "leader", 'Z', 101, 1)?;
    write_stat(root, 102, "process (with) spaces", 'X', 101, 1)?;
    write_stat(root, 103, "other", 'R', 900, 1)?;
    fs::create_dir(root.join("104"))?;
    fs::write(root.join("not-a-pid"), b"ignored")?;
    let deadline = Instant::now() + Duration::from_secs(1);

    assert!(!process_group_has_live_members(root, 101, deadline, None)?);
    write_stat(root, 102, "process (with) spaces", 'S', 101, 1)?;
    assert!(process_group_has_live_members(root, 101, deadline, None)?);
    Ok(())
}

#[test]
fn invalid_group_metadata() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("101");
    fs::create_dir(&directory)?;
    fs::write(directory.join("stat"), b"malformed process metadata")?;

    let result = process_group_has_live_members(
        temporary.path(),
        101,
        Instant::now() + Duration::from_secs(1),
        None,
    );
    assert!(matches!(result, Err(ProcessError::Read(_))));
    Ok(())
}

#[test]
fn group_deadline_and_cancellation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    write_stat(temporary.path(), 101, "leader", 'R', 101, 1)?;
    let timed_out = process_group_has_live_members(temporary.path(), 101, Instant::now(), None);
    assert!(matches!(timed_out, Err(ProcessError::TimedOut)));

    let job = Job::new("cancel group scan");
    job.request_cancel();
    let cancelled = process_group_has_live_members(
        temporary.path(),
        101,
        Instant::now() + Duration::from_secs(1),
        Some(&job),
    );
    assert!(matches!(cancelled, Err(ProcessError::Cancelled)));
    Ok(())
}

#[test]
fn visible_proc_mount() {
    let visible = "1 0 0:3 / /proc rw,nosuid - proc proc rw\n";
    let hidden = "1 0 0:3 / /proc rw - proc proc rw,hidepid=invisible\n";
    let other_filesystem = "1 0 0:3 / /proc rw - tmpfs tmpfs rw\n";

    assert!(validate_proc_mount(visible).is_ok());
    assert!(validate_proc_mount(hidden).is_err());
    assert!(validate_proc_mount(other_filesystem).is_err());
    assert!(validate_proc_mount("").is_err());
}

#[test]
fn proc_view_pid_namespace_mismatch() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "L2_TEST_PROC_VIEW_NAMESPACE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // The inherited proc mount still shows the parent PID namespace
        let proc_pid = fs::read_link("/proc/self")?;
        let current_pid = std::process::id().to_string();
        assert_ne!(proc_pid, Path::new(&current_pid));
        let result = validate_proc_view();
        assert!(result.is_err(), "a mismatched proc view was accepted");
        let error = result.err().ok_or("proc view error missing")?;
        assert_eq!(error.to_string(), "procfs uses a different PID namespace");
        return Ok(());
    }

    let name = format!(
        "{}::proc_view_pid_namespace_mismatch",
        module_path!()
            .split_once("::")
            .ok_or("test module missing")?
            .1
    );
    // Keep the parent's proc mount while entering a new PID namespace
    let output = Command::new("unshare")
        .args(["--user", "--map-root-user", "--pid", "--fork"])
        .arg(std::env::current_exe()?)
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, "1")
        .output()?;
    assert!(
        output.status.success(),
        "namespace test failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "namespace child did not run the test"
    );
    Ok(())
}

#[test]
fn proc_view_current_pid_namespace() -> io::Result<()> {
    validate_proc_view()
}

#[test]
fn live_group_wait_deadline() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    write_stat(temporary.path(), 101, "stuck", 'D', 101, 1)?;
    let start = Instant::now();

    let result = wait_for_group_stop(
        temporary.path(),
        101,
        start + Duration::from_millis(40),
        None,
    );

    assert!(matches!(result, Err(ProcessError::TimedOut)));
    assert!(start.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn zombie_leader_live_threads() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    write_stat(temporary.path(), 101, "leader", 'Z', 101, 2)?;
    let deadline = Instant::now() + Duration::from_secs(1);

    assert!(process_group_has_live_members(
        temporary.path(),
        101,
        deadline,
        None,
    )?);
    write_stat(temporary.path(), 101, "leader", 'Z', 101, 1)?;
    assert!(!process_group_has_live_members(
        temporary.path(),
        101,
        deadline,
        None,
    )?);
    Ok(())
}
