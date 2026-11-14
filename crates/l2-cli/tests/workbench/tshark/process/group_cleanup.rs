use super::super::{
    ProcessError, process_group_has_live_members, validate_proc_mount, wait_for_group_stop,
};
use l2_workbench::job::Job;
use std::{
    error::Error,
    fs, io,
    path::Path,
    time::{Duration, Instant},
};

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
