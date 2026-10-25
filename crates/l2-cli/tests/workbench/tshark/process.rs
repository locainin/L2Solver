use super::{ProcessError, StreamingMonitor, StreamingPolicy, run_streaming};
use crate::workbench::tshark::ObjectExportBudget;
use l2_workbench::job::Job;
#[cfg(target_os = "linux")]
use std::fs;
use std::{
    error::Error,
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

fn empty_object_root(directory: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir(directory)?;
    Ok(())
}

fn policy(
    deadline: Instant,
    object_root: &Path,
    protocol_directory_count: u64,
    object_budget: ObjectExportBudget,
) -> StreamingPolicy<'_> {
    StreamingPolicy {
        stderr_maximum: 64,
        deadline,
        object_root,
        protocol_directory_count,
        object_budget,
        job: None,
    }
}

#[test]
fn keeps_bounded_diagnostic_tail() -> Result<(), Box<dyn Error>> {
    let script = "printf '%0100000d' 0; printf '%0100000d' 0 >&2; printf ' final-error' >&2";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let output = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        policy(deadline, &object_root, 0, ObjectExportBudget::default()),
    )?;

    assert!(output.status.success());
    assert_eq!(output.stderr.len(), 64);
    assert!(output.stderr_truncated);
    assert!(output.stderr.ends_with(b"final-error"));
    Ok(())
}

#[test]
fn streaming_failure_keeps_tshark_diagnostic() -> Result<(), Box<dyn Error>> {
    let arguments = [
        OsString::from("-c"),
        OsString::from("printf 'export denied' >&2; exit 7"),
    ];
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let output = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        policy(deadline, &object_root, 0, ObjectExportBudget::default()),
    )?;

    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stderr, b"export denied");
    assert!(!output.stderr_truncated);
    Ok(())
}

#[test]
fn streaming_deadline_stops_process_group() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("descendant.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let script = "(/bin/sh -c 'printf %s \"$$\" > \"$PID_FILE\"; while :; do :; done') & exit 0";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [(OsString::from("PID_FILE"), pid_path.as_os_str().to_owned())];
    let deadline = Instant::now() + Duration::from_millis(250);

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(deadline, &object_root, 0, ObjectExportBudget::default()),
    )
    .err()
    .ok_or("a descendant keeping stderr open must time out")?;

    assert!(matches!(error, ProcessError::ObjectExportTimeout(_)));
    #[cfg(target_os = "linux")]
    {
        let pid = fs::read_to_string(pid_path)?.parse::<u32>()?;
        assert!(!process_is_running(pid)?);
    }
    Ok(())
}

#[test]
fn streaming_cancellation_stops_process_before_deadline() -> Result<(), Box<dyn Error>> {
    let job = Job::new("test TShark cancellation");
    let cancellation_job = job.clone();
    let cancellation = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(75));
        cancellation_job.request_cancel();
    });
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let arguments = [OsString::from("-c"), OsString::from("exec sleep 30")];
    let mut streaming_policy = policy(
        Instant::now() + Duration::from_secs(5),
        &object_root,
        0,
        ObjectExportBudget::default(),
    );
    streaming_policy.job = Some(&job);
    let started = Instant::now();

    let error = run_streaming(Path::new("/bin/sh"), &arguments, &[], streaming_policy)
        .err()
        .ok_or("cancelled TShark work should stop with a cancellation error")?;
    cancellation
        .join()
        .map_err(|_| "cancellation worker panicked")?;

    assert!(matches!(error, ProcessError::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn streaming_timeout_cleanup_is_bounded_for_detached_stderr_holder() -> Result<(), Box<dyn Error>> {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::sync::mpsc;

    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("detached.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let script = "setsid /bin/sh -c 'printf %s \"$$\" > \"$PID_FILE\"; exec sleep 30' & exit 0";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [(OsString::from("PID_FILE"), pid_path.as_os_str().to_owned())];
    let deadline = Instant::now() + Duration::from_millis(150);
    let started = Instant::now();
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = run_streaming(
            Path::new("/bin/sh"),
            &arguments,
            &environment,
            policy(deadline, &object_root, 0, ObjectExportBudget::default()),
        );
        let _ = sender.send(result);
    });
    let early_result = receiver.recv_timeout(Duration::from_millis(500));
    let returned_within_bound = early_result.is_ok();

    if !returned_within_bound {
        let pid_text = fs::read_to_string(&pid_path)?;
        let pid = pid_text.parse::<i32>()?;
        kill(Pid::from_raw(pid), Signal::SIGKILL)?;
    }
    let result = match early_result {
        Ok(result) => result,
        Err(_) => receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "streaming test worker did not stop after detached child cleanup")?,
    };
    if returned_within_bound {
        let pid_text = fs::read_to_string(&pid_path)?;
        let pid = pid_text.parse::<i32>()?;
        kill(Pid::from_raw(pid), Signal::SIGKILL)?;
    }
    worker
        .join()
        .map_err(|_| "streaming test worker panicked")?;

    assert!(
        returned_within_bound,
        "streaming timeout cleanup waited for detached stderr EOF"
    );
    assert!(matches!(result, Err(ProcessError::ObjectExportTimeout(_))));
    assert!(started.elapsed() < Duration::from_millis(500));
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: u32) -> std::io::Result<bool> {
    let status_path = format!("/proc/{pid}/status");
    let status = match fs::read_to_string(status_path) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let state = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("State:")
                .and_then(|rest| rest.split_whitespace().next())
        })
        .ok_or_else(|| std::io::Error::other("process state is unavailable"))?;
    Ok(state != "Z" && state != "X")
}

#[test]
fn streaming_completes_before_deadline() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let protocol_root = object_root.join("http");
    empty_object_root(&protocol_root)?;
    let object_path = protocol_root.join("payload.bin");
    let environment = [(
        OsString::from("OBJECT_FILE"),
        object_path.as_os_str().to_owned(),
    )];
    let arguments = [
        OsString::from("-c"),
        OsString::from("printf x > \"$OBJECT_FILE\"; printf 'export complete' >&2"),
    ];
    let deadline = Instant::now() + Duration::from_secs(2);

    let output = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            deadline,
            &object_root,
            1,
            ObjectExportBudget {
                temporary_bytes: 1,
                temporary_files: 1,
            },
        ),
    )?;

    assert!(output.status.success());
    assert_eq!(output.stderr, b"export complete");
    assert!(!output.stderr_truncated);
    assert_eq!(output.object_usage.temporary_bytes_peak, 1);
    assert_eq!(output.object_usage.temporary_files_peak, 1);
    assert_eq!(output.object_usage.temporary_tree_entries_peak, 2);
    assert_eq!(output.object_usage.protocol_directory_count, 1);
    assert!(output.object_usage.temporary_scan_complete);
    Ok(())
}

#[test]
fn nonzero_exit_preserves_diagnostic_and_observed_object_usage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let protocol_root = object_root.join("http");
    empty_object_root(&protocol_root)?;
    let stable_path = protocol_root.join("stable.bin");
    let late_path = protocol_root.join("late.bin");
    let script = "printf stable > \"$STABLE_FILE\"; printf late > \"$LATE_FILE\"; printf 'nonzero diagnostic' >&2; exit 7";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (
            OsString::from("STABLE_FILE"),
            stable_path.as_os_str().to_owned(),
        ),
        (
            OsString::from("LATE_FILE"),
            late_path.as_os_str().to_owned(),
        ),
    ];
    let budget = ObjectExportBudget {
        temporary_bytes: 64,
        temporary_files: 2,
    };

    let output = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            Instant::now() + Duration::from_secs(2),
            &object_root,
            1,
            budget,
        ),
    )?;

    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stderr, b"nonzero diagnostic");
    assert_eq!(output.object_usage.temporary_bytes_peak, 10);
    assert_eq!(output.object_usage.temporary_files_peak, 2);
    assert!(output.object_usage.temporary_scan_complete);
    Ok(())
}

#[test]
fn new_and_changed_objects_wait_for_a_second_unchanged_scan() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    let protocol_root = object_root.join("http");
    std::fs::create_dir_all(&protocol_root)?;
    let stable_path = protocol_root.join("stable.bin");
    let late_path = protocol_root.join("late.bin");
    let scan_policy = policy(
        Instant::now() + Duration::from_secs(2),
        &object_root,
        1,
        ObjectExportBudget {
            temporary_bytes: 64,
            temporary_files: 2,
        },
    );
    let mut monitor = StreamingMonitor::new(scan_policy, std::sync::Arc::default());

    // Explicit scan boundaries avoid relying on process scheduling between writes
    std::fs::write(&stable_path, b"stable")?;
    monitor.scan_objects(scan_policy)?;
    assert!(monitor.stable_objects.is_empty());

    std::fs::write(&late_path, b"late")?;
    monitor.scan_objects(scan_policy)?;
    assert_eq!(monitor.stable_objects.len(), 1);
    assert_eq!(
        monitor
            .stable_objects
            .first()
            .ok_or("stable object is missing")?
            .relative_path,
        Path::new("http/stable.bin")
    );

    // A different length invalidates the prior snapshot even on coarse filesystems
    std::fs::write(&stable_path, b"changed stable")?;
    monitor.scan_objects(scan_policy)?;
    assert_eq!(monitor.stable_objects.len(), 1);
    assert_eq!(
        monitor
            .stable_objects
            .first()
            .ok_or("late object is missing")?
            .relative_path,
        Path::new("http/late.bin")
    );

    monitor.scan_objects(scan_policy)?;
    assert_eq!(monitor.stable_objects.len(), 2);
    Ok(())
}

#[test]
fn streaming_timeout_keeps_verified_objects_and_observed_usage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let protocol_root = object_root.join("http");
    empty_object_root(&protocol_root)?;
    let stable_path = protocol_root.join("stable.bin");
    let script = "printf safe > \"$STABLE_FILE\"; printf 'timeout diagnostic' >&2; sleep 30";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [(
        OsString::from("STABLE_FILE"),
        stable_path.as_os_str().to_owned(),
    )];
    let budget = ObjectExportBudget {
        temporary_bytes: 64,
        temporary_files: 1,
    };

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            Instant::now() + Duration::from_millis(300),
            &object_root,
            1,
            budget,
        ),
    )
    .err()
    .ok_or("the running child must reach its deadline")?;
    let ProcessError::ObjectExportTimeout(timeout) = error else {
        return Err("a streaming deadline must preserve a partial export result".into());
    };

    assert_eq!(timeout.stderr, b"timeout diagnostic");
    assert!(timeout.stderr_complete);
    assert_eq!(
        timeout.describe(),
        "TShark object export exceeded its time budget: timeout diagnostic"
    );
    assert_eq!(timeout.status, None);
    assert_eq!(timeout.usage.temporary_bytes_peak, 4);
    assert_eq!(timeout.usage.temporary_files_peak, 1);
    assert_eq!(timeout.usage.protocol_directory_count, 1);
    assert!(timeout.usage.temporary_scan_complete);
    assert_eq!(timeout.stable_objects.len(), 1);
    assert_eq!(
        timeout
            .stable_objects
            .first()
            .ok_or("stable object snapshot is missing")?
            .relative_path,
        Path::new("http/stable.bin")
    );
    Ok(())
}

#[test]
fn streaming_output_budget_stops_process_group() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("descendant.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let object_path = object_root.join("payload.bin");
    let script = "(/bin/sh -c 'printf %s \"$$\" > \"$PID_FILE\"; chunk=$(printf %4096s \"\"); while :; do printf %s \"$chunk\" >> \"$OBJECT_FILE\"; done') & exit 0";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (OsString::from("PID_FILE"), pid_path.as_os_str().to_owned()),
        (
            OsString::from("OBJECT_FILE"),
            object_path.as_os_str().to_owned(),
        ),
    ];
    let budget = ObjectExportBudget {
        temporary_bytes: 16 * 1024,
        temporary_files: 1,
    };
    let deadline = Instant::now() + Duration::from_secs(2);

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(deadline, &object_root, 0, budget),
    )
    .err()
    .ok_or("a growing TShark output object must exceed its budget")?;

    let ProcessError::ObjectExportLimit(limit) = error else {
        return Err("temporary object overflow must return its typed limit error".into());
    };
    assert_eq!(limit.resource, super::ObjectExportResource::Bytes);
    assert_eq!(limit.maximum, budget.temporary_bytes);
    assert!(limit.observed > limit.maximum);
    #[cfg(target_os = "linux")]
    {
        let pid = fs::read_to_string(pid_path)?.parse::<u32>()?;
        assert!(!process_is_running(pid)?);
    }
    Ok(())
}

#[test]
fn partial_limit_retains_only_files_stable_across_complete_scans() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let protocol_root = object_root.join("http");
    empty_object_root(&protocol_root)?;
    let complete_path = protocol_root.join("complete.bin");
    let changing_path = protocol_root.join("changing.bin");
    let script = "printf safe > \"$COMPLETE_FILE\"; sleep 0.25; printf 12345678 > \"$CHANGING_FILE\"; while :; do printf 12345678 >> \"$CHANGING_FILE\"; done";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (
            OsString::from("COMPLETE_FILE"),
            complete_path.as_os_str().to_owned(),
        ),
        (
            OsString::from("CHANGING_FILE"),
            changing_path.as_os_str().to_owned(),
        ),
    ];
    let budget = ObjectExportBudget {
        temporary_bytes: 8,
        temporary_files: 2,
    };

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            Instant::now() + Duration::from_secs(2),
            &object_root,
            1,
            budget,
        ),
    )
    .err()
    .ok_or("the changing object must exceed the temporary byte budget")?;
    let ProcessError::ObjectExportLimit(limit) = error else {
        return Err("temporary byte overflow must return its typed limit error".into());
    };

    assert_eq!(limit.resource, super::ObjectExportResource::Bytes);
    assert_eq!(limit.maximum, budget.temporary_bytes);
    assert!(limit.observed > limit.maximum);
    assert!(!limit.usage.temporary_scan_complete);
    assert_eq!(limit.stable_objects.len(), 1);
    assert_eq!(
        limit
            .stable_objects
            .first()
            .ok_or("stable object snapshot is missing")?
            .relative_path,
        Path::new("http/complete.bin")
    );
    assert!(
        !limit
            .stable_objects
            .iter()
            .any(|object| { object.relative_path == Path::new("http/changing.bin") })
    );
    assert!(fs::metadata(changing_path)?.len() >= 8);
    Ok(())
}

#[test]
fn streaming_file_count_limit_stops_process_group() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("descendant.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let script = "(/bin/sh -c 'printf %s \"$$\" > \"$PID_FILE\"; count=0; while :; do : > \"$OBJECT_DIR/object-$count\"; count=$((count + 1)); done') & exit 0";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (OsString::from("PID_FILE"), pid_path.as_os_str().to_owned()),
        (
            OsString::from("OBJECT_DIR"),
            object_root.as_os_str().to_owned(),
        ),
    ];
    let budget = ObjectExportBudget {
        temporary_bytes: 1024 * 1024,
        temporary_files: 1,
    };
    let deadline = Instant::now() + Duration::from_secs(2);

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(deadline, &object_root, 0, budget),
    )
    .err()
    .ok_or("more than one temporary output file must exceed the budget")?;

    let ProcessError::ObjectExportLimit(limit) = error else {
        return Err("temporary file overflow must return its typed limit error".into());
    };
    assert_eq!(limit.resource, super::ObjectExportResource::Files);
    assert_eq!(limit.maximum, budget.temporary_files);
    assert_eq!(limit.observed, budget.temporary_files + 1);
    #[cfg(target_os = "linux")]
    {
        let pid = fs::read_to_string(pid_path)?.parse::<u32>()?;
        assert!(!process_is_running(pid)?);
    }
    Ok(())
}

#[test]
fn streaming_tree_entry_budget_stops_nested_directory_growth() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("descendant.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let script = "(/bin/sh -c 'printf %s \"$$\" > \"$PID_FILE\"; mkdir \"$OBJECT_DIR/one\"; mkdir \"$OBJECT_DIR/two\"; while :; do :; done') & exit 0";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (OsString::from("PID_FILE"), pid_path.as_os_str().to_owned()),
        (
            OsString::from("OBJECT_DIR"),
            object_root.as_os_str().to_owned(),
        ),
    ];
    let budget = ObjectExportBudget {
        temporary_bytes: 1024,
        temporary_files: 1,
    };
    let deadline = Instant::now() + Duration::from_secs(2);

    let error = run_streaming(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(deadline, &object_root, 0, budget),
    )
    .err()
    .ok_or("excess nested directories must exceed the derived tree-entry budget")?;

    let ProcessError::ObjectExportLimit(limit) = error else {
        return Err("tree-entry overflow must return its typed limit error".into());
    };
    assert_eq!(limit.resource, super::ObjectExportResource::TreeEntries);
    assert_eq!(limit.maximum, budget.temporary_files);
    assert_eq!(limit.observed, budget.temporary_files + 1);
    #[cfg(target_os = "linux")]
    {
        let pid = fs::read_to_string(pid_path)?.parse::<u32>()?;
        assert!(!process_is_running(pid)?);
    }
    Ok(())
}
