use super::super::{
    CapturePolicy, DiagnosticState, OutputControl, ProcessError, ProcessGate, ResourceLimit,
    ScopeSession, StreamingMonitor, ThreadSpawner, WorkerSpawner, read_bootstrap_line,
    resource_limit, run_streaming_inner, run_with_gate_and_spawner, spawn_with_output,
    wait_for_streaming,
};
use super::{ObjectExportBudget, empty_object_root, policy};
use l2_workbench::{
    job::{CgroupMemoryEvents, Job},
    tshark::{ScopeReceipt, ScopeUsage},
};
use std::{
    error::Error,
    ffi::OsString,
    fs, io,
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

struct RejectGate {
    verifications: usize,
    stops: usize,
}

struct PendingGate;

impl ProcessGate for PendingGate {
    fn verify(&mut self, _child: u32) -> io::Result<bool> {
        Ok(false)
    }

    fn stop(&mut self, _deadline: Instant) -> io::Result<()> {
        Err(io::Error::other("unverified scope was stopped"))
    }

    fn verify_member(&self, _process: &fs::File) -> io::Result<()> {
        Err(io::Error::other("unverified scope was queried"))
    }

    fn request_freeze(&mut self) -> io::Result<()> {
        Err(io::Error::other("unverified freeze"))
    }
    fn poll_frozen(&mut self) -> io::Result<bool> {
        Err(io::Error::other("unverified freeze"))
    }
    fn verify_only_members(&mut self, _outer_pid: u32) -> io::Result<()> {
        Err(io::Error::other("unverified freeze"))
    }
}

struct FailingSpawner;

impl WorkerSpawner for FailingSpawner {
    fn spawn<F>(&mut self, _name: &'static str, _worker: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "worker failed"))
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum GateFault {
    #[default]
    None,
    Stop,
    StopOnce,
    Member,
    PendingFreeze,
    OtherMember,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum FreezeState {
    #[default]
    Idle,
    Requested,
    Frozen,
    Verified,
}

#[derive(Default)]
struct AcceptGate {
    child: Option<u32>,
    stops: usize,
    fault: GateFault,
    stop_delay: Duration,
    cancel_on_stop: Option<Job>,
    waitable_on_stop: Option<bool>,
    freeze: FreezeState,
    cancel_on_freeze: Option<Job>,
}

impl ProcessGate for AcceptGate {
    fn verify(&mut self, child: u32) -> io::Result<bool> {
        self.child = Some(child);
        Ok(true)
    }

    fn stop(&mut self, _deadline: Instant) -> io::Result<()> {
        self.stops += 1;
        if let Some(job) = &self.cancel_on_stop {
            job.request_cancel();
        }
        std::thread::sleep(self.stop_delay);
        self.waitable_on_stop = self
            .child
            .map(|child| Path::new(&format!("/proc/{child}")).exists());
        if self.fault == GateFault::Stop || (self.fault == GateFault::StopOnce && self.stops == 1) {
            Err(io::Error::other("scope kill failed"))
        } else {
            Ok(())
        }
    }

    fn verify_member(&self, _process: &std::fs::File) -> io::Result<()> {
        if self.fault == GateFault::Member {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong member",
            ))
        } else {
            Ok(())
        }
    }

    fn request_freeze(&mut self) -> io::Result<()> {
        self.freeze = FreezeState::Requested;
        Ok(())
    }

    fn poll_frozen(&mut self) -> io::Result<bool> {
        if let Some(job) = &self.cancel_on_freeze {
            job.request_cancel();
        }
        let frozen = self.freeze != FreezeState::Idle && self.fault != GateFault::PendingFreeze;
        if frozen {
            self.freeze = FreezeState::Frozen;
        }
        Ok(frozen)
    }

    fn verify_only_members(&mut self, outer_pid: u32) -> io::Result<()> {
        if self.freeze != FreezeState::Frozen
            || self.child != Some(outer_pid)
            || self.fault == GateFault::OtherMember
        {
            return Err(io::Error::other("unexpected scope member"));
        }
        self.freeze = FreezeState::Verified;
        Ok(())
    }
}

impl ProcessGate for RejectGate {
    fn verify(&mut self, _child: u32) -> io::Result<bool> {
        self.verifications += 1;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "wrong scope",
        ))
    }

    fn stop(&mut self, _deadline: Instant) -> io::Result<()> {
        self.stops += 1;
        Ok(())
    }

    fn verify_member(&self, _process: &std::fs::File) -> io::Result<()> {
        Ok(())
    }

    fn request_freeze(&mut self) -> io::Result<()> {
        Err(io::Error::other("unverified freeze"))
    }
    fn poll_frozen(&mut self) -> io::Result<bool> {
        Err(io::Error::other("unverified freeze"))
    }
    fn verify_only_members(&mut self, _outer_pid: u32) -> io::Result<()> {
        Err(io::Error::other("unverified freeze"))
    }
}

#[test]
fn scope_gate_rejection() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("released");
    let arguments = [
        OsString::from("-c"),
        OsString::from("IFS= read -r token || exit 0; : > \"$MARKER\""),
    ];
    let environment = [(OsString::from("MARKER"), marker.as_os_str().to_owned())];
    let mut gate = RejectGate {
        verifications: 0,
        stops: 0,
    };
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        CapturePolicy {
            timeout: Duration::from_secs(2),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut ThreadSpawner,
        &mut gate,
    );
    assert!(matches!(result, Err(ProcessError::Containment(_))));
    assert_eq!(gate.verifications, 1);
    assert_eq!(gate.stops, 0);
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn scope_verification_deadline() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("released");
    let arguments = [
        OsString::from("-c"),
        OsString::from("IFS= read -r token && : > \"$MARKER\""),
    ];
    let environment = [(OsString::from("MARKER"), marker.as_os_str().to_owned())];
    let started = Instant::now();
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        CapturePolicy {
            timeout: Duration::from_millis(50),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut ThreadSpawner,
        &mut PendingGate,
    );
    assert!(matches!(result, Err(ProcessError::TimedOut)));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn scope_cleanup_order() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("released");
    let arguments = [
        OsString::from("-c"),
        OsString::from("IFS= read -r token && printf %s \"$token\" > \"$MARKER\""),
    ];
    let environment = [(OsString::from("MARKER"), marker.as_os_str().to_owned())];
    let mut gate = AcceptGate::default();
    let output = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        CapturePolicy {
            timeout: Duration::from_secs(2),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut ThreadSpawner,
        &mut gate,
    )?;
    assert!(output.status.success());
    assert_eq!(fs::read_to_string(marker)?, "scope");
    assert_eq!(gate.stops, 1);
    assert_eq!(gate.waitable_on_stop, Some(true));
    Ok(())
}

#[test]
fn scope_cleanup_deadline() {
    let arguments = [OsString::from("-c"), OsString::from("IFS= read -r token")];
    let mut gate = AcceptGate {
        stop_delay: Duration::from_millis(350),
        ..AcceptGate::default()
    };
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        CapturePolicy {
            timeout: Duration::from_millis(200),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut ThreadSpawner,
        &mut gate,
    );
    assert_eq!(gate.stops, 1);
    assert!(matches!(result, Err(ProcessError::TimedOut)));
}

#[test]
fn scope_cleanup_cancellation() {
    let arguments = [OsString::from("-c"), OsString::from("IFS= read -r token")];
    let job = Job::new("scope cleanup cancellation");
    let mut gate = AcceptGate {
        cancel_on_stop: Some(job.clone()),
        ..AcceptGate::default()
    };
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        CapturePolicy {
            timeout: Duration::from_secs(2),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: Some(&job),
        },
        &mut ThreadSpawner,
        &mut gate,
    );
    assert_eq!(gate.stops, 1);
    assert!(matches!(result, Err(ProcessError::Cancelled)));
}

#[test]
fn object_scan_cancellation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("objects");
    empty_object_root(&root)?;
    fs::write(root.join("first"), b"one")?;
    fs::write(root.join("second"), b"two")?;
    let job = Job::new("object scan cancellation");
    let cancellation = job.clone();
    super::NEXT_SCANNED_ENTRY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || cancellation.request_cancel()));
    });
    let mut policy = policy(
        Instant::now() + Duration::from_secs(2),
        &root,
        0,
        ObjectExportBudget::default(),
    );
    policy.job = Some(&job);
    let diagnostics = Arc::new(Mutex::new(DiagnosticState::default()));
    let mut monitor = StreamingMonitor::new(policy, diagnostics);
    let result = monitor.scan_objects(policy);
    assert!(matches!(result, Err(ProcessError::Cancelled)));
    assert!(!monitor.usage.temporary_scan_complete);
    Ok(())
}

#[test]
fn cleanup_error_timeout() -> Result<(), Box<dyn Error>> {
    let arguments = [
        OsString::from("-c"),
        OsString::from("IFS= read -r token && exec sleep 30"),
    ];
    let mut gate = AcceptGate {
        fault: GateFault::Stop,
        ..AcceptGate::default()
    };
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        CapturePolicy {
            timeout: Duration::from_millis(150),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut ThreadSpawner,
        &mut gate,
    );
    assert!(matches!(
        result,
        Err(ProcessError::ScopeCleanup {
            primary: Some(primary), source
        }) if matches!(*primary, ProcessError::TimedOut) && source.to_string() == "scope kill failed"
    ));
    assert_eq!(gate.stops, 1);
    assert_eq!(gate.waitable_on_stop, Some(true));
    assert!(!Path::new(&format!("/proc/{}", gate.child.ok_or("missing child")?)).exists());
    Ok(())
}

#[test]
fn worker_start_cleanup() -> Result<(), Box<dyn Error>> {
    let arguments = [
        OsString::from("-c"),
        OsString::from("IFS= read -r token && exec sleep 30"),
    ];
    let mut gate = AcceptGate::default();
    let result = run_with_gate_and_spawner(
        Path::new("/bin/sh"),
        &arguments,
        &[],
        CapturePolicy {
            timeout: Duration::from_secs(2),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut FailingSpawner,
        &mut gate,
    );
    assert!(matches!(result, Err(ProcessError::WorkerSpawn { .. })));
    assert_eq!(gate.stops, 1);
    assert_eq!(gate.waitable_on_stop, Some(true));
    assert!(!Path::new(&format!("/proc/{}", gate.child.ok_or("missing child")?)).exists());
    Ok(())
}

#[test]
fn streaming_cleanup_retry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("objects");
    empty_object_root(&root)?;
    let arguments = [OsString::from("-c"), OsString::from("IFS= read -r token")];
    for (fault, retry_fails) in [(GateFault::StopOnce, false), (GateFault::Stop, true)] {
        let mut gate = AcceptGate {
            fault,
            ..AcceptGate::default()
        };
        let result = run_streaming_inner(
            Path::new("/bin/sh"),
            &arguments,
            &[],
            policy(
                Instant::now() + Duration::from_secs(2),
                &root,
                0,
                ObjectExportBudget::default(),
            ),
            &mut ThreadSpawner,
            Some(&mut gate),
            None,
        );
        assert_eq!(gate.stops, 2, "streaming cleanup must retry a failed stop");
        let Err(ProcessError::ScopeCleanup { primary, source }) = result else {
            return Err("failed cleanup did not produce a cleanup error".into());
        };
        assert_eq!(source.to_string(), "scope kill failed");
        if retry_fails {
            assert!(matches!(
                primary.as_deref(),
                Some(ProcessError::ScopeCleanup { primary: None, source })
                    if source.to_string() == "scope kill failed"
            ));
        } else {
            assert!(primary.is_none(), "successful retry must add no error");
        }
        assert!(!Path::new(&format!("/proc/{}", gate.child.ok_or("missing child")?)).exists());
    }
    Ok(())
}

#[test]
fn storage_gate_rejection() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("objects");
    empty_object_root(&root)?;
    let marker = directory.path().join("released");
    let arguments = [
        OsString::from("-c"),
        OsString::from(
            "IFS= read -r token || exit; printf '{\"child-pid\":4294967295,\"mnt-namespace\":1}\\nL2_EXPORT_READY\\n'; IFS= read -r token && : > \"$MARKER\"",
        ),
    ];
    let environment = [(OsString::from("MARKER"), marker.as_os_str().to_owned())];
    let mut gate = AcceptGate::default();
    let mut storage = None;
    let result = run_streaming_inner(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            Instant::now() + Duration::from_secs(2),
            &root,
            0,
            ObjectExportBudget::default(),
        ),
        &mut ThreadSpawner,
        Some(&mut gate),
        Some(&mut storage),
    );
    assert!(matches!(result, Err(ProcessError::Containment(_))));
    assert!(storage.is_none());
    assert_eq!(gate.stops, 1);
    assert_eq!(gate.waitable_on_stop, Some(true));
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn scope_member_rejection() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("objects");
    empty_object_root(&root)?;
    let marker = directory.path().join("released");
    let arguments = [
        OsString::from("-c"),
        OsString::from(
            "IFS= read -r token || exit; printf '{\"child-pid\":%s,\"mnt-namespace\":%s}\\nL2_EXPORT_READY\\n' \"$BOOT_PID\" \"$BOOT_NS\"; IFS= read -r token && : > \"$MARKER\"",
        ),
    ];
    let environment = [
        (OsString::from("MARKER"), marker.as_os_str().to_owned()),
        (
            OsString::from("BOOT_PID"),
            std::process::id().to_string().into(),
        ),
        (
            OsString::from("BOOT_NS"),
            fs::metadata("/proc/self/ns/mnt")?.ino().to_string().into(),
        ),
    ];
    let mut gate = AcceptGate {
        fault: GateFault::Member,
        ..AcceptGate::default()
    };
    let mut storage = None;
    let result = run_streaming_inner(
        Path::new("/bin/sh"),
        &arguments,
        &environment,
        policy(
            Instant::now() + Duration::from_secs(2),
            &root,
            0,
            ObjectExportBudget::default(),
        ),
        &mut ThreadSpawner,
        Some(&mut gate),
        Some(&mut storage),
    );
    assert!(
        matches!(result, Err(ProcessError::Containment(error)) if error.to_string() == "wrong member")
    );
    assert!(storage.is_none());
    assert_eq!(gate.stops, 1);
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn bootstrap_line_bounds() {
    let mut oversized = io::Cursor::new(vec![b'x'; 4096]);
    let result = read_bootstrap_line(
        &mut oversized,
        Instant::now() + Duration::from_secs(1),
        None,
    );
    assert!(
        matches!(result, Err(ProcessError::Containment(error)) if error.kind() == io::ErrorKind::InvalidData)
    );
    let mut incomplete = io::Cursor::new(b"ready".to_vec());
    let result = read_bootstrap_line(
        &mut incomplete,
        Instant::now() + Duration::from_secs(1),
        None,
    );
    assert!(
        matches!(result, Err(ProcessError::Containment(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn completion_status() -> Result<(), Box<dyn Error>> {
    let mut control = OutputControl::new(io::Cursor::new(
        b"{\"exit-code\":7}\nL2_EXPORT_DONE:7\n".as_slice(),
    ));
    assert_eq!(
        control.poll(Instant::now() + Duration::from_secs(1), None)?,
        Some(7)
    );
    Ok(())
}

#[test]
fn completion_status_mismatch() {
    let mut control = OutputControl::new(io::Cursor::new(
        b"{\"exit-code\":7}\nL2_EXPORT_DONE:0\n".as_slice(),
    ));
    assert!(matches!(
        control.poll(Instant::now() + Duration::from_secs(1), None),
        Err(ProcessError::Containment(_))
    ));
}

#[test]
fn completion_invalid_frames() {
    let oversized = vec![b'x'; 4097];
    for bytes in [
        b"L2_EXPORT_DONE:256\n".as_slice(),
        b"L2_EXPORT_DONE:00\n".as_slice(),
        b"{\"exit-code\":7}\n{\"exit-code\":7}\n".as_slice(),
        b"L2_EXPORT_DONE:".as_slice(),
        oversized.as_slice(),
    ] {
        let mut control = OutputControl::new(io::Cursor::new(bytes));
        assert!(matches!(
            control.poll(Instant::now() + Duration::from_secs(1), None),
            Err(ProcessError::Containment(_))
        ));
    }
}

#[test]
fn completion_cleanup_status() -> Result<(), Box<dyn Error>> {
    for (status, reject_only) in [(0_u8, false), (7, false), (255, false), (0, true)] {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("objects");
        empty_object_root(&root)?;
        let script = format!(
            "printf '{{\"exit-code\":{status}}}\\nL2_EXPORT_DONE:{status}\\n'; exec 1>&- 2>&-; IFS= read -r"
        );
        let mut child = spawn_with_output(
            Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from(script)],
            &[],
            Stdio::piped(),
            Stdio::null(),
            true,
        )?;
        let stdout = child.stdout.take().ok_or("control pipe missing")?;
        let flags = rustix::fs::fcntl_getfl(&stdout)?;
        rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK)?;
        let policy = policy(
            Instant::now() + Duration::from_secs(2),
            &root,
            0,
            ObjectExportBudget::default(),
        );
        let diagnostics = Arc::new(Mutex::new(DiagnosticState {
            complete: true,
            ..DiagnosticState::default()
        }));
        let mut monitor = StreamingMonitor::new(policy, diagnostics);
        let worker = std::thread::spawn(|| {});
        let mut gate = AcceptGate {
            child: Some(child.id()),
            fault: if reject_only {
                GateFault::OtherMember
            } else {
                GateFault::None
            },
            ..AcceptGate::default()
        };
        let result = {
            let mut scope = ScopeSession::new(Some(&mut gate));
            scope.verified = true;
            wait_for_streaming(
                &mut child,
                worker,
                &mut monitor,
                policy,
                &mut scope,
                Some(OutputControl::new(stdout)),
            )
        };
        if reject_only {
            assert!(matches!(result, Err(ProcessError::Containment(_))));
        } else {
            assert_eq!(result?.status.code(), Some(i32::from(status)));
        }
        assert_eq!(
            gate.freeze,
            if reject_only {
                FreezeState::Frozen
            } else {
                FreezeState::Verified
            }
        );
        assert_eq!(gate.stops, 1);
        assert!(!Path::new(&format!("/proc/{}", child.id())).exists());
    }
    Ok(())
}

#[test]
fn scope_freeze_budget() {
    let job = Job::new("freeze cancellation");
    let mut gate = AcceptGate {
        fault: GateFault::PendingFreeze,
        cancel_on_freeze: Some(job.clone()),
        ..AcceptGate::default()
    };
    let mut scope = ScopeSession::new(Some(&mut gate));
    scope.verified = true;
    assert!(matches!(
        scope.finish_output(1, Instant::now() + Duration::from_secs(2), Some(&job)),
        Err(ProcessError::Cancelled)
    ));

    let mut gate = AcceptGate {
        fault: GateFault::PendingFreeze,
        ..AcceptGate::default()
    };
    let mut scope = ScopeSession::new(Some(&mut gate));
    scope.verified = true;
    assert!(matches!(
        scope.finish_output(1, Instant::now() + Duration::from_millis(25), None),
        Err(ProcessError::TimedOut)
    ));
}

fn scope_receipt(usage: Option<ScopeUsage>) -> ScopeReceipt {
    ScopeReceipt {
        memory_max_bytes: 4096,
        memory_high_bytes: 2048,
        swap_max_bytes: 0,
        tasks_max: 4,
        effective_memory_max_bytes: 4096,
        effective_memory_high_bytes: 2048,
        effective_swap_max_bytes: 0,
        effective_tasks_max: 4,
        usage,
    }
}

#[test]
fn scope_pressure_events() {
    assert!(resource_limit(&scope_receipt(None)).is_none());
    let usage = ScopeUsage {
        memory_peak_bytes: None,
        tasks_peak: None,
        memory_events: Some(CgroupMemoryEvents {
            high: 1,
            max: 1,
            ..CgroupMemoryEvents::default()
        }),
        tasks_max_events: None,
        observed_after_stop: false,
        observed_while_frozen: false,
    };
    assert!(resource_limit(&scope_receipt(Some(usage))).is_none());
}

#[test]
fn scope_limit_events() {
    let mut usage = ScopeUsage {
        memory_peak_bytes: None,
        tasks_peak: None,
        memory_events: Some(CgroupMemoryEvents {
            oom: 1,
            ..CgroupMemoryEvents::default()
        }),
        tasks_max_events: Some(0),
        observed_after_stop: true,
        observed_while_frozen: false,
    };
    assert_eq!(
        resource_limit(&scope_receipt(Some(usage))),
        Some(ResourceLimit::Memory)
    );
    usage.memory_events = Some(CgroupMemoryEvents {
        oom_kill: 1,
        ..CgroupMemoryEvents::default()
    });
    assert_eq!(
        resource_limit(&scope_receipt(Some(usage))),
        Some(ResourceLimit::Memory)
    );
    usage.memory_events = None;
    usage.tasks_max_events = Some(1);
    assert_eq!(
        resource_limit(&scope_receipt(Some(usage))),
        Some(ResourceLimit::Tasks)
    );
}
