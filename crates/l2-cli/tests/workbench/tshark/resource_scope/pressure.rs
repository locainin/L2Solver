use super::{PARENT_SCOPE, TestResult, announce_parent_case, harness_name, run_parent_case};
use crate::workbench::tshark::{
    resource_scope::{Gate, ResourceScope, kernel::control_text},
    sandbox::Launch,
};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    num::NonZeroU64,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[path = "pressure/supervisor.rs"]
mod supervisor;

const HELPER_MODE: &str = "L2_SCOPE_PRESSURE_HELPER";
const HELPER_MARKER: &str = "L2_SCOPE_PRESSURE_MARKER";
const MEMORY_LIMIT: u64 = 64 * 1024 * 1024;
const TASK_LIMIT: u64 = 12;

/// Retain the launch descriptors until the private scope has been stopped
struct ScopeProbe {
    _launch: Launch,
    gate: Gate,
    child: Child,
}

impl ScopeProbe {
    fn start(mode: &str, marker: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_launch(helper_launch(mode, marker)?, Duration::from_secs(10))
    }

    fn start_launch(
        launch: Launch,
        remaining: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let memory = NonZeroU64::new(MEMORY_LIMIT).ok_or("zero memory")?;
        let tasks = NonZeroU64::new(TASK_LIMIT).ok_or("zero tasks")?;
        let resource = ResourceScope::new(memory, 0, tasks, remaining)?;
        let mut launch = resource.wrap(launch)?;
        let mut gate = launch.scope.take().ok_or("missing scope gate")?;
        gate.claim()?;
        let child = Command::new(&launch.executable)
            .args(&launch.arguments)
            .env_clear()
            .envs(launch.environment.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut probe = Self {
            _launch: launch,
            gate,
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !probe.gate.verify(probe.child.id())? {
            if probe.child.try_wait()?.is_some() {
                return Err("scope launcher exited before verification".into());
            }
            if Instant::now() >= deadline {
                return Err("scope verification timed out".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
        let receipt = probe.gate.receipt().ok_or("missing scope receipt")?;
        assert_eq!(receipt.memory_max_bytes, MEMORY_LIMIT);
        assert_eq!(receipt.swap_max_bytes, 0);
        assert_eq!(receipt.tasks_max, TASK_LIMIT);
        Ok(probe)
    }

    fn release(&mut self) -> io::Result<()> {
        self.input()?.write_all(b"scope\n")
    }

    fn input(&mut self) -> io::Result<&mut std::process::ChildStdin> {
        self.child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("scope input unavailable"))
    }

    fn wait(&mut self, deadline: Instant) -> Result<ExitStatus, Box<dyn std::error::Error>> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("scope helper timed out".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn wait_marker(&mut self, marker: &Path) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !marker.exists() {
            if let Some(status) = self.child.try_wait()? {
                let mut diagnostic = String::new();
                if let Some(stderr) = self.child.stderr.take() {
                    stderr.take(4096).read_to_string(&mut diagnostic)?;
                }
                return Err(format!(
                    "scope helper exited before its marker ({status}): {diagnostic}"
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err("scope helper marker timed out".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    fn set_high_to_max(&self) -> TestResult {
        let scope = self.gate.verified.as_ref().ok_or("scope not verified")?;
        let flags =
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
        let mut high = fs::File::from(rustix::fs::openat(
            &scope.directory,
            "memory.high",
            flags,
            rustix::fs::Mode::empty(),
        )?);
        // Preserve the hard cap while avoiding a long throttle before the OOM probe
        high.write_all(MEMORY_LIMIT.to_string().as_bytes())?;
        assert_eq!(
            control_text(&scope.directory, "memory.high")?
                .trim()
                .parse::<u64>()?,
            MEMORY_LIMIT
        );
        Ok(())
    }

    fn finish(&mut self) -> TestResult {
        self.gate
            .stop_verified_scope(Instant::now() + Duration::from_secs(2))?;
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for ScopeProbe {
    fn drop(&mut self) {
        let _ = self
            .gate
            .stop_verified_scope(Instant::now() + Duration::from_secs(2));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn helper_launch(mode: &str, marker: &Path) -> Result<Launch, Box<dyn std::error::Error>> {
    let helper = harness_name(module_path!(), "scope_fixture");
    Ok(Launch {
        executable: PathBuf::from("/usr/bin/bash"),
        arguments: vec![
            OsString::from("-c"),
            OsString::from("exec \"$@\""),
            OsString::from("scope-helper"),
            std::env::current_exe()?.into_os_string(),
            OsString::from("--exact"),
            OsString::from(helper),
            OsString::from("--nocapture"),
        ],
        environment: vec![
            (OsString::from(HELPER_MODE), OsString::from(mode)),
            (OsString::from(HELPER_MARKER), marker.as_os_str().to_owned()),
        ],
        handles: Vec::new(),
        scope: None,
        output_bootstrap: false,
        output_storage: None,
    })
}

fn in_unlimited_parent(test: &str) -> Result<bool, Box<dyn std::error::Error>> {
    in_unlimited_parent_at(module_path!(), test)
}

fn in_unlimited_parent_at(module: &str, test: &str) -> Result<bool, Box<dyn std::error::Error>> {
    if std::env::var_os("L2_SKIP_SYSTEMD_SCOPE_TESTS").is_some() {
        eprintln!("systemd scope integration explicitly skipped by L2_SKIP_SYSTEMD_SCOPE_TESTS");
        return Ok(false);
    }
    match std::env::var_os(PARENT_SCOPE) {
        None => {
            run_parent_case(&harness_name(module, test), "unlimited", "infinity")?;
            Ok(false)
        }
        Some(mode) if mode == "unlimited" => {
            announce_parent_case()?;
            Ok(true)
        }
        Some(_) => Err("pressure test requires an unlimited parent scope".into()),
    }
}

#[test]
fn scope_fixture() -> TestResult {
    let Some(mode) = std::env::var_os(HELPER_MODE) else {
        return Ok(());
    };
    let marker = PathBuf::from(std::env::var_os(HELPER_MARKER).ok_or("missing fixture marker")?);
    fixture_guard()?;
    match mode.to_str() {
        Some("oom") => fixture_oom(&marker),
        Some("tasks") => fixture_tasks(&marker),
        Some("detached") => fixture_detached(&marker),
        _ => Err("invalid scope fixture mode".into()),
    }
}

fn fixture_guard() -> TestResult {
    let groups = fs::read_to_string("/proc/self/cgroup")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let hierarchy = crate::recovery_job::system_memory::hierarchy(&groups, &mounts)?;
    let leaf = hierarchy.first().ok_or("fixture cgroup unavailable")?;
    let directory = super::super::kernel::open_cgroup(leaf)?;
    let memory = control_text(&directory, "memory.max")?
        .trim()
        .parse::<u64>()?;
    let swap = control_text(&directory, "memory.swap.max")?
        .trim()
        .parse::<u64>()?;
    let tasks = control_text(&directory, "pids.max")?
        .trim()
        .parse::<u64>()?;
    if memory > MEMORY_LIMIT || swap != 0 || tasks > TASK_LIMIT {
        return Err("fixture resource controls are too permissive".into());
    }
    if control_text(&directory, "memory.oom.group")?.trim() != "1" {
        return Err("fixture cgroup OOM policy is unavailable".into());
    }
    // The pressure helper must be the only process in its private scope
    let processes = control_text(&directory, "cgroup.procs")?;
    let mut processes = processes.lines();
    if processes.next().and_then(|line| line.parse::<u32>().ok()) != Some(std::process::id())
        || processes.next().is_some()
    {
        return Err("fixture scope contains an unexpected process".into());
    }
    Ok(())
}

fn fixture_oom(marker: &Path) -> TestResult {
    let mut blocks = Vec::new();
    // Touch at most twice the cgroup limit even if the kernel control fails
    for _ in 0..128 {
        blocks.push(vec![0xa5_u8; 1024 * 1024]);
        std::hint::black_box(&blocks);
    }
    fs::write(marker, b"survived")?;
    Ok(())
}

fn fixture_tasks(marker: &Path) -> TestResult {
    let released = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for _ in 0..64 {
        let worker_released = Arc::clone(&released);
        match thread::Builder::new().stack_size(64 * 1024).spawn(move || {
            while !worker_released.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(100));
            }
        }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                let pending = marker.with_extension("pending");
                fs::write(
                    &pending,
                    format!(
                        "{} {}",
                        workers.len(),
                        error.raw_os_error().unwrap_or_default()
                    ),
                )?;
                fs::rename(pending, marker)?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if input != "tasks-go\n" {
                    return Err("invalid task fixture release".into());
                }
                released.store(true, Ordering::Release);
                for worker in workers {
                    worker.thread().unpark();
                    worker.join().map_err(|_| "task worker panicked")?;
                }
                return Ok(());
            }
        }
    }
    Err("thread creation never reached the task limit".into())
}

fn fixture_detached(marker: &Path) -> TestResult {
    let escaped = marker.with_extension("escaped");
    let _detached = Command::new("/usr/bin/setsid")
        .args([
            "/usr/bin/bash",
            "-c",
            "printf '%s' \"$$\" > \"${1}.pending\"; mv -- \"${1}.pending\" \"$1\"; sleep 2; printf escaped > \"$2\"; exec sleep 8",
            "scope-detached",
        ])
        .arg(marker)
        .arg(escaped)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    thread::sleep(Duration::from_secs(8));
    Ok(())
}

#[test]
fn memory_oom() -> TestResult {
    if !in_unlimited_parent("memory_oom")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("oom");
    let mut probe = ScopeProbe::start("oom", &marker)?;
    probe.set_high_to_max()?;
    probe.release()?;
    let status = match probe.wait(Instant::now() + Duration::from_secs(6)) {
        Ok(status) => status,
        Err(error) => {
            let scope = probe.gate.verified.as_ref().ok_or("scope not verified")?;
            let current = control_text(&scope.directory, "memory.current")?;
            let events = control_text(&scope.directory, "memory.events")?;
            return Err(format!("{error}: memory.current={current:?}, events={events:?}").into());
        }
    };
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(
        !marker.exists(),
        "the bounded workload escaped the memory limit"
    );
    let events = probe
        .gate
        .verified
        .as_ref()
        .and_then(|scope| control_text(&scope.directory, "memory.events").ok());
    if let Some(events) = events {
        let oom = crate::recovery_job::system_memory::field(&events, "oom")?.unwrap_or_default();
        let killed =
            crate::recovery_job::system_memory::field(&events, "oom_kill")?.unwrap_or_default();
        assert!(oom > 0 || killed > 0, "SIGKILL lacked a cgroup OOM event");
    } else {
        eprintln!("scope was removed before final memory events could be read");
    }
    probe.finish()?;
    Ok(())
}

#[test]
fn task_exhaustion() -> TestResult {
    if !in_unlimited_parent("task_exhaustion")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("tasks");
    let mut probe = ScopeProbe::start("tasks", &marker)?;
    probe.release()?;
    probe.wait_marker(&marker)?;
    let observation = fs::read_to_string(&marker)?;
    let mut values = observation.split_whitespace();
    let created = values
        .next()
        .ok_or("missing thread count")?
        .parse::<u64>()?;
    let error = values
        .next()
        .ok_or("missing thread error")?
        .parse::<i32>()?;
    assert!(created > 0 && created < TASK_LIMIT);
    assert_eq!(error, libc::EAGAIN);
    let scope = probe.gate.verified.as_ref().ok_or("scope not verified")?;
    let events = control_text(&scope.directory, "pids.events")?;
    assert!(
        crate::recovery_job::system_memory::field(&events, "max")?.ok_or("missing max event")? > 0
    );
    probe.input()?.write_all(b"tasks-go\n")?;
    assert!(
        probe
            .wait(Instant::now() + Duration::from_secs(4))?
            .success()
    );
    probe.finish()?;
    Ok(())
}

#[test]
fn detached_cleanup() -> TestResult {
    if !in_unlimited_parent("detached_cleanup")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("detached");
    let mut probe = ScopeProbe::start("detached", &marker)?;
    probe.release()?;
    probe.wait_marker(&marker)?;
    let detached = fs::read_to_string(&marker)?.parse::<u32>()?;
    let (group, session) = process_group(detached)?;
    let (helper_group, _) = process_group(probe.child.id())?;
    assert_eq!(group, detached);
    assert_eq!(session, detached);
    assert_ne!(group, helper_group);
    let process = fs::File::open(format!("/proc/{detached}"))?;
    probe.gate.verify_member(&process)?;
    probe.gate.request_freeze()?;
    wait_frozen(&mut probe.gate)?;
    assert!(probe.gate.verify_only_members(probe.child.id()).is_err());
    probe.finish()?;
    thread::sleep(Duration::from_millis(2300));
    assert!(
        !marker.with_extension("escaped").exists(),
        "detached child survived cgroup cleanup"
    );
    Ok(())
}

#[test]
fn frozen_counters() -> TestResult {
    if !in_unlimited_parent("frozen_counters")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("frozen");
    let mut probe = ScopeProbe::start("tasks", &marker)?;
    assert!(probe.gate.verify_only_members(probe.child.id()).is_err());
    probe.gate.request_freeze()?;
    wait_frozen(&mut probe.gate)?;
    probe.gate.verify_only_members(probe.child.id())?;
    let usage = probe
        .gate
        .receipt()
        .and_then(|receipt| receipt.usage)
        .ok_or("missing frozen usage")?;
    assert!(usage.observed_while_frozen);
    assert!(!usage.observed_after_stop);
    assert!(usage.memory_events.is_some());
    assert!(usage.tasks_max_events.is_some());
    probe.finish()?;
    let usage = probe
        .gate
        .receipt()
        .and_then(|receipt| receipt.usage)
        .ok_or("lost final usage")?;
    assert!(usage.observed_while_frozen || usage.observed_after_stop);
    assert!(usage.memory_events.is_some());
    assert!(usage.tasks_max_events.is_some());
    Ok(())
}

fn wait_frozen(gate: &mut Gate) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !gate.poll_frozen()? {
        if Instant::now() >= deadline {
            return Err("scope did not freeze".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn process_group(pid: u32) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, fields) = stat.rsplit_once(") ").ok_or("invalid process stat")?;
    let mut fields = fields.split_whitespace();
    fields.next().ok_or("missing process state")?;
    fields.next().ok_or("missing parent pid")?;
    let group = fields.next().ok_or("missing process group")?.parse()?;
    let session = fields.next().ok_or("missing session")?.parse()?;
    Ok((group, session))
}
