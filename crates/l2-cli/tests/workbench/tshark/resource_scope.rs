use super::kernel::{
    check_controls, ensure_domain, ensure_unlimited, parse_frozen, parse_populated, sole_member,
};
use super::{Limits, ResourceScope};
use crate::workbench::tshark::sandbox::Launch;
use std::{
    error::Error,
    ffi::OsString,
    fs,
    io::Write,
    num::NonZeroU64,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "resource_scope/pressure.rs"]
mod pressure;

type TestResult = Result<(), Box<dyn Error>>;
const PARENT_SCOPE: &str = "L2_TEST_UNLIMITED_PARENT_SCOPE";
const PARENT_MARKER: &str = "L2_TEST_SCOPE_PARENT_MARKER";

fn limits(memory: u64, swap: u64, tasks: u64, page: u64) -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(
        NonZeroU64::new(memory).ok_or("zero memory")?,
        swap,
        NonZeroU64::new(tasks).ok_or("zero tasks")?,
        page,
    )?)
}

fn test_receipt() -> l2_workbench::tshark::ScopeReceipt {
    l2_workbench::tshark::ScopeReceipt {
        memory_max_bytes: 8192,
        memory_high_bytes: 4096,
        swap_max_bytes: 0,
        tasks_max: 12,
        effective_memory_max_bytes: 8192,
        effective_memory_high_bytes: 4096,
        effective_swap_max_bytes: 0,
        effective_tasks_max: 12,
        usage: None,
    }
}

#[test]
fn memory_and_swap_round_down() -> TestResult {
    let limits = limits(8193, 4097, 12, 4096)?;
    assert_eq!(limits.memory_max, 8192);
    assert_eq!(limits.memory_high, 4096);
    assert_eq!(limits.swap_max, 4096);
    assert_eq!(limits.tasks_max, 12);
    assert!(
        super::Limits::new(
            NonZeroU64::new(2048).ok_or("zero memory")?,
            0,
            NonZeroU64::new(1).ok_or("zero tasks")?,
            4096,
        )
        .is_err()
    );
    assert!(
        super::Limits::new(
            NonZeroU64::new(8192).ok_or("zero memory")?,
            0,
            NonZeroU64::new(1).ok_or("zero tasks")?,
            0,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn control_limits_require_finite_enforced_values() -> TestResult {
    let limits = limits(8192, 4096, 12, 4096)?;
    assert!(check_controls(&limits, "8192\n", "4096\n", "4096\n", "12\n", "1\n").is_ok());
    assert!(check_controls(&limits, "4096\n", "0\n", "0\n", "4\n", "1\n").is_ok());
    for (memory, high, swap, tasks, oom) in [
        ("max", "4096", "4096", "12", "1"),
        ("12288", "4096", "4096", "12", "1"),
        ("8192", "8192", "4096", "12", "1"),
        ("8192", "4096", "max", "12", "1"),
        ("8192", "4096", "8192", "12", "1"),
        ("8192", "4096", "4096", "max", "1"),
        ("8192", "4096", "4096", "13", "1"),
        ("8192", "4096", "4096", "0", "1"),
        ("8192", "4096", "4096", "12", "0"),
        ("8192 trailing", "4096", "4096", "12", "1"),
    ] {
        assert!(
            check_controls(&limits, memory, high, swap, tasks, oom).is_err(),
            "accepted invalid controls: {memory}, {high}, {swap}, {tasks}, {oom}"
        );
    }
    Ok(())
}

#[test]
fn populated_requires_one_boolean_field() -> TestResult {
    assert!(!parse_populated("populated 0\nfrozen 0\n")?);
    assert!(parse_populated("frozen 0\npopulated 1\n")?);
    for input in [
        "frozen 0\n",
        "populated 2\n",
        "populated 0\npopulated 1\n",
        "populated 1 extra\n",
    ] {
        assert!(parse_populated(input).is_err(), "accepted {input:?}");
    }
    Ok(())
}

#[test]
fn frozen_requires_one_boolean_field() -> TestResult {
    assert!(!parse_frozen("populated 1\nfrozen 0\n")?);
    assert!(parse_frozen("frozen 1\npopulated 1\n")?);
    for input in [
        "populated 1\n",
        "frozen 2\n",
        "frozen 0\nfrozen 1\n",
        "frozen 1 extra\n",
    ] {
        assert!(parse_frozen(input).is_err(), "accepted {input:?}");
    }
    Ok(())
}

#[test]
fn scope_requires_only_outer_process() -> TestResult {
    sole_member("42\n", 42)?;
    for input in ["", "42\n43\n", "42\n42\n", "43\n", "invalid\n"] {
        assert!(sole_member(input, 42).is_err(), "accepted {input:?}");
    }
    Ok(())
}

#[test]
fn old_usage_defaults_unfrozen() -> TestResult {
    let usage: l2_workbench::tshark::ScopeUsage = serde_json::from_value(serde_json::json!({
        "memory_peak_bytes": null,
        "tasks_peak": null,
        "memory_events": null,
        "tasks_max_events": null,
        "observed_after_stop": true
    }))?;
    assert!(usage.observed_after_stop);
    assert!(!usage.observed_while_frozen);
    Ok(())
}

#[test]
fn unshared_parent_limits_are_rejected() {
    assert!(ensure_unlimited("max\n").is_ok());
    for record in ["0", "12\n", "18446744073709551615", "", "invalid"] {
        assert!(ensure_unlimited(record).is_err(), "accepted {record:?}");
    }
}

#[test]
fn threaded_parent_cgroups_are_rejected() {
    assert!(ensure_domain("domain\n").is_ok());
    for record in ["threaded", "domain threaded", "domain invalid", "", "other"] {
        assert!(ensure_domain(record).is_err(), "accepted {record:?}");
    }
}

#[test]
fn harness_name_omits_crate() {
    assert_eq!(
        harness_name("l2solver::scope::tests", "probe"),
        "scope::tests::probe"
    );
}

#[test]
fn runtime_budget_is_finite() -> TestResult {
    assert!(super::runtime_micros(Duration::ZERO).is_err());
    assert!(super::runtime_micros(Duration::from_nanos(999)).is_err());
    assert_eq!(super::runtime_micros(Duration::from_micros(1))?, 1);
    assert_eq!(super::runtime_micros(Duration::from_millis(25))?, 25_000);
    assert!(super::runtime_micros(Duration::MAX).is_err());
    Ok(())
}

#[test]
fn parent_scope_is_never_killed() -> TestResult {
    let groups = fs::read_to_string("/proc/self/cgroup")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let hierarchy = crate::recovery_job::system_memory::hierarchy(&groups, &mounts)?;
    let name = hierarchy
        .first()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .ok_or("no unified parent scope")?;
    let mut gate = super::Gate {
        unit: format!("{name}-different"),
        limits: limits(8192, 0, 12, 4096)?,
        verified: None,
        stopped: false,
        claimed: false,
    };
    gate.claim()?;
    assert!(gate.claim().is_err());
    assert!(gate.verify_member(&fs::File::open("/proc/self")?).is_err());
    assert!(gate.request_freeze().is_err());
    assert!(gate.poll_frozen().is_err());
    assert!(gate.verify_only_members(std::process::id()).is_err());
    assert!(!gate.verify(std::process::id())?);
    assert!(gate.stop_verified_scope(Instant::now()).is_err());
    gate.unit = name.to_owned();
    assert!(gate.verify(std::process::id()).is_err());
    assert!(gate.stop_verified_scope(Instant::now()).is_err());
    let parent = super::open_cgroup(hierarchy.first().ok_or("missing parent")?)?;
    let harmless_kill = tempfile::tempfile()?;
    let kill_snapshot = harmless_kill.try_clone()?;
    gate.verified = Some(super::VerifiedScope {
        child_pid: std::process::id(),
        directory: parent,
        freeze: kill_snapshot.try_clone()?,
        kill: kill_snapshot,
        freeze_requested: false,
        frozen: false,
        receipt: test_receipt(),
    });
    assert!(gate.stop_verified_scope(Instant::now()).is_err());
    assert_eq!(harmless_kill.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn frozen_scope_allows_missing_counters() -> TestResult {
    let temporary = tempfile::tempdir()?;
    fs::write(
        temporary.path().join("cgroup.events"),
        "populated 1\nfrozen 1\n",
    )?;
    fs::write(
        temporary.path().join("cgroup.procs"),
        std::process::id().to_string(),
    )?;
    let control = tempfile::tempfile()?;
    let mut gate = super::Gate {
        unit: String::new(),
        limits: limits(8192, 0, 12, 4096)?,
        verified: Some(super::VerifiedScope {
            child_pid: std::process::id(),
            directory: fs::File::open(temporary.path())?,
            freeze: control.try_clone()?,
            kill: control,
            freeze_requested: true,
            frozen: true,
            receipt: test_receipt(),
        }),
        stopped: false,
        claimed: true,
    };
    fs::write(
        temporary.path().join("cgroup.procs"),
        format!("{}\n{}\n", std::process::id(), std::process::id() + 1),
    )?;
    assert!(gate.verify_only_members(std::process::id()).is_err());
    fs::write(
        temporary.path().join("cgroup.procs"),
        std::process::id().to_string(),
    )?;
    let subgroup = temporary.path().join("unexpected-subgroup");
    fs::create_dir(&subgroup)?;
    assert!(gate.verify_only_members(std::process::id()).is_err());
    fs::remove_dir(subgroup)?;
    gate.verify_only_members(std::process::id())?;
    assert!(gate.receipt().ok_or("missing receipt")?.usage.is_none());
    fs::write(
        temporary.path().join("cgroup.events"),
        "populated 1\nfrozen 0\n",
    )?;
    assert!(gate.verify_only_members(std::process::id()).is_err());
    Ok(())
}

#[test]
fn scope_gate_and_cgroup_cleanup() -> TestResult {
    if std::env::var_os("L2_SKIP_SYSTEMD_SCOPE_TESTS").is_some() {
        eprintln!("systemd scope integration explicitly skipped by L2_SKIP_SYSTEMD_SCOPE_TESTS");
        return Ok(());
    }
    if std::env::var_os(PARENT_SCOPE).is_none() {
        return run_parent_scopes();
    }
    announce_parent_case()?;
    let limited_parent =
        std::env::var_os(PARENT_SCOPE).as_deref() == Some(std::ffi::OsStr::new("limited"));
    run_scope_child(limited_parent)
}

fn run_parent_scopes() -> TestResult {
    let test_name = harness_name(module_path!(), "scope_gate_and_cgroup_cleanup");
    for (mode, tasks) in [("unlimited", "infinity"), ("limited", "512")] {
        run_parent_case(&test_name, mode, tasks)?;
    }
    Ok(())
}

fn run_parent_case(test_name: &str, mode: &str, tasks: &str) -> TestResult {
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("selected");
    let mut parent = Command::new("/usr/bin/systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--expand-environment=no",
            "--property=MemoryMax=infinity",
            "--property=MemoryHigh=infinity",
            "--property=MemorySwapMax=infinity",
            &format!("--property=TasksMax={tasks}"),
            "--",
        ])
        .arg(std::env::current_exe()?)
        .args(["--exact", test_name, "--nocapture"])
        .env(PARENT_SCOPE, mode)
        .env(PARENT_MARKER, &marker)
        .process_group(0)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(14);
    loop {
        if let Some(status) = parent.try_wait()? {
            assert!(
                status.success(),
                "{mode} parent scope test failed: {status}"
            );
            assert_eq!(fs::read(&marker)?, b"started", "nested test did not run");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let group = i32::try_from(parent.id())?;
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(group),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = parent.wait();
            return Err(format!("{mode} parent scope test timed out").into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn harness_name(module: &str, test: &str) -> String {
    let path = module.split_once("::").map_or(module, |(_, path)| path);
    format!("{path}::{test}")
}

fn announce_parent_case() -> TestResult {
    let marker = std::env::var_os(PARENT_MARKER).ok_or("nested test marker unavailable")?;
    fs::write(marker, b"started")?;
    Ok(())
}

fn test_launch(marker: &Path) -> Launch {
    Launch {
        executable: PathBuf::from("/usr/bin/bash"),
        arguments: vec![
            OsString::from("-c"),
            OsString::from("printf started > \"$1\"; sleep 10 & wait"),
            OsString::from("scope-test"),
            marker.as_os_str().to_owned(),
        ],
        environment: Vec::new(),
        handles: Vec::new(),
        scope: None,
        output_bootstrap: false,
        output_storage: None,
    }
}

fn run_scope_child(limited_parent: bool) -> TestResult {
    let memory = NonZeroU64::new(64 * 1024 * 1024).ok_or("zero memory")?;
    let tasks = NonZeroU64::new(16).ok_or("zero tasks")?;
    let temporary = tempfile::tempdir()?;
    let marker = temporary.path().join("started");
    let resource = ResourceScope::new(memory, 0, tasks, Duration::from_secs(10))?;
    let mut launch = resource.wrap(test_launch(&marker))?;
    assert_scope_launcher(&launch)?;
    let mut gate = launch.scope.take().ok_or("missing scope gate")?;
    gate.claim()?;
    assert!(gate.claim().is_err());
    let mut child = Command::new(&launch.executable)
        .args(&launch.arguments)
        .env_clear()
        .envs(launch.environment.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    if !verify_scope_fixture(&mut gate, &mut child, limited_parent, &marker, deadline)? {
        return Ok(());
    }
    assert_no_new_privs(child.id())?;
    assert!(gate.verify(std::process::id()).is_err());
    gate.verify_member(&fs::File::open(format!("/proc/{}", child.id()))?)?;
    assert!(gate.verify_member(&fs::File::open("/proc/self")?).is_err());
    let receipt = gate.receipt().ok_or("missing verified limits")?;
    assert_eq!(receipt.memory_max_bytes, memory.get());
    assert_eq!(receipt.memory_high_bytes, memory.get() * 3 / 4);
    assert_eq!(receipt.swap_max_bytes, 0);
    assert_eq!(receipt.tasks_max, tasks.get());
    assert!(receipt.effective_memory_max_bytes <= receipt.memory_max_bytes);
    assert!(receipt.effective_tasks_max <= receipt.tasks_max);
    assert!(!marker.exists(), "workload ran before cgroup verification");
    child
        .stdin
        .as_mut()
        .ok_or("stdin missing")?
        .write_all(b"scope\n")?;
    while !marker.exists() {
        assert!(
            child.try_wait()?.is_none(),
            "scope workload exited before starting"
        );
        assert!(Instant::now() < deadline, "scope workload did not start");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(fs::read(&marker)?, b"started");
    gate.stop_verified_scope(Instant::now() + Duration::from_secs(2))?;
    assert!(gate.verify(child.id()).is_err());
    let receipt = gate.receipt().ok_or("missing final receipt")?;
    if let Some(usage) = receipt.usage {
        assert!(usage.memory_peak_bytes.is_none_or(|peak| peak > 0));
    }
    assert!(!child.wait()?.success());
    Ok(())
}

fn assert_scope_launcher(launch: &Launch) -> TestResult {
    let executable = fs::metadata(&launch.executable)?;
    let setpriv = fs::metadata("/usr/bin/setpriv")?;
    assert_eq!(
        (executable.dev(), executable.ino()),
        (setpriv.dev(), setpriv.ino())
    );
    assert!(
        launch
            .arguments
            .iter()
            .any(|argument| argument == "--collect")
    );
    Ok(())
}

fn assert_no_new_privs(pid: u32) -> TestResult {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    assert!(status.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, value)| name == "NoNewPrivs" && value.trim() == "1")
    }));
    Ok(())
}

fn verify_scope_fixture(
    gate: &mut super::Gate,
    child: &mut Child,
    limited_parent: bool,
    marker: &Path,
    deadline: Instant,
) -> Result<bool, Box<dyn Error>> {
    loop {
        match gate.verify(child.id()) {
            Ok(true) => {
                assert!(!limited_parent, "finite parent limit was escaped");
                return Ok(true);
            }
            Ok(false) => {}
            Err(error) if limited_parent => {
                assert!(error.to_string().contains("finite parent limit"), "{error}");
                child.kill()?;
                child.wait()?;
                assert!(
                    !marker.exists(),
                    "workload ran after its parent limit was escaped"
                );
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
        assert!(
            child.try_wait()?.is_none(),
            "scope launcher exited before the gate"
        );
        assert!(Instant::now() < deadline, "scope gate timed out");
        thread::sleep(Duration::from_millis(5));
    }
}
