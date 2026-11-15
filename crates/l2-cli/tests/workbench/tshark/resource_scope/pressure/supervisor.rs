use super::{ScopeProbe, in_unlimited_parent_at};
use crate::workbench::tshark::{
    resource_scope::kernel::{
        control_text, ensure_parent_outside, open_cgroup, parent_cgroups, parse_populated,
        scope_removed,
    },
    sandbox::Launch,
    secure_files::descriptor_source,
};
use rustix::fs::{self as rfs, Mode, OFlags};
use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn Error>>;
const FIXTURE_MODE: &str = "L2_SCOPE_SUPERVISOR_MODE";
const FIXTURE_DIR: &str = "L2_SCOPE_SUPERVISOR_DIR";
const CGROUP2_MAGIC: u64 = 0x6367_7270;

struct SupervisedScope {
    supervisor: Child,
    directory: File,
    kill: File,
}

struct PendingSupervisor(Option<Child>);

impl Drop for PendingSupervisor {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for SupervisedScope {
    fn drop(&mut self) {
        // The held file can only affect the private verified test scope
        let _ = self.kill.write_all(b"1");
        let _ = self.supervisor.kill();
        let _ = self.supervisor.wait();
    }
}

#[test]
fn supervisor_fixture() -> TestResult {
    let Some(mode) = std::env::var_os(FIXTURE_MODE) else {
        return Ok(());
    };
    let directory =
        PathBuf::from(std::env::var_os(FIXTURE_DIR).ok_or("missing fixture directory")?);
    let marker = directory.join("producer-ready");
    let (launch, limit) = match mode.to_str() {
        Some("parent-death") => (death_launch(&directory), Duration::from_secs(10)),
        Some("runtime") => (runtime_launch(&marker), Duration::from_secs(2)),
        _ => return Err("invalid supervisor fixture mode".into()),
    };
    let mut probe = ScopeProbe::start_launch(launch, limit)?;
    probe.release()?;
    probe.wait_marker(&marker)?;
    let scope = probe
        .gate
        .verified
        .as_ref()
        .ok_or("scope was not verified")?;
    let source = descriptor_source(&scope.directory)?;
    let pending = directory.join("supervisor-pending");
    fs::write(
        &pending,
        format!("{} {}", probe.child.id(), source.display()),
    )?;
    fs::rename(pending, directory.join("supervisor-ready"))?;
    thread::sleep(Duration::from_secs(8));
    Ok(())
}

fn death_launch(directory: &Path) -> Launch {
    let script = concat!(
        "/usr/bin/bwrap --unshare-user --unshare-pid --die-with-parent --as-pid-1 ",
        "--new-session --uid 65534 --gid 65534 --ro-bind /usr /usr --ro-bind /bin /bin ",
        "--ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 ",
        "--proc /proc --dev /dev --bind \"$1\" /out -- /usr/bin/bash -c ",
        "'printf started > /out/producer-ready; sleep 2; ",
        "printf escaped > /out/escaped; exec sleep 8' & wait",
    );
    test_launch(script, directory)
}

fn runtime_launch(marker: &Path) -> Launch {
    // Clear the immediate parent-death signal only in this fixture to test systemd's timer
    let script = concat!(
        "exec /usr/bin/setpriv --pdeathsig clear /usr/bin/bash -c ",
        "\"trap '' TERM; printf started > \\\"\\$1\\\"; while :; do sleep 1; done\" ",
        "runtime-child \"$1\"",
    );
    test_launch(script, marker)
}

fn test_launch(script: &str, argument: &Path) -> Launch {
    Launch {
        executable: PathBuf::from("/usr/bin/bash"),
        arguments: vec![
            OsString::from("-c"),
            OsString::from(script),
            OsString::from("scope-supervisor-test"),
            argument.as_os_str().to_owned(),
        ],
        environment: Vec::new(),
        handles: Vec::new(),
        scope: None,
        output_bootstrap: false,
        output_storage: None,
    }
}

fn start_supervisor(mode: &str, directory: &Path) -> Result<SupervisedScope, Box<dyn Error>> {
    let name = super::super::harness_name(module_path!(), "supervisor_fixture");
    let supervisor = Command::new(std::env::current_exe()?)
        .args(["--exact", &name, "--nocapture"])
        .env(FIXTURE_MODE, mode)
        .env(FIXTURE_DIR, directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut pending = PendingSupervisor(Some(supervisor));
    let ready = directory.join("supervisor-ready");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        if pending
            .0
            .as_mut()
            .ok_or("missing supervisor")?
            .try_wait()?
            .is_some()
        {
            let output = pending
                .0
                .take()
                .ok_or("missing supervisor")?
                .wait_with_output()?;
            return Err(format!(
                "supervisor exited before its scope was ready: stdout={}, stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("supervisor startup timed out".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    let data = fs::read_to_string(ready)?;
    let mut fields = data.split_whitespace();
    let outer = fields.next().ok_or("missing outer pid")?.parse::<u32>()?;
    let source = fields.next().ok_or("missing scope descriptor")?;
    if fields.next().is_some() {
        return Err("invalid scope descriptor receipt".into());
    }
    let directory = File::open(source)?;
    let directory_stat = rfs::fstat(&directory)?;
    if u64::try_from(rfs::fstatfs(&directory)?.f_type).ok() != Some(CGROUP2_MAGIC) {
        return Err("scope descriptor is not cgroup v2".into());
    }
    let groups = fs::read_to_string(format!("/proc/{outer}/cgroup"))?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let hierarchy = crate::recovery_job::system_memory::hierarchy(&groups, &mounts)?;
    let child = open_cgroup(hierarchy.first().ok_or("missing child cgroup")?)?;
    let child_stat = rfs::fstat(child)?;
    if child_stat.st_dev != directory_stat.st_dev || child_stat.st_ino != directory_stat.st_ino {
        return Err("scope descriptor does not match the supervisor child".into());
    }
    ensure_parent_outside(&parent_cgroups(&mounts)?, &directory_stat)?;
    let kill = File::from(rfs::openat(
        &directory,
        "cgroup.kill",
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let supervisor = pending.0.take().ok_or("missing supervisor")?;
    Ok(SupervisedScope {
        supervisor,
        directory,
        kill,
    })
}

fn wait_empty(scope: &SupervisedScope, deadline: Instant) -> TestResult {
    loop {
        match control_text(&scope.directory, "cgroup.events") {
            Ok(events) if !parse_populated(&events)? => return Ok(()),
            Ok(_) => {}
            Err(error) if scope_removed(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err("orphaned test scope remained populated".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn parent_death() -> TestResult {
    if !in_unlimited_parent_at(module_path!(), "parent_death")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let mut scope = start_supervisor("parent-death", temporary.path())?;
    scope.supervisor.kill()?;
    scope.supervisor.wait()?;
    wait_empty(&scope, Instant::now() + Duration::from_secs(3))?;
    thread::sleep(Duration::from_millis(2300));
    assert!(!temporary.path().join("escaped").exists());
    Ok(())
}

#[test]
fn runtime_limit() -> TestResult {
    if !in_unlimited_parent_at(module_path!(), "runtime_limit")? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let mut scope = start_supervisor("runtime", temporary.path())?;
    scope.supervisor.kill()?;
    scope.supervisor.wait()?;
    // The fixture removed PDEATHSIG so that the manager timer is the only stop path
    thread::sleep(Duration::from_millis(150));
    assert!(parse_populated(&control_text(
        &scope.directory,
        "cgroup.events"
    )?)?);
    wait_empty(&scope, Instant::now() + Duration::from_secs(4))?;
    Ok(())
}
