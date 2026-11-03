use super::{ObjectExportBudget, ProcessError, empty_object_root, policy, run_streaming};
use nix::{
    errno::Errno,
    sys::wait::{Id, WaitPidFlag, WaitStatus, waitid},
    unistd::Pid,
};
use std::{
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Write},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_MARKER: &str = "L2_TSHARK_PGID_NAMESPACE_TEST";
const IGNORED_SIGCHLD_MARKER: &str = "L2_TSHARK_IGNORED_SIGCHLD_TEST";
#[derive(Clone, Copy)]
enum Mode {
    Buffered,
    Streaming,
}

struct ReleaseOnDrop(PathBuf);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, b"release");
    }
}

struct Victim(Child);

impl Drop for Victim {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn wait_for(mut condition: impl FnMut() -> bool) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture was not ready",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn read_pid(path: &Path) -> io::Result<i32> {
    let mut pid = None;
    wait_for(|| {
        pid = fs::read_to_string(path)
            .ok()
            .and_then(|value| value.strip_suffix('\n')?.parse().ok());
        pid.is_some()
    })?;
    pid.ok_or_else(|| io::Error::other("fixture PID is unavailable"))
}

#[test]
fn streaming_cleanup_never_signals_a_reused_process_group() -> Result<(), Box<dyn Error>> {
    check_process_group(Mode::Streaming)
}

#[test]
fn buffered_cleanup_never_signals_a_reused_process_group() -> Result<(), Box<dyn Error>> {
    check_process_group(Mode::Buffered)
}

fn in_private_namespace(name: &str) -> Result<bool, Box<dyn Error>> {
    if std::env::var_os(CHILD_MARKER).is_none() {
        let output = Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
            ])
            .arg(std::env::current_exe()?)
            .args(["--exact", name, "--nocapture"])
            .env(CHILD_MARKER, "1")
            .output()?;
        if !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("Operation not permitted")
        {
            eprintln!("private PID namespaces are unavailable; skipping reuse fixture");
            return Ok(false);
        }
        assert!(
            output.status.success(),
            "private namespace fixture failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(false);
    }

    // The PID allocator is changed only inside a new PID and mount namespace
    assert_eq!(
        std::process::id(),
        1,
        "fixture must be the private namespace init"
    );
    Ok(true)
}

fn start_fixture_capture(
    mode: Mode,
    leader_path: &Path,
    ready: &Path,
    release: &Path,
    object_root: PathBuf,
) -> thread::JoinHandle<Result<(), ProcessError>> {
    let arguments = [
        OsString::from("-c"),
        OsString::from(
            "printf '%s\n' \"$$\" > \"$LEADER_FILE\"; setsid sh -c ': > \"$READY\"; while [ ! -f \"$RELEASE\" ]; do sleep 0.02; done' & while [ ! -f \"$READY\" ]; do sleep 0.01; done; exit 7",
        ),
    ];
    let environment = [
        (
            OsString::from("LEADER_FILE"),
            leader_path.as_os_str().to_owned(),
        ),
        (OsString::from("READY"), ready.as_os_str().to_owned()),
        (OsString::from("RELEASE"), release.as_os_str().to_owned()),
    ];
    thread::spawn(move || match mode {
        Mode::Buffered => super::super::run(
            Path::new("sh"),
            &arguments,
            &environment,
            Duration::from_secs(2),
            1024,
            1024,
        )
        .map(|_| ()),
        Mode::Streaming => run_streaming(
            Path::new("sh"),
            &arguments,
            &environment,
            policy(
                Instant::now() + Duration::from_secs(2),
                &object_root,
                0,
                ObjectExportBudget::default(),
            ),
        )
        .map(|_| ()),
    })
}

fn check_process_group(mode: Mode) -> Result<(), Box<dyn Error>> {
    let name = match mode {
        Mode::Buffered => {
            "workbench::tshark::process::tests::pgid_reuse::buffered_cleanup_never_signals_a_reused_process_group"
        }
        Mode::Streaming => {
            "workbench::tshark::process::tests::pgid_reuse::streaming_cleanup_never_signals_a_reused_process_group"
        }
    };
    if !in_private_namespace(name)? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let leader_path = temporary.path().join("leader.pid");
    let ready = temporary.path().join("detached.ready");
    let release = temporary.path().join("release");
    let _release = ReleaseOnDrop(release.clone());
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let worker = start_fixture_capture(mode, &leader_path, &ready, &release, object_root);
    wait_for(|| ready.exists())?;
    let leader = read_pid(&leader_path)?;
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    wait_for(|| {
        matches!(
            waitid(Id::Pid(Pid::from_raw(leader)), flags),
            Ok(WaitStatus::Exited(_, _)) | Err(Errno::ECHILD)
        )
    })?;
    // Give the real monitor a chance to observe the already-exited leader
    thread::sleep(Duration::from_millis(100));
    fs::write("/proc/sys/kernel/ns_last_pid", (leader - 1).to_string())?;
    let mut victim = Victim(
        Command::new("sleep")
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let victim_pid = victim.0.id();
    let result = worker
        .join()
        .map_err(|_| io::Error::other("capture worker panicked"))?;
    let victim_was_running = victim.0.try_wait()?.is_none();
    fs::write(&release, b"release")?;
    match (mode, result) {
        (Mode::Buffered, Err(ProcessError::TimedOut)) => {}
        (Mode::Streaming, Err(ProcessError::ObjectExportTimeout(timeout))) => {
            assert_eq!(timeout.status.and_then(|status| status.code()), Some(7));
        }
        _ => return Err("capture did not preserve the timeout result".into()),
    }
    assert!(
        victim_was_running,
        "cleanup signalled the unrelated process group {victim_pid} after leader {leader} exited"
    );
    assert_ne!(
        victim_pid,
        u32::try_from(leader)?,
        "the exited leader's identity was reallocated before cleanup"
    );
    Ok(())
}

#[test]
fn cleanup_after_an_external_reap_does_not_signal_a_reused_group() -> Result<(), Box<dyn Error>> {
    let name = "workbench::tshark::process::tests::pgid_reuse::cleanup_after_an_external_reap_does_not_signal_a_reused_group";
    if !in_private_namespace(name)? {
        return Ok(());
    }
    let temporary = tempfile::tempdir()?;
    let victim_path = temporary.path().join("victim.pid");
    let release = temporary.path().join("release");
    let _release = ReleaseOnDrop(release.clone());
    let script = "read -r trigger || exit 10; setsid sh -c 'printf \"%s\\n\" \"$$\" > \"$VICTIM\"; while [ ! -f \"$RELEASE\" ]; do sleep 0.02; done' & wait";
    let mut owner = Victim(
        Command::new("sh")
            .args(["-c", script])
            .env("VICTIM", &victim_path)
            .env("RELEASE", &release)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut leader = Command::new("sh")
        .args(["-c", "exit 7"])
        .process_group(0)
        .spawn()?;
    let leader_pid = Pid::from_raw(i32::try_from(leader.id())?);
    nix::sys::wait::waitpid(leader_pid, None)?;

    fs::write(
        "/proc/sys/kernel/ns_last_pid",
        (leader_pid.as_raw() - 1).to_string(),
    )?;
    owner
        .0
        .stdin
        .as_mut()
        .ok_or("fixture input unavailable")?
        .write_all(b"go\n")?;
    let victim_pid = read_pid(&victim_path)?;
    assert_eq!(victim_pid, leader_pid.as_raw(), "failed to force PID reuse");
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    assert_eq!(waitid(Id::Pid(leader_pid), flags), Err(Errno::ECHILD));

    super::super::stop_and_reap(&mut leader);
    thread::sleep(Duration::from_millis(25));
    let victim_was_running = super::process_is_running(u32::try_from(victim_pid)?)?;
    fs::write(&release, b"release")?;
    let _ = owner.0.wait()?;
    assert!(
        victim_was_running,
        "cleanup signalled the unrelated group after ECHILD"
    );
    Ok(())
}

struct ReapingSpawner {
    pid_path: PathBuf,
    reaped: bool,
    fail: bool,
}

impl super::super::WorkerSpawner for ReapingSpawner {
    fn spawn<F>(&mut self, name: &'static str, worker: F) -> io::Result<thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.reaped {
            let pid = read_pid(&self.pid_path)?;
            nix::sys::wait::waitpid(Pid::from_raw(pid), None).map_err(io::Error::other)?;
            self.reaped = true;
        }
        if self.fail {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "injected reader start failure",
            ));
        }
        thread::Builder::new().name(name.into()).spawn(worker)
    }
}

fn check_external_reap(mode: Mode, fail_reader: bool) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("child.pid");
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let arguments = [
        OsString::from("-c"),
        OsString::from("printf '%s\n' \"$$\" > \"$PID_FILE\"; exit 7"),
    ];
    let environment = [(OsString::from("PID_FILE"), pid_path.as_os_str().to_owned())];
    let mut spawner = ReapingSpawner {
        pid_path,
        reaped: false,
        fail: fail_reader,
    };
    super::OBSERVED_POLLS.set(Some(0));
    let start = Instant::now();
    let result = match mode {
        Mode::Buffered => super::super::run_with_job_and_spawner(
            Path::new("sh"),
            &arguments,
            &environment,
            super::super::CapturePolicy {
                timeout: Duration::from_secs(2),
                stdout_maximum: 1024,
                stderr_maximum: 1024,
                job: None,
            },
            &mut spawner,
        )
        .map(|_| ()),
        Mode::Streaming => super::super::run_streaming_with_spawner(
            Path::new("sh"),
            &arguments,
            &environment,
            policy(
                Instant::now() + Duration::from_secs(2),
                &object_root,
                0,
                ObjectExportBudget::default(),
            ),
            &mut spawner,
        )
        .map(|_| ()),
    };
    let polls = super::OBSERVED_POLLS.replace(None);
    if fail_reader {
        assert!(
            matches!(result, Err(ProcessError::WorkerSpawn { source, .. }) if source.kind() == io::ErrorKind::WouldBlock),
            "reader-start error lost precedence"
        );
    } else {
        assert!(
            matches!(result, Err(ProcessError::Read(source)) if source.raw_os_error() == Some(Errno::ECHILD as i32)),
            "lost child status did not return ECHILD"
        );
    }
    assert_eq!(
        polls,
        Some(1),
        "cleanup performed another wait after ECHILD"
    );
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "lost child cleanup exceeded its bound"
    );
    Ok(())
}

#[test]
fn capture_reports_a_lost_child_without_waiting_again() -> Result<(), Box<dyn Error>> {
    check_external_reap(Mode::Buffered, false)?;
    check_external_reap(Mode::Streaming, false)
}

#[test]
fn reader_start_failure_keeps_precedence_after_an_external_reap() -> Result<(), Box<dyn Error>> {
    check_external_reap(Mode::Buffered, true)?;
    check_external_reap(Mode::Streaming, true)
}

#[test]
fn streaming_signal_exit_preserves_the_termination_status() -> Result<(), Box<dyn Error>> {
    use std::os::unix::process::ExitStatusExt;

    let temporary = tempfile::tempdir()?;
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let arguments = [OsString::from("-c"), OsString::from("kill -TERM $$")];
    let output = run_streaming(
        Path::new("sh"),
        &arguments,
        &[],
        policy(
            Instant::now() + Duration::from_secs(2),
            &object_root,
            0,
            ObjectExportBudget::default(),
        ),
    )?;
    assert_eq!(output.status.signal(), Some(nix::libc::SIGTERM));
    Ok(())
}

#[test]
fn ignored_sigchld_rejects_capture_before_launching_tshark() -> Result<(), Box<dyn Error>> {
    let name = "workbench::tshark::process::tests::pgid_reuse::ignored_sigchld_rejects_capture_before_launching_tshark";
    if std::env::var_os(IGNORED_SIGCHLD_MARKER).is_some() {
        return check_ignored_sigchld();
    }
    if !in_private_namespace(name)? {
        return Ok(());
    }
    let output = Command::new("sh")
        .args([
            "-c",
            "trap '' CHLD; exec \"$1\" --exact \"$2\" --nocapture",
            "sh",
        ])
        .arg(std::env::current_exe()?)
        .arg(name)
        .env(IGNORED_SIGCHLD_MARKER, "1")
        .output()?;
    assert!(
        output.status.success(),
        "ignored SIGCHLD fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn check_ignored_sigchld() -> Result<(), Box<dyn Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .ok_or("missing SigIgn")?;
    let mask = u128::from_str_radix(mask.trim(), 16)?;
    assert_ne!(
        mask & (1_u128 << (nix::libc::SIGCHLD - 1)),
        0,
        "fixture did not inherit ignored SIGCHLD"
    );
    for mode in [Mode::Buffered, Mode::Streaming] {
        let temporary = tempfile::tempdir()?;
        let started = temporary.path().join("tshark-started");
        let object_root = temporary.path().join("objects");
        empty_object_root(&object_root)?;
        let arguments = [
            OsString::from("-c"),
            OsString::from("printf started > \"$STARTED\""),
        ];
        let environment = [(OsString::from("STARTED"), started.as_os_str().to_owned())];
        let result = match mode {
            Mode::Buffered => super::super::run(
                Path::new("sh"),
                &arguments,
                &environment,
                Duration::from_secs(1),
                1024,
                1024,
            )
            .map(|_| ()),
            Mode::Streaming => run_streaming(
                Path::new("sh"),
                &arguments,
                &environment,
                policy(
                    Instant::now() + Duration::from_secs(1),
                    &object_root,
                    0,
                    ObjectExportBudget::default(),
                ),
            )
            .map(|_| ()),
        };
        assert!(
            !started.exists(),
            "capture launched despite ignored SIGCHLD"
        );
        assert!(
            matches!(result, Err(ProcessError::Spawn(error)) if error.kind() == io::ErrorKind::Unsupported && error.to_string().contains("SIGCHLD")),
            "ignored SIGCHLD did not return a clear spawn error"
        );
    }
    Ok(())
}

#[test]
fn sigchld_policy_requires_a_valid_nonignored_mask() -> Result<(), Box<dyn Error>> {
    super::super::check_sigchld_policy("SigIgn:\t0000000000000000\n")?;
    let ignored = format!("SigIgn:\t{:016x}\n", 1_u128 << (nix::libc::SIGCHLD - 1));
    assert_eq!(
        super::super::check_sigchld_policy(&ignored)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    for status in [
        "",
        "SigIgn:\n",
        "SigIgn: not-hex\n",
        "SigIgn: 100000000000000000000000000000000\n",
    ] {
        assert_eq!(
            super::super::check_sigchld_policy(status)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    Ok(())
}

#[test]
fn sigchld_policy_accepts_a_valid_128_bit_linux_mask() -> Result<(), Box<dyn Error>> {
    let high_signal = 1_u128 << 100;
    let allowed = format!("SigIgn:\t{high_signal:032x}\n");
    super::super::check_sigchld_policy(&allowed)?;
    let ignored = format!(
        "SigIgn:\t{:032x}\n",
        high_signal | (1_u128 << (nix::libc::SIGCHLD - 1))
    );
    assert_eq!(
        super::super::check_sigchld_policy(&ignored)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn interrupted_waitid_does_not_fail_capture() -> Result<(), Box<dyn Error>> {
    for mode in [Mode::Buffered, Mode::Streaming] {
        let temporary = tempfile::tempdir()?;
        let object_root = temporary.path().join("objects");
        empty_object_root(&object_root)?;
        let arguments = [OsString::from("-c"), OsString::from("exit 0")];
        super::NEXT_POLL_ERROR.set(Some(Errno::EINTR));
        let result = match mode {
            Mode::Buffered => super::super::run(
                Path::new("sh"),
                &arguments,
                &[],
                Duration::from_secs(2),
                1024,
                1024,
            )
            .map(|output| output.status),
            Mode::Streaming => run_streaming(
                Path::new("sh"),
                &arguments,
                &[],
                policy(
                    Instant::now() + Duration::from_secs(2),
                    &object_root,
                    0,
                    ObjectExportBudget::default(),
                ),
            )
            .map(|output| output.status),
        };
        assert_eq!(
            super::NEXT_POLL_ERROR.take(),
            None,
            "waitid fault was not consumed"
        );
        assert!(
            result?.success(),
            "capture failed after a transient waitid interruption"
        );
    }
    Ok(())
}

#[test]
fn interrupted_cleanup_still_terminates_and_reaps_the_owned_child() -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("sh")
        .args(["-c", "exec sleep 30"])
        .process_group(0)
        .spawn()?;
    super::NEXT_POLL_ERROR.set(Some(Errno::EINTR));
    super::super::stop_and_reap(&mut child);
    let exited = child.try_wait()?.is_some();
    if !exited {
        child.kill()?;
        child.wait()?;
    }
    assert_eq!(
        super::NEXT_POLL_ERROR.take(),
        None,
        "waitid fault was not consumed"
    );
    assert!(
        exited,
        "an interrupted cleanup left the owned child running"
    );
    Ok(())
}

#[test]
fn buffered_failure_stops_descendant_after_it_closes_capture_pipes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("descendant.pid");
    let release = temporary.path().join("release");
    let _release = ReleaseOnDrop(release.clone());
    let script = "sh -c 'printf \"%s\\n\" \"$$\" > \"$DESCENDANT\"; i=0; while [ ! -f \"$RELEASE\" ] && [ \"$i\" -lt 100 ]; do i=$((i + 1)); sleep 0.02; done' </dev/null >/dev/null 2>&1 & while [ ! -s \"$DESCENDANT\" ]; do sleep 0.01; done; exit 7";
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let environment = [
        (
            OsString::from("DESCENDANT"),
            pid_path.as_os_str().to_owned(),
        ),
        (OsString::from("RELEASE"), release.as_os_str().to_owned()),
    ];
    let output = super::super::run(
        Path::new("sh"),
        &arguments,
        &environment,
        Duration::from_secs(2),
        1024,
        1024,
    )?;
    let descendant = u32::try_from(read_pid(&pid_path)?)?;
    let deadline = Instant::now() + Duration::from_millis(300);
    while super::process_is_running(descendant)? && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    let still_running = super::process_is_running(descendant)?;
    fs::write(&release, b"release")?;
    let cleanup_deadline = Instant::now() + Duration::from_secs(1);
    while super::process_is_running(descendant)? && Instant::now() < cleanup_deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(output.status.code(), Some(7));
    assert!(
        !still_running,
        "failed buffered capture left a same-group descendant running"
    );
    Ok(())
}

struct PersistentPollError;

impl Drop for PersistentPollError {
    fn drop(&mut self) {
        super::PERSISTENT_POLL_ERROR.set(None);
    }
}

#[test]
fn persistent_waitid_error_does_not_abandon_a_live_owned_child() -> Result<(), Box<dyn Error>> {
    let mut child = Victim(Command::new("sleep").arg("30").process_group(0).spawn()?);
    super::OBSERVED_POLLS.set(Some(0));
    super::PERSISTENT_POLL_ERROR.set(Some(Errno::EPERM));
    let _fault = PersistentPollError;
    super::super::stop_and_reap(&mut child.0);
    let status = child.0.try_wait()?;
    let polls = super::OBSERVED_POLLS.replace(None);
    assert_eq!(
        polls,
        Some(1),
        "the waitid fault was not observed during cleanup"
    );
    assert!(
        status.is_some(),
        "persistent waitid failure abandoned the owned child"
    );
    Ok(())
}

struct ReadySpawner {
    pid_path: PathBuf,
}

impl super::super::WorkerSpawner for ReadySpawner {
    fn spawn<F>(&mut self, name: &'static str, worker: F) -> io::Result<thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        read_pid(&self.pid_path)?;
        thread::Builder::new().name(name.into()).spawn(worker)
    }
}

fn check_persistent_waitid_failure(mode: Mode) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let pid_path = temporary.path().join("child.pid");
    let release = temporary.path().join("release");
    let _release = ReleaseOnDrop(release.clone());
    let object_root = temporary.path().join("objects");
    empty_object_root(&object_root)?;
    let arguments = [
        OsString::from("-c"),
        OsString::from(
            "printf '%s\\n' \"$$\" > \"$PID_FILE\"; i=0; while [ ! -f \"$RELEASE\" ] && [ \"$i\" -lt 100 ]; do i=$((i + 1)); sleep 0.02; done",
        ),
    ];
    let environment = [
        (OsString::from("PID_FILE"), pid_path.as_os_str().to_owned()),
        (OsString::from("RELEASE"), release.as_os_str().to_owned()),
    ];
    let mut spawner = ReadySpawner {
        pid_path: pid_path.clone(),
    };
    super::OBSERVED_POLLS.set(Some(0));
    super::PERSISTENT_POLL_ERROR.set(Some(Errno::EPERM));
    let _fault = PersistentPollError;
    let result = match mode {
        Mode::Buffered => super::super::run_with_job_and_spawner(
            Path::new("sh"),
            &arguments,
            &environment,
            super::super::CapturePolicy {
                timeout: Duration::from_secs(2),
                stdout_maximum: 1024,
                stderr_maximum: 1024,
                job: None,
            },
            &mut spawner,
        )
        .map(|_| ()),
        Mode::Streaming => super::super::run_streaming_with_spawner(
            Path::new("sh"),
            &arguments,
            &environment,
            policy(
                Instant::now() + Duration::from_secs(2),
                &object_root,
                0,
                ObjectExportBudget::default(),
            ),
            &mut spawner,
        )
        .map(|_| ()),
    };
    let polls = super::OBSERVED_POLLS.replace(None);
    let pid = Pid::from_raw(read_pid(&pid_path)?);
    let outcome = nix::sys::wait::waitpid(pid, Some(WaitPidFlag::WNOHANG));
    if matches!(outcome, Ok(WaitStatus::StillAlive)) {
        fs::write(&release, b"release")?;
        wait_for(|| {
            !matches!(
                nix::sys::wait::waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::StillAlive)
            )
        })?;
    }
    assert!(
        matches!(result, Err(ProcessError::Read(error)) if error.raw_os_error() == Some(Errno::EPERM as i32)),
        "the original waitid error was not reported"
    );
    assert_eq!(
        polls,
        Some(2),
        "monitor and cleanup must both encounter the persistent failure"
    );
    assert_eq!(
        outcome,
        Err(Errno::ECHILD),
        "the runner left the owned child unreaped"
    );
    Ok(())
}

#[test]
fn persistent_waitid_error_keeps_the_runner_error_and_reaps_the_child() -> Result<(), Box<dyn Error>>
{
    let name = "workbench::tshark::process::tests::pgid_reuse::persistent_waitid_error_keeps_the_runner_error_and_reaps_the_child";
    if !in_private_namespace(name)? {
        return Ok(());
    }
    check_persistent_waitid_failure(Mode::Buffered)?;
    check_persistent_waitid_failure(Mode::Streaming)
}
