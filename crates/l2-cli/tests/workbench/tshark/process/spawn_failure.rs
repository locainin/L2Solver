use super::super::{
    CapturePolicy, ProcessError, WorkerSpawner, run_streaming_with_spawner,
    run_with_job_and_spawner,
};
use super::{ObjectExportBudget, empty_object_root, policy, process_is_running};
use nix::{
    sys::signal::{Signal, kill, killpg},
    unistd::Pid,
};
use std::{
    error::Error,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

struct FailingSpawner {
    fail_on: usize,
    calls: usize,
    ready: PathBuf,
    worker_started: Arc<AtomicBool>,
    worker_finished: Arc<AtomicBool>,
}

impl WorkerSpawner for FailingSpawner {
    fn spawn<F>(&mut self, _name: &'static str, worker: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        self.calls += 1;
        if self.calls == self.fail_on {
            // Wait for both processes so cleanup is tested after real partial startup
            wait_until(|| self.ready.exists())?;
            if self.fail_on > 1 {
                wait_until(|| self.worker_started.load(Ordering::Acquire))?;
            }
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "injected thread failure",
            ));
        }
        let started = Arc::clone(&self.worker_started);
        let finished = Arc::clone(&self.worker_finished);
        thread::Builder::new().spawn(move || {
            started.store(true, Ordering::Release);
            worker();
            finished.store(true, Ordering::Release);
        })
    }
}

struct ProcessFixture {
    directory: tempfile::TempDir,
    parent_pid: PathBuf,
    child_pid: PathBuf,
    ready: PathBuf,
    clean: bool,
}

impl ProcessFixture {
    fn new() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        Ok(Self {
            parent_pid: directory.path().join("parent.pid"),
            child_pid: directory.path().join("child.pid"),
            ready: directory.path().join("ready"),
            directory,
            clean: false,
        })
    }

    fn environment(&self) -> [(OsString, OsString); 3] {
        [
            ("PARENT_PID".into(), self.parent_pid.as_os_str().to_owned()),
            ("CHILD_PID".into(), self.child_pid.as_os_str().to_owned()),
            ("READY".into(), self.ready.as_os_str().to_owned()),
        ]
    }

    fn spawner(&self, fail_on: usize) -> FailingSpawner {
        FailingSpawner {
            fail_on,
            calls: 0,
            ready: self.ready.clone(),
            worker_started: Arc::new(AtomicBool::new(false)),
            worker_finished: Arc::new(AtomicBool::new(false)),
        }
    }

    fn verify_stopped(&mut self) -> Result<(), Box<dyn Error>> {
        let parent = read_pid(&self.parent_pid)?;
        let child = read_pid(&self.child_pid)?;
        wait_until(|| !process_is_running(parent).unwrap_or(true))?;
        wait_until(|| !process_is_running(child).unwrap_or(true))?;
        assert!(
            !Path::new(&format!("/proc/{parent}")).exists(),
            "the direct child must also be reaped"
        );
        self.clean = true;
        Ok(())
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        if !self.clean {
            // Keep a failed regression from leaving its fixture processes alive
            if let Ok(parent) = read_pid(&self.parent_pid)
                && let Ok(parent) = i32::try_from(parent)
            {
                let _ = killpg(Pid::from_raw(parent), Signal::SIGKILL);
            }
            if let Ok(child) = read_pid(&self.child_pid)
                && let Ok(child) = i32::try_from(child)
            {
                let _ = kill(Pid::from_raw(child), Signal::SIGKILL);
            }
        }
    }
}

fn read_pid(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(fs::read_to_string(path)?.parse()?)
}

fn wait_until(mut condition: impl FnMut() -> bool) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture did not become ready",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn arguments() -> [OsString; 2] {
    [
        "-c".into(),
        "printf %s \"$$\" > \"$PARENT_PID\"; sh -c 'printf %s \"$$\" > \"$CHILD_PID\"; : > \"$READY\"; exec sleep 30' & wait".into(),
    ]
}

fn assert_worker_start_error(
    error: &ProcessError,
    expected_worker: &str,
) -> Result<(), Box<dyn Error>> {
    let ProcessError::WorkerSpawn { worker, source } = error else {
        return Err("reader startup must return the typed worker-start error".into());
    };
    assert_eq!(*worker, expected_worker);
    assert_eq!(source.kind(), io::ErrorKind::WouldBlock);
    assert!(error.to_string().contains(expected_worker));
    assert!(error.to_string().contains("injected thread failure"));
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .map(io::Error::kind),
        Some(io::ErrorKind::WouldBlock),
        "the original thread creation error must remain available"
    );
    Ok(())
}

fn buffered_start_failure(fail_on: usize, expected_worker: &str) -> Result<(), Box<dyn Error>> {
    let mut fixture = ProcessFixture::new()?;
    let mut spawner = fixture.spawner(fail_on);
    let result = run_with_job_and_spawner(
        Path::new("sh"),
        &arguments(),
        &fixture.environment(),
        CapturePolicy {
            timeout: Duration::from_secs(5),
            stdout_maximum: 1024,
            stderr_maximum: 1024,
            job: None,
        },
        &mut spawner,
    );
    let error = result.err().ok_or("reader creation must fail")?;

    assert_worker_start_error(&error, expected_worker)?;
    assert_eq!(spawner.calls, fail_on);
    if fail_on == 2 {
        assert!(
            spawner.worker_finished.load(Ordering::Acquire),
            "the first reader must finish during cleanup"
        );
    }
    fixture.verify_stopped()?;
    Ok(())
}

#[test]
fn first_reader_start_failure_reaps_the_child_and_stops_its_descendant()
-> Result<(), Box<dyn Error>> {
    buffered_start_failure(1, "stdout")
}

#[test]
fn second_reader_start_failure_joins_the_first_reader_and_stops_the_process_group()
-> Result<(), Box<dyn Error>> {
    buffered_start_failure(2, "stderr")
}

#[test]
fn streaming_reader_start_failure_reaps_the_child_and_stops_its_descendant()
-> Result<(), Box<dyn Error>> {
    let mut fixture = ProcessFixture::new()?;
    let object_root = fixture.directory.path().join("objects");
    empty_object_root(&object_root)?;
    let mut spawner = fixture.spawner(1);
    let result = run_streaming_with_spawner(
        Path::new("sh"),
        &arguments(),
        &fixture.environment(),
        policy(
            Instant::now() + Duration::from_secs(5),
            &object_root,
            0,
            ObjectExportBudget::default(),
        ),
        &mut spawner,
    );
    let error = result.err().ok_or("streaming reader creation must fail")?;

    assert_worker_start_error(&error, "stderr")?;
    fixture.verify_stopped()?;
    assert_eq!(spawner.calls, 1);
    Ok(())
}
