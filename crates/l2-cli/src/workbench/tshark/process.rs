use super::budget::{
    ObjectExportBudget, ObjectExportLimit, ObjectExportResource, ObjectExportUsage,
    ObjectFileSnapshot, StableObject,
};
use l2_workbench::job::Job;
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
#[cfg(unix)]
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    cmp::Ordering,
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    sync::{Arc, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const WORKER_STOP_WAIT: Duration = Duration::from_millis(100);
#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
const GROUP_STOP_WAIT: Duration = Duration::from_millis(500);

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/process.rs"]
mod tests;

/// Captured output and final child status
pub(super) struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
    pub scope: Option<l2_workbench::tshark::ScopeReceipt>,
}

/// Exit status and a bounded tail of `TShark` diagnostics
pub(super) struct StreamOutput {
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub status: ExitStatus,
    pub object_usage: ObjectExportUsage,
    // A successful export uses the final scan after writers stop
    pub objects: Vec<StableObject>,
    pub unsafe_entries: bool,
    pub scope: Option<l2_workbench::tshark::ScopeReceipt>,
}

/// Timeout receipt with the last bounded diagnostic tail and observed object state
#[derive(Debug)]
pub(super) struct ObjectExportTimeout {
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub stderr_complete: bool,
    pub status: Option<ExitStatus>,
    pub usage: ObjectExportUsage,
    pub stable_objects: Vec<StableObject>,
}

impl ObjectExportTimeout {
    pub(super) fn describe(&self) -> String {
        let mut issue = String::from("TShark object export exceeded its time budget");
        if let Some(status) = self.status {
            use fmt::Write as _;
            let _ = write!(issue, " after child exit status {status}");
        }
        let diagnostic = String::from_utf8_lossy(&self.stderr);
        if !diagnostic.trim().is_empty() {
            issue.push_str(": ");
            issue.push_str(diagnostic.trim());
        }
        if self.stderr_truncated {
            issue.push_str(" [diagnostic output truncated]");
        } else if !self.stderr_complete {
            issue.push_str(" [diagnostic output incomplete at timeout]");
        }
        issue
    }
}

#[derive(Default)]
struct DiagnosticState {
    stderr: Vec<u8>,
    truncated: bool,
    complete: bool,
    error: Option<String>,
}

type SharedDiagnostics = Arc<Mutex<DiagnosticState>>;

/// Constraints for one object-export streaming process
#[derive(Clone, Copy)]
pub(super) struct StreamingPolicy<'a> {
    pub stderr_maximum: usize,
    pub deadline: Instant,
    pub object_root: &'a Path,
    pub protocol_directory_count: u64,
    pub object_budget: ObjectExportBudget,
    pub job: Option<&'a Job>,
}

#[derive(Clone, Copy)]
struct CapturePolicy<'a> {
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
    job: Option<&'a Job>,
}

trait WorkerSpawner {
    fn spawn<F>(&mut self, name: &'static str, worker: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static;
}

trait ProcessGate {
    fn verify(&mut self, child: u32) -> io::Result<bool>;
    fn stop(&mut self, deadline: Instant) -> io::Result<()>;
    #[cfg(target_os = "linux")]
    fn verify_member(&self, process: &File) -> io::Result<()>;
    #[cfg(target_os = "linux")]
    fn request_freeze(&mut self) -> io::Result<()>;
    #[cfg(target_os = "linux")]
    fn poll_frozen(&mut self) -> io::Result<bool>;
    #[cfg(target_os = "linux")]
    fn verify_only_members(&mut self, outer_pid: u32) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
impl ProcessGate for super::resource_scope::Gate {
    fn verify(&mut self, child: u32) -> io::Result<bool> {
        self.verify(child)
    }

    fn stop(&mut self, deadline: Instant) -> io::Result<()> {
        self.stop_verified_scope(deadline)
    }

    fn verify_member(&self, process: &File) -> io::Result<()> {
        self.verify_member(process)
    }

    fn request_freeze(&mut self) -> io::Result<()> {
        self.request_freeze()
    }

    fn poll_frozen(&mut self) -> io::Result<bool> {
        self.poll_frozen()
    }

    fn verify_only_members(&mut self, outer_pid: u32) -> io::Result<()> {
        self.verify_only_members(outer_pid)
    }
}

struct ScopeSession<'a> {
    gate: Option<&'a mut dyn ProcessGate>,
    verified: bool,
    stopped: bool,
}

impl<'a> ScopeSession<'a> {
    fn new(gate: Option<&'a mut dyn ProcessGate>) -> Self {
        Self {
            gate,
            verified: false,
            stopped: false,
        }
    }

    fn enter(
        &mut self,
        child: &mut Child,
        deadline: Instant,
        job: Option<&Job>,
        keep_input: bool,
    ) -> Result<(), ProcessError> {
        let Some(gate) = self.gate.as_deref_mut() else {
            return Ok(());
        };
        loop {
            check_start_budget(deadline, job)?;
            if observe_exit(child).map_err(ProcessError::Read)?.is_some() {
                return Err(ProcessError::Containment(io::Error::other(
                    "resource launcher exited before verification",
                )));
            }
            if gate.verify(child.id()).map_err(ProcessError::Containment)? {
                self.verified = true;
                break;
            }
            thread::sleep(Duration::from_millis(3));
        }
        check_start_budget(deadline, job)?;
        let input = child.stdin.as_mut().ok_or_else(|| {
            ProcessError::Containment(io::Error::other("resource gate input unavailable"))
        })?;
        input
            .write_all(b"scope\n")
            .map_err(ProcessError::Containment)?;
        if !keep_input {
            drop(child.stdin.take());
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), io::Error> {
        if !self.verified || self.stopped {
            return Ok(());
        }
        self.stopped = true;
        if let Some(gate) = self.gate.as_deref_mut() {
            gate.stop(Instant::now() + Duration::from_millis(500))?;
        }
        Ok(())
    }

    fn failure(&mut self, primary: ProcessError) -> ProcessError {
        with_cleanup_error(primary, self.stop())
    }

    fn stop_before_reap(&mut self) -> Result<(), ProcessError> {
        self.stop().map_err(|source| ProcessError::ScopeCleanup {
            primary: None,
            source,
        })
    }

    #[cfg(target_os = "linux")]
    fn verify_member(&self, process: &File) -> Result<(), ProcessError> {
        if !self.verified {
            return Err(ProcessError::Containment(io::Error::other(
                "resource scope is not verified",
            )));
        }
        self.gate
            .as_deref()
            .ok_or_else(|| {
                ProcessError::Containment(io::Error::other("resource scope unavailable"))
            })?
            .verify_member(process)
            .map_err(ProcessError::Containment)
    }

    #[cfg(target_os = "linux")]
    fn finish_output(
        &mut self,
        outer_pid: u32,
        deadline: Instant,
        job: Option<&Job>,
    ) -> Result<(), ProcessError> {
        if !self.verified {
            return Err(ProcessError::Containment(io::Error::other(
                "resource scope is not verified",
            )));
        }
        let gate = self.gate.as_deref_mut().ok_or_else(|| {
            ProcessError::Containment(io::Error::other("resource scope unavailable"))
        })?;
        check_start_budget(deadline, job)?;
        gate.request_freeze().map_err(ProcessError::Containment)?;
        loop {
            check_start_budget(deadline, job)?;
            if gate.poll_frozen().map_err(ProcessError::Containment)? {
                break;
            }
            thread::sleep(Duration::from_millis(3));
        }
        check_start_budget(deadline, job)?;
        gate.verify_only_members(outer_pid)
            .map_err(ProcessError::Containment)?;
        check_start_budget(deadline, job)?;
        self.stop_before_reap()
    }
}

fn check_start_budget(deadline: Instant, job: Option<&Job>) -> Result<(), ProcessError> {
    if job.is_some_and(Job::is_cancelled) {
        return Err(ProcessError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(ProcessError::TimedOut);
    }
    Ok(())
}

fn stop_after_error(
    scope: &mut ScopeSession<'_>,
    child: &mut Child,
    primary: ProcessError,
) -> ProcessError {
    let error = scope.failure(primary);
    stop_and_reap(child);
    error
}

struct ThreadSpawner;

impl WorkerSpawner for ThreadSpawner {
    fn spawn<F>(&mut self, name: &'static str, worker: F) -> io::Result<JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        thread::Builder::new()
            .name(format!("tshark-{name}"))
            .spawn(worker)
    }
}

/// Process failure that cannot be represented by a successful receipt
#[derive(Debug)]
pub(super) enum ProcessError {
    Spawn(io::Error),
    Containment(io::Error),
    MemoryLimit(Box<l2_workbench::tshark::ScopeReceipt>),
    TaskLimit(Box<l2_workbench::tshark::ScopeReceipt>),
    ScopeCleanup {
        primary: Option<Box<Self>>,
        source: io::Error,
    },
    WorkerSpawn {
        worker: &'static str,
        source: io::Error,
    },
    Read(io::Error),
    Cancelled,
    TimedOut,
    OutputLimit,
    ObjectExportLimit(ObjectExportLimit),
    ObjectExportTimeout(ObjectExportTimeout),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "could not start TShark: {error}"),
            Self::Containment(error) => write!(formatter, "could not contain TShark: {error}"),
            Self::MemoryLimit(receipt) => write!(
                formatter,
                "TShark encountered an out-of-memory event (effective limit: {} bytes)",
                receipt.effective_memory_max_bytes
            ),
            Self::TaskLimit(receipt) => write!(
                formatter,
                "TShark reached its task limit (effective limit: {})",
                receipt.effective_tasks_max
            ),
            Self::ScopeCleanup { primary, source } => {
                if let Some(primary) = primary {
                    write!(
                        formatter,
                        "{primary}; resource scope cleanup failed: {source}"
                    )
                } else {
                    write!(formatter, "resource scope cleanup failed: {source}")
                }
            }
            Self::WorkerSpawn { worker, source } => {
                write!(
                    formatter,
                    "could not start TShark {worker} reader: {source}"
                )
            }
            Self::Read(error) => write!(formatter, "could not capture TShark output: {error}"),
            Self::Cancelled => formatter.write_str("TShark object export was cancelled"),
            Self::TimedOut => formatter.write_str("TShark exceeded its time budget"),
            Self::OutputLimit => formatter.write_str("TShark output exceeded its byte budget"),
            Self::ObjectExportLimit(limit) => formatter.write_str(&limit.describe()),
            Self::ObjectExportTimeout(timeout) => formatter.write_str(&timeout.describe()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResourceLimit {
    Memory,
    Tasks,
}

pub(super) fn resource_limit(
    receipt: &l2_workbench::tshark::ScopeReceipt,
) -> Option<ResourceLimit> {
    let usage = receipt.usage?;
    if usage
        .memory_events
        .is_some_and(|events| events.oom > 0 || events.oom_kill > 0)
    {
        Some(ResourceLimit::Memory)
    } else if usage.tasks_max_events.is_some_and(|events| events > 0) {
        Some(ResourceLimit::Tasks)
    } else {
        None
    }
}

impl Error for ProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn(error)
            | Self::Containment(error)
            | Self::Read(error)
            | Self::WorkerSpawn { source: error, .. } => Some(error),
            Self::ScopeCleanup {
                primary: Some(primary),
                ..
            } => Some(primary.as_ref()),
            Self::ScopeCleanup { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
fn run_with_gate_and_spawner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: CapturePolicy<'_>,
    spawner: &mut impl WorkerSpawner,
    gate: &mut dyn ProcessGate,
) -> Result<Output, ProcessError> {
    run_capture(
        executable,
        arguments,
        environment,
        policy,
        spawner,
        Some(gate),
    )
}

fn start_worker(
    spawner: &mut impl WorkerSpawner,
    name: &'static str,
    worker: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, ProcessError> {
    spawner
        .spawn(name, worker)
        .map_err(|source| ProcessError::WorkerSpawn {
            worker: name,
            source,
        })
}

/// Run an offline `TShark` process while draining both pipes and enforcing hard budgets
#[cfg(test)]
pub(super) fn run(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
) -> Result<Output, ProcessError> {
    run_with_job_and_spawner(
        executable,
        arguments,
        environment,
        CapturePolicy {
            timeout,
            stdout_maximum,
            stderr_maximum,
            job: None,
        },
        &mut ThreadSpawner,
    )
}

pub(super) fn run_launch(
    launch: &mut super::sandbox::Launch,
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
    job: Option<&Job>,
) -> Result<Output, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        if launch.output_bootstrap {
            return Err(ProcessError::Containment(io::Error::other(
                "object export requires streaming",
            )));
        }
        let gate = launch.scope.as_mut().ok_or_else(|| {
            ProcessError::Containment(io::Error::other("resource scope is required"))
        })?;
        gate.claim().map_err(ProcessError::Containment)?;
        let mut output = run_capture(
            &launch.executable,
            &launch.arguments,
            &launch.environment,
            CapturePolicy {
                timeout,
                stdout_maximum,
                stderr_maximum,
                job,
            },
            &mut ThreadSpawner,
            Some(gate),
        )?;
        if let Some(receipt) = launch
            .scope
            .as_ref()
            .and_then(super::resource_scope::Gate::receipt)
        {
            if let Some(limit) = resource_limit(&receipt) {
                return Err(match limit {
                    ResourceLimit::Memory => ProcessError::MemoryLimit(Box::new(receipt)),
                    ResourceLimit::Tasks => ProcessError::TaskLimit(Box::new(receipt)),
                });
            }
            output.scope = Some(receipt);
        }
        Ok(output)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (launch, timeout, stdout_maximum, stderr_maximum, job);
        Err(ProcessError::Containment(io::Error::new(
            io::ErrorKind::Unsupported,
            "resource scope unavailable",
        )))
    }
}

#[cfg(test)]
fn run_with_job_and_spawner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: CapturePolicy<'_>,
    spawner: &mut impl WorkerSpawner,
) -> Result<Output, ProcessError> {
    run_capture(executable, arguments, environment, policy, spawner, None)
}

fn run_capture(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: CapturePolicy<'_>,
    spawner: &mut impl WorkerSpawner,
    gate: Option<&mut dyn ProcessGate>,
) -> Result<Output, ProcessError> {
    let CapturePolicy {
        timeout,
        stdout_maximum,
        stderr_maximum,
        job,
    } = policy;
    if job.is_some_and(Job::is_cancelled) {
        return Err(ProcessError::Cancelled);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ProcessError::TimedOut)?;
    let mut scope = ScopeSession::new(gate);
    let mut child = spawn(executable, arguments, environment, scope.gate.is_some())?;
    if let Err(error) = scope.enter(&mut child, deadline, job, false) {
        return Err(stop_after_error(&mut scope, &mut child, error));
    }
    let Some(stdout) = child.stdout.take() else {
        let error = ProcessError::Read(io::Error::other("stdout pipe unavailable"));
        return Err(stop_after_error(&mut scope, &mut child, error));
    };
    let Some(stderr) = child.stderr.take() else {
        let error = ProcessError::Read(io::Error::other("stderr pipe unavailable"));
        return Err(stop_after_error(&mut scope, &mut child, error));
    };
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_worker = match start_worker(spawner, "stdout", move || {
        let _ = stdout_sender.send((true, capture(stdout, stdout_maximum)));
    }) {
        Ok(worker) => worker,
        Err(error) => {
            // No reader owns stderr yet, so close it before stopping the process
            drop(stderr);
            return Err(stop_after_error(&mut scope, &mut child, error));
        }
    };
    let stderr_worker = match start_worker(spawner, "stderr", move || {
        let _ = sender.send((false, capture(stderr, stderr_maximum)));
    }) {
        Ok(worker) => worker,
        Err(error) => {
            // Stop the process group so the first reader can finish before joining
            let error = stop_after_error(&mut scope, &mut child, error);
            join_workers_after_stop([stdout_worker]);
            return Err(error);
        }
    };
    wait_for_capture(
        &mut child,
        &receiver,
        [stdout_worker, stderr_worker],
        deadline,
        job,
        &mut scope,
    )
}

fn wait_for_capture(
    child: &mut Child,
    receiver: &mpsc::Receiver<(bool, Result<Vec<u8>, ProcessError>)>,
    workers: [JoinHandle<()>; 2],
    deadline: Instant,
    job: Option<&Job>,
    scope: &mut ScopeSession<'_>,
) -> Result<Output, ProcessError> {
    let [stdout_worker, stderr_worker] = workers;
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut status = None;

    loop {
        if job.is_some_and(Job::is_cancelled) {
            let error = stop_after_error(scope, child, ProcessError::Cancelled);
            join_workers_after_stop([stdout_worker, stderr_worker]);
            return Err(error);
        }
        while let Ok((is_stdout, result)) = receiver.try_recv() {
            match result {
                Ok(bytes) if is_stdout => stdout_result = Some(bytes),
                Ok(bytes) => stderr_result = Some(bytes),
                Err(error) => {
                    let error = stop_after_error(scope, child, error);
                    join_workers_after_stop([stdout_worker, stderr_worker]);
                    return Err(error);
                }
            }
        }
        if status.is_none() {
            status = match observe_exit(child) {
                Ok(status) => status,
                Err(error) => {
                    let lost = lost_child(&error);
                    let error = scope.failure(ProcessError::Read(error));
                    if !lost {
                        stop_and_reap(child);
                    }
                    join_workers_after_stop([stdout_worker, stderr_worker]);
                    return Err(error);
                }
            };
        }
        if status.is_some() && stdout_result.is_some() && stderr_result.is_some() {
            let _ = stdout_worker.join();
            let _ = stderr_worker.join();
            let cleanup = scope.stop();
            let budget = check_start_budget(deadline, job);
            if let Err(source) = cleanup {
                stop_and_reap(child);
                return Err(ProcessError::ScopeCleanup {
                    primary: budget.err().map(Box::new),
                    source,
                });
            }
            if let Err(error) = budget {
                stop_and_reap(child);
                return Err(error);
            }
            // The waitable leader reserves its group until all capture helpers are signalled
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            stop_process_group(child).map_err(ProcessError::Read)?;
            #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
            let status = status.ok_or_else(|| {
                ProcessError::Read(io::Error::other("TShark exit status unavailable"))
            })?;
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            let status = child.wait().map_err(ProcessError::Read)?;
            check_start_budget(deadline, job)?;
            return Ok(Output {
                stdout: stdout_result.unwrap_or_default(),
                stderr: stderr_result.unwrap_or_default(),
                status,
                scope: None,
            });
        }
        if Instant::now() >= deadline {
            let error = stop_after_error(scope, child, ProcessError::TimedOut);
            join_workers_after_stop([stdout_worker, stderr_worker]);
            return Err(error);
        }
        thread::sleep(Duration::from_millis(3));
    }
}

/// Run `TShark` with discarded stdout, a bounded stderr tail, and one deadline
///
/// The isolated process group lets timeout cleanup stop helper processes too
#[cfg(test)]
pub(super) fn run_streaming(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: StreamingPolicy<'_>,
) -> Result<StreamOutput, ProcessError> {
    run_streaming_with_spawner(
        executable,
        arguments,
        environment,
        policy,
        &mut ThreadSpawner,
    )
}

pub(super) fn run_streaming_launch(
    launch: &mut super::sandbox::Launch,
    policy: StreamingPolicy<'_>,
) -> Result<StreamOutput, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        if !launch.output_bootstrap || launch.output_storage.is_some() {
            return Err(ProcessError::Containment(io::Error::other(
                "object export bootstrap unavailable",
            )));
        }
        let gate = launch.scope.as_mut().ok_or_else(|| {
            ProcessError::Containment(io::Error::other("resource scope is required"))
        })?;
        gate.claim().map_err(ProcessError::Containment)?;
        let mut output = run_streaming_inner(
            &launch.executable,
            &launch.arguments,
            &launch.environment,
            policy,
            &mut ThreadSpawner,
            Some(gate),
            Some(&mut launch.output_storage),
        )?;
        output.scope = launch
            .scope
            .as_ref()
            .and_then(super::resource_scope::Gate::receipt);
        Ok(output)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (launch, policy);
        Err(ProcessError::Containment(io::Error::new(
            io::ErrorKind::Unsupported,
            "resource scope unavailable",
        )))
    }
}

#[cfg(test)]
fn run_streaming_with_spawner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: StreamingPolicy<'_>,
    spawner: &mut impl WorkerSpawner,
) -> Result<StreamOutput, ProcessError> {
    run_streaming_inner(
        executable,
        arguments,
        environment,
        policy,
        spawner,
        None,
        #[cfg(target_os = "linux")]
        None,
    )
}

fn run_streaming_inner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: StreamingPolicy<'_>,
    spawner: &mut impl WorkerSpawner,
    gate: Option<&mut dyn ProcessGate>,
    #[cfg(target_os = "linux")] bootstrap: Option<
        &mut Option<super::output_storage::OutputStorage>,
    >,
) -> Result<StreamOutput, ProcessError> {
    if policy.job.is_some_and(Job::is_cancelled) {
        return Err(ProcessError::Cancelled);
    }
    if Instant::now() >= policy.deadline {
        return Err(empty_stream_timeout(policy));
    }
    #[cfg(target_os = "linux")]
    let output_bootstrap = bootstrap.is_some();
    #[cfg(not(target_os = "linux"))]
    let output_bootstrap = false;
    let mut scope = ScopeSession::new(gate);
    let mut child = spawn_with_output(
        executable,
        arguments,
        environment,
        if output_bootstrap {
            Stdio::piped()
        } else {
            Stdio::null()
        },
        Stdio::piped(),
        scope.gate.is_some(),
    )?;
    if let Err(error) = scope.enter(&mut child, policy.deadline, policy.job, output_bootstrap) {
        let error = if matches!(error, ProcessError::TimedOut) {
            empty_stream_timeout(policy)
        } else {
            error
        };
        return Err(stop_after_error(&mut scope, &mut child, error));
    }
    let (worker, diagnostics) = start_diagnostic_worker(&mut child, policy, &mut scope, spawner)?;
    let mut monitor = StreamingMonitor::new(policy, Arc::clone(&diagnostics));
    #[cfg(target_os = "linux")]
    let (root, control) = if let Some(storage) = bootstrap {
        match bootstrap_output(&mut child, storage, &scope, policy.deadline, policy.job) {
            Ok((root, control)) => (Some(root), Some(control)),
            Err(error) => {
                let cleanup = scope.stop();
                stop_and_reap(&mut child);
                join_workers_after_stop([worker]);
                let error = if matches!(error, ProcessError::TimedOut) {
                    ProcessError::ObjectExportTimeout(monitor.timeout_receipt())
                } else {
                    error
                };
                return Err(with_cleanup_error(error, cleanup));
            }
        }
    } else {
        (None, None)
    };
    #[cfg(target_os = "linux")]
    let policy = StreamingPolicy {
        object_root: root.as_deref().unwrap_or(policy.object_root),
        ..policy
    };

    wait_for_streaming(
        &mut child,
        worker,
        &mut monitor,
        policy,
        &mut scope,
        #[cfg(target_os = "linux")]
        control,
    )
}

fn start_diagnostic_worker(
    child: &mut Child,
    policy: StreamingPolicy<'_>,
    scope: &mut ScopeSession<'_>,
    spawner: &mut impl WorkerSpawner,
) -> Result<(JoinHandle<()>, SharedDiagnostics), ProcessError> {
    let Some(stderr) = child.stderr.take() else {
        let error = ProcessError::Read(io::Error::other("stderr pipe unavailable"));
        return Err(stop_after_error(scope, child, error));
    };
    let diagnostics = Arc::new(Mutex::new(DiagnosticState::default()));
    let worker_diagnostics = Arc::clone(&diagnostics);
    let worker = start_worker(spawner, "stderr", move || {
        let result = drain_tail(stderr, policy.stderr_maximum, &worker_diagnostics);
        let mut state = lock_diagnostics(&worker_diagnostics);
        state.complete = true;
        if let Err(error) = result {
            state.error = Some(error.to_string());
        }
    })
    .map_err(|error| stop_after_error(scope, child, error))?;
    Ok((worker, diagnostics))
}

fn wait_for_streaming(
    child: &mut Child,
    worker: JoinHandle<()>,
    monitor: &mut StreamingMonitor,
    policy: StreamingPolicy<'_>,
    scope: &mut ScopeSession<'_>,
    #[cfg(target_os = "linux")] mut control: Option<OutputControl<std::process::ChildStdout>>,
) -> Result<StreamOutput, ProcessError> {
    loop {
        if policy.job.is_some_and(Job::is_cancelled) {
            let error = stop_after_error(scope, child, ProcessError::Cancelled);
            join_workers_after_stop([worker]);
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        let result = poll_output_control(control.as_mut(), child, policy, scope, monitor)
            .and_then(|()| monitor.poll_scoped(child, policy, scope));
        #[cfg(not(target_os = "linux"))]
        let result = monitor.poll_scoped(child, policy, scope);
        match result {
            Ok(Some(output)) => {
                let _ = worker.join();
                #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
                if !output.status.success() {
                    // A failed direct child can leave helpers alive after closing stderr
                    stop_process_group(child).map_err(ProcessError::Read)?;
                }
                #[cfg(target_os = "linux")]
                let output = StreamOutput {
                    status: if control.is_some() {
                        let _ = child.wait().map_err(ProcessError::Read)?;
                        output.status
                    } else {
                        child.wait().map_err(ProcessError::Read)?
                    },
                    ..output
                };
                if let Err(error) = check_start_budget(policy.deadline, policy.job) {
                    return Err(if matches!(error, ProcessError::TimedOut) {
                        ProcessError::ObjectExportTimeout(monitor.timeout_receipt())
                    } else {
                        error
                    });
                }
                return Ok(output);
            }
            Ok(None) => thread::sleep(Duration::from_millis(3)),
            Err(error) => {
                let lost = matches!(&error, ProcessError::Read(source) if lost_child(source));
                let cleanup = scope.stop();
                if !lost {
                    stop_and_reap(child);
                }
                join_workers_after_stop([worker]);
                let error = if matches!(error, ProcessError::TimedOut) {
                    ProcessError::ObjectExportTimeout(monitor.timeout_receipt())
                } else {
                    error
                };
                return Err(with_cleanup_error(error, cleanup));
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(
    not(target_env = "uclibc"),
    expect(
        clippy::needless_pass_by_ref_mut,
        reason = "uClibc uses Child::try_wait to observe the child"
    )
)]
fn poll_output_control(
    control: Option<&mut OutputControl<std::process::ChildStdout>>,
    child: &mut Child,
    policy: StreamingPolicy<'_>,
    scope: &mut ScopeSession<'_>,
    monitor: &mut StreamingMonitor,
) -> Result<(), ProcessError> {
    use std::os::unix::process::ExitStatusExt;

    let Some(control) = control else {
        return Ok(());
    };
    if let Some(status) = control.poll(policy.deadline, policy.job)? {
        scope.finish_output(child.id(), policy.deadline, policy.job)?;
        monitor.status = Some(ExitStatus::from_raw(i32::from(status) << 8));
    } else if !control.complete && observe_exit(child).map_err(ProcessError::Read)?.is_some() {
        return Err(invalid_control(
            "sandbox supervisor exited before completion",
        ));
    }
    Ok(())
}

fn with_cleanup_error(primary: ProcessError, cleanup: io::Result<()>) -> ProcessError {
    match cleanup {
        Ok(()) => primary,
        Err(source) => ProcessError::ScopeCleanup {
            primary: Some(Box::new(primary)),
            source,
        },
    }
}

fn empty_stream_timeout(policy: StreamingPolicy<'_>) -> ProcessError {
    ProcessError::ObjectExportTimeout(ObjectExportTimeout {
        stderr: Vec::new(),
        stderr_truncated: false,
        stderr_complete: true,
        status: None,
        usage: ObjectExportUsage {
            protocol_directory_count: policy.protocol_directory_count,
            ..ObjectExportUsage::default()
        },
        stable_objects: Vec::new(),
    })
}

#[cfg(target_os = "linux")]
struct OutputControl<R> {
    reader: R,
    line: Vec<u8>,
    bytes: usize,
    reported_exit: Option<u8>,
    complete: bool,
}

#[cfg(target_os = "linux")]
impl<R: Read> OutputControl<R> {
    const fn new(reader: R) -> Self {
        Self {
            reader,
            line: Vec::new(),
            bytes: 0,
            reported_exit: None,
            complete: false,
        }
    }

    fn poll(&mut self, deadline: Instant, job: Option<&Job>) -> Result<Option<u8>, ProcessError> {
        const MAX_CONTROL_BYTES: usize = 4096;
        if self.complete {
            return Ok(None);
        }
        loop {
            check_start_budget(deadline, job)?;
            let mut byte = [0_u8; 1];
            match self.reader.read(&mut byte) {
                Ok(0) => return Err(invalid_control("sandbox control ended before completion")),
                Ok(_) => {
                    self.bytes += 1;
                    if self.bytes > MAX_CONTROL_BYTES {
                        return Err(invalid_control("sandbox control exceeded its byte limit"));
                    }
                    let [byte] = byte;
                    if byte == b'\n' {
                        if let Some(status) = self.finish_line()? {
                            self.complete = true;
                            return Ok(Some(status));
                        }
                    } else {
                        self.line.push(byte);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(ProcessError::Containment(error)),
            }
        }
    }

    fn finish_line(&mut self) -> Result<Option<u8>, ProcessError> {
        let line = std::mem::take(&mut self.line);
        if line.starts_with(b"{") {
            let value: serde_json::Value = serde_json::from_slice(&line)
                .map_err(|_| invalid_control("invalid sandbox exit status"))?;
            let object = value
                .as_object()
                .filter(|object| object.len() == 1)
                .ok_or_else(|| invalid_control("invalid sandbox exit status"))?;
            let status = object
                .get("exit-code")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u8::try_from(status).ok())
                .ok_or_else(|| invalid_control("invalid sandbox exit status"))?;
            if self.reported_exit.replace(status).is_some() {
                return Err(invalid_control("duplicate sandbox exit status"));
            }
            return Ok(None);
        }
        let text = line
            .strip_prefix(b"L2_EXPORT_DONE:")
            .and_then(|value| std::str::from_utf8(value).ok())
            .ok_or_else(|| invalid_control("invalid sandbox completion signal"))?;
        let status = text
            .parse::<u8>()
            .map_err(|_| invalid_control("invalid sandbox completion status"))?;
        if text != status.to_string() || self.reported_exit.is_some_and(|exit| exit != status) {
            return Err(invalid_control("sandbox completion status disagrees"));
        }
        Ok(Some(status))
    }
}

#[cfg(target_os = "linux")]
fn invalid_control(message: &'static str) -> ProcessError {
    ProcessError::Containment(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(target_os = "linux")]
fn bootstrap_output(
    child: &mut Child,
    storage: &mut Option<super::output_storage::OutputStorage>,
    scope: &ScopeSession<'_>,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<(std::path::PathBuf, OutputControl<std::process::ChildStdout>), ProcessError> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let mut stdout = child.stdout.take().ok_or_else(|| {
        ProcessError::Containment(io::Error::other("sandbox status pipe unavailable"))
    })?;
    let flags = fcntl_getfl(&stdout).map_err(|error| ProcessError::Containment(error.into()))?;
    fcntl_setfl(&stdout, flags | OFlags::NONBLOCK)
        .map_err(|error| ProcessError::Containment(error.into()))?;
    let status = read_bootstrap_line(&mut stdout, deadline, job)?;
    let status: serde_json::Value = serde_json::from_slice(&status).map_err(|error| {
        ProcessError::Containment(io::Error::new(io::ErrorKind::InvalidData, error))
    })?;
    let pid = status
        .get("child-pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            ProcessError::Containment(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid sandbox child PID",
            ))
        })?;
    let mount_namespace = status
        .get("mnt-namespace")
        .and_then(serde_json::Value::as_u64)
        .filter(|namespace| *namespace > 0)
        .ok_or_else(|| {
            ProcessError::Containment(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid sandbox mount namespace",
            ))
        })?;
    let sandbox = super::output_storage::SandboxProcess::pin(pid, mount_namespace)
        .map_err(ProcessError::Containment)?;
    if read_bootstrap_line(&mut stdout, deadline, job)? != b"L2_EXPORT_READY\n" {
        return Err(ProcessError::Containment(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid sandbox readiness signal",
        )));
    }
    // Only the trusted monitor and blocked bootstrap can write before release
    match stdout.read(&mut [0_u8; 1]) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(ProcessError::Containment(error)),
        Ok(_) => {
            return Err(ProcessError::Containment(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected sandbox status data",
            )));
        }
    }
    check_start_budget(deadline, job)?;
    scope.verify_member(sandbox.directory())?;
    let output = sandbox.output().map_err(ProcessError::Containment)?;
    let root = output.path().map_err(ProcessError::Containment)?;
    *storage = Some(output);
    check_start_budget(deadline, job)?;
    let input = child.stdin.as_mut().ok_or_else(|| {
        ProcessError::Containment(io::Error::other("sandbox bootstrap input unavailable"))
    })?;
    input
        .write_all(b"L2_EXPORT_GO\n")
        .map_err(ProcessError::Containment)?;
    Ok((root, OutputControl::new(stdout)))
}

#[cfg(target_os = "linux")]
fn read_bootstrap_line(
    reader: &mut impl Read,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<Vec<u8>, ProcessError> {
    const MAX_STATUS_LINE: usize = 4096;
    let mut line = Vec::new();
    loop {
        check_start_budget(deadline, job)?;
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(ProcessError::Containment(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sandbox bootstrap ended early",
                )));
            }
            Ok(_) => {
                let [byte] = byte;
                line.push(byte);
                if byte == b'\n' {
                    return Ok(line);
                }
                if line.len() >= MAX_STATUS_LINE {
                    return Err(ProcessError::Containment(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sandbox status line is too long",
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(3));
            }
            Err(error) => return Err(ProcessError::Containment(error)),
        }
    }
}

struct StreamingMonitor {
    diagnostics: Option<(Vec<u8>, bool)>,
    diagnostic_state: SharedDiagnostics,
    status: Option<ExitStatus>,
    usage: ObjectExportUsage,
    next_scan: Instant,
    previous_objects: Vec<StableObject>,
    stable_objects: Vec<StableObject>,
    unsafe_entries: bool,
}

impl StreamingMonitor {
    fn new(policy: StreamingPolicy<'_>, diagnostic_state: SharedDiagnostics) -> Self {
        Self {
            diagnostics: None,
            diagnostic_state,
            status: None,
            usage: ObjectExportUsage {
                protocol_directory_count: policy.protocol_directory_count,
                ..ObjectExportUsage::default()
            },
            next_scan: Instant::now(),
            previous_objects: Vec::new(),
            stable_objects: Vec::new(),
            unsafe_entries: false,
        }
    }

    #[cfg(test)]
    fn poll(
        &mut self,
        child: &mut Child,
        policy: StreamingPolicy<'_>,
    ) -> Result<Option<StreamOutput>, ProcessError> {
        self.poll_scoped(child, policy, &mut ScopeSession::new(None))
    }

    fn poll_scoped(
        &mut self,
        child: &mut Child,
        policy: StreamingPolicy<'_>,
        scope: &mut ScopeSession<'_>,
    ) -> Result<Option<StreamOutput>, ProcessError> {
        self.receive_diagnostics()?;
        self.poll_child(child)?;
        if Instant::now() >= policy.deadline {
            return Err(ProcessError::TimedOut);
        }
        if self.status.is_some() && self.diagnostics.is_some() {
            scope.stop_before_reap()?;
            // Stop writers before the last scan while the leader still reserves the group ID
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            stop_group_before_final_scan(child, policy)?;
            #[cfg(all(test, target_os = "linux", not(target_env = "uclibc")))]
            tests::before_final_scan();
            self.scan_objects(policy)?;
            check_start_budget(policy.deadline, policy.job)?;
            return self.finish().map(Some);
        }
        if Instant::now() >= self.next_scan {
            self.scan_objects(policy)?;
            self.next_scan = Instant::now() + Duration::from_millis(50);
            check_start_budget(policy.deadline, policy.job)?;
        }
        Ok(None)
    }

    fn receive_diagnostics(&mut self) -> Result<(), ProcessError> {
        if self.diagnostics.is_some() {
            return Ok(());
        }
        let state = lock_diagnostics(&self.diagnostic_state);
        if let Some(error) = &state.error {
            return Err(ProcessError::Read(io::Error::other(error.clone())));
        }
        let diagnostics = state
            .complete
            .then(|| (state.stderr.clone(), state.truncated));
        drop(state);
        self.diagnostics = diagnostics;
        Ok(())
    }

    #[cfg_attr(
        all(target_os = "linux", not(target_env = "uclibc")),
        expect(
            clippy::needless_pass_by_ref_mut,
            reason = "Other targets use Child::try_wait to observe the child"
        )
    )]
    fn poll_child(&mut self, child: &mut Child) -> Result<(), ProcessError> {
        if self.status.is_none() {
            self.status = observe_exit(child).map_err(ProcessError::Read)?;
        }
        Ok(())
    }

    fn scan_objects(&mut self, policy: StreamingPolicy<'_>) -> Result<(), ProcessError> {
        match observe_object_tree(policy, &mut self.usage) {
            Ok(current) => {
                // Every non-directory must be a private regular file in a protocol directory
                self.unsafe_entries = usize::try_from(current.files).ok()
                    != Some(current.stable_objects.len())
                    || current.entries - current.files != policy.protocol_directory_count;
                self.stable_objects =
                    intersect_object_scans(&self.previous_objects, &current.stable_objects);
                self.previous_objects = current.stable_objects;
                Ok(())
            }
            Err(ProcessError::ObjectExportLimit(mut limit)) => {
                // Only objects unchanged across complete scans qualify for a partial snapshot
                limit.stable_objects.clone_from(&self.stable_objects);
                Err(ProcessError::ObjectExportLimit(limit))
            }
            Err(error) => Err(error),
        }
    }

    fn finish(&mut self) -> Result<StreamOutput, ProcessError> {
        let status = self.status.take().ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark exit status unavailable"))
        })?;
        let (stderr, stderr_truncated) = self.diagnostics.take().ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark diagnostic output unavailable"))
        })?;
        Ok(StreamOutput {
            stderr,
            stderr_truncated,
            status,
            object_usage: self.usage,
            objects: if status.success() {
                std::mem::take(&mut self.previous_objects)
            } else {
                std::mem::take(&mut self.stable_objects)
            },
            unsafe_entries: self.unsafe_entries,
            scope: None,
        })
    }

    fn timeout_receipt(&self) -> ObjectExportTimeout {
        let state = lock_diagnostics(&self.diagnostic_state);
        ObjectExportTimeout {
            stderr: state.stderr.clone(),
            stderr_truncated: state.truncated,
            stderr_complete: state.complete && state.error.is_none(),
            status: self.status,
            usage: self.usage,
            stable_objects: self.stable_objects.clone(),
        }
    }
}

fn observe_object_tree(
    policy: StreamingPolicy<'_>,
    usage: &mut ObjectExportUsage,
) -> Result<ObjectTreeScan, ProcessError> {
    usage.temporary_scan_complete = false;
    check_start_budget(policy.deadline, policy.job)?;
    let root_directory = open_tree_directory(policy.object_root).map_err(ProcessError::Read)?;
    let mut directories = vec![(std::path::PathBuf::new(), root_directory)];
    let maximum_entries = policy
        .object_budget
        .temporary_files
        .checked_add(policy.protocol_directory_count)
        .ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark object entry budget overflow"))
        })?;
    let mut scan = ObjectTreeScan::default();
    while let Some((relative_directory, directory)) = directories.pop() {
        check_start_budget(policy.deadline, policy.job)?;
        // Each descriptor pins its directory even if the child replaces its name
        let directory_path = tree_directory_source(&directory).map_err(ProcessError::Read)?;
        let entries = fs::read_dir(directory_path).map_err(ProcessError::Read)?;
        for entry in entries {
            check_start_budget(policy.deadline, policy.job)?;
            let entry = entry.map_err(ProcessError::Read)?;
            observe_tree_entry(
                &entry,
                &mut directories,
                &relative_directory,
                &mut scan,
                maximum_entries,
                policy.object_budget,
                usage,
            )?;
            #[cfg(all(test, target_os = "linux"))]
            tests::after_tree_entry();
        }
    }
    check_start_budget(policy.deadline, policy.job)?;
    usage.temporary_bytes_peak = usage.temporary_bytes_peak.max(scan.bytes);
    usage.temporary_files_peak = usage.temporary_files_peak.max(scan.files);
    scan.stable_objects
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    check_start_budget(policy.deadline, policy.job)?;
    usage.temporary_scan_complete = true;
    Ok(scan)
}

#[derive(Default)]
struct ObjectTreeScan {
    bytes: u64,
    files: u64,
    entries: u64,
    stable_objects: Vec<StableObject>,
}

fn observe_tree_entry(
    entry: &fs::DirEntry,
    directories: &mut Vec<(std::path::PathBuf, File)>,
    relative_directory: &Path,
    scan: &mut ObjectTreeScan,
    maximum_entries: u64,
    budget: ObjectExportBudget,
    usage: &mut ObjectExportUsage,
) -> Result<(), ProcessError> {
    scan.entries = scan
        .entries
        .checked_add(1)
        .ok_or_else(|| ProcessError::Read(io::Error::other("TShark tree entry count overflow")))?;
    usage.temporary_tree_entries_peak = usage.temporary_tree_entries_peak.max(scan.entries);
    let path = entry.path();
    let relative_path = relative_directory.join(entry.file_name());
    let metadata = fs::symlink_metadata(&path).map_err(ProcessError::Read)?;
    if metadata.file_type().is_dir() {
        if scan.entries > maximum_entries {
            return Err(tree_entry_limit(maximum_entries, scan.entries, usage));
        }
        let directory = open_tree_directory(&path).map_err(ProcessError::Read)?;
        directories.push((relative_path, directory));
        return Ok(());
    }

    scan.files = scan
        .files
        .checked_add(1)
        .ok_or_else(|| ProcessError::Read(io::Error::other("TShark object file count overflow")))?;
    usage.temporary_files_peak = usage.temporary_files_peak.max(scan.files);
    if scan.files > budget.temporary_files {
        return Err(ProcessError::ObjectExportLimit(ObjectExportLimit::new(
            ObjectExportResource::Files,
            budget.temporary_files,
            scan.files,
            *usage,
        )));
    }
    if metadata.file_type().is_file() {
        scan.bytes = scan.bytes.checked_add(metadata.len()).ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark object byte count overflow"))
        })?;
        usage.temporary_bytes_peak = usage.temporary_bytes_peak.max(scan.bytes);
        if scan.bytes > budget.temporary_bytes {
            return Err(ProcessError::ObjectExportLimit(ObjectExportLimit::new(
                ObjectExportResource::Bytes,
                budget.temporary_bytes,
                scan.bytes,
                *usage,
            )));
        }
    }
    if scan.entries > maximum_entries {
        return Err(tree_entry_limit(maximum_entries, scan.entries, usage));
    }
    if let Some(relative_path) = eligible_object_path(&relative_path)
        && let Some(snapshot) = ObjectFileSnapshot::from_metadata(&metadata)
    {
        scan.stable_objects.push(StableObject {
            relative_path,
            snapshot,
        });
    }
    Ok(())
}

fn eligible_object_path(relative_path: &Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    let mut components = relative_path.components();
    let Component::Normal(_) = components.next()? else {
        return None;
    };
    let Component::Normal(_) = components.next()? else {
        return None;
    };
    if components.next().is_some() {
        return None;
    }
    Some(relative_path.to_owned())
}

#[cfg(target_os = "linux")]
fn open_tree_directory(path: &Path) -> io::Result<File> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_tree_directory(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe TShark object scanning requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn tree_directory_source(directory: &File) -> io::Result<std::path::PathBuf> {
    super::secure_files::descriptor_source(directory)
}

#[cfg(not(target_os = "linux"))]
fn tree_directory_source(_directory: &File) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe TShark object scanning requires Linux",
    ))
}

fn intersect_object_scans(
    previous: &[StableObject],
    current: &[StableObject],
) -> Vec<StableObject> {
    let mut stable = Vec::new();
    let (mut previous_index, mut current_index) = (0, 0);
    while let (Some(before), Some(now)) = (previous.get(previous_index), current.get(current_index))
    {
        match before.relative_path.cmp(&now.relative_path) {
            Ordering::Less => previous_index += 1,
            Ordering::Greater => current_index += 1,
            Ordering::Equal => {
                if before.snapshot == now.snapshot {
                    stable.push(now.clone());
                }
                previous_index += 1;
                current_index += 1;
            }
        }
    }
    stable
}

const fn tree_entry_limit(maximum: u64, observed: u64, usage: &ObjectExportUsage) -> ProcessError {
    ProcessError::ObjectExportLimit(ObjectExportLimit::new(
        ObjectExportResource::TreeEntries,
        maximum,
        observed,
        *usage,
    ))
}

fn drain_tail(
    mut reader: impl Read,
    maximum: usize,
    diagnostics: &SharedDiagnostics,
) -> io::Result<()> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        append_diagnostic_tail(diagnostics, &buffer, count, maximum)?;
    }
}

fn append_diagnostic_tail(
    diagnostics: &SharedDiagnostics,
    buffer: &[u8],
    count: usize,
    maximum: usize,
) -> io::Result<()> {
    let mut state = lock_diagnostics(diagnostics);
    let combined = state.stderr.len().saturating_add(count);
    if combined > maximum {
        state.truncated = true;
    }
    let excess = combined.saturating_sub(maximum);
    if excess >= state.stderr.len() {
        state.stderr.clear();
        let skip = excess - combined.saturating_sub(count);
        state.stderr.extend_from_slice(
            buffer
                .get(skip..count)
                .ok_or_else(|| io::Error::other("diagnostic buffer range is invalid"))?,
        );
    } else {
        state.stderr.drain(..excess);
        state.stderr.extend_from_slice(
            buffer
                .get(..count)
                .ok_or_else(|| io::Error::other("diagnostic buffer range is invalid"))?,
        );
    }
    drop(state);
    Ok(())
}

fn spawn(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    gated: bool,
) -> Result<Child, ProcessError> {
    spawn_with_output(
        executable,
        arguments,
        environment,
        Stdio::piped(),
        Stdio::piped(),
        gated,
    )
}

fn spawn_with_output(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    stdout: Stdio,
    stderr: Stdio,
    gated: bool,
) -> Result<Child, ProcessError> {
    // Auto-reaped children cannot reserve their process group during cleanup
    #[cfg(target_os = "linux")]
    ensure_waitable_children().map_err(ProcessError::Spawn)?;
    let mut command = Command::new(executable);
    // Retain only command lookup and the Windows system root from the caller environment
    let path = std::env::var_os("PATH");
    let system_root = std::env::var_os("SystemRoot");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(system_root) = system_root {
        command.env("SystemRoot", system_root);
    }
    // A dedicated group lets timeout cleanup stop helper processes with the direct child
    #[cfg(unix)]
    command.process_group(0);
    // Explicit TLS-key-log input is the only source of secrets for this process
    for (name, value) in environment {
        command.env(name, value);
    }
    command
        .args(arguments)
        .stdin(if gated { Stdio::piped() } else { Stdio::null() })
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(ProcessError::Spawn)
}

#[cfg(target_os = "linux")]
fn ensure_waitable_children() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot inspect SIGCHLD policy: {error}"),
        )
    })?;
    check_sigchld_policy(&status)
}

#[cfg(target_os = "linux")]
fn check_sigchld_policy(status: &str) -> io::Result<()> {
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|value| u128::from_str_radix(value.trim(), 16).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cannot read SIGCHLD policy"))?;
    if mask & (1_u128 << (nix::libc::SIGCHLD - 1)) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TShark cannot start while SIGCHLD is ignored",
        ));
    }
    Ok(())
}

fn capture(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>, ProcessError> {
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 8192];
    loop {
        let remaining = maximum - bytes.len();
        // The extra byte is read only into stack memory after the budget is full
        let read_size = remaining.clamp(1, scratch.len());
        let (buffer, _) = scratch.split_at_mut(read_size);
        let count = match reader.read(buffer) {
            Ok(0) => return Ok(bytes),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ProcessError::Read(error)),
        };
        if remaining == 0 {
            return Err(ProcessError::OutputLimit);
        }
        let chunk = buffer.get(..count).ok_or_else(|| {
            ProcessError::Read(io::Error::new(
                io::ErrorKind::InvalidData,
                "reader returned an invalid byte count",
            ))
        })?;
        let required = bytes.len() + chunk.len();
        if required > bytes.capacity() {
            // Moving reallocations can temporarily retain both buffers; this bounds retained capacity
            let target = bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(maximum);
            bytes
                .try_reserve_exact(target - bytes.len())
                .map_err(|error| ProcessError::Read(io::Error::other(error)))?;
            if bytes.capacity() > maximum {
                return Err(ProcessError::OutputLimit);
            }
        }
        bytes.extend_from_slice(chunk);
    }
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn observe_exit(child: &Child) -> io::Result<Option<ExitStatus>> {
    use std::os::unix::process::ExitStatusExt;

    #[cfg(test)]
    tests::record_observe();
    let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    #[cfg(test)]
    let status = tests::waitid_with_fault(pid, flags);
    #[cfg(not(test))]
    let status = waitid(Id::Pid(pid), flags);
    let status = match status {
        Ok(status) => status,
        // Returning to the caller keeps cancellation and deadlines observable
        Err(nix::errno::Errno::EINTR) => return Ok(None),
        Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
    };
    let raw = match status {
        WaitStatus::StillAlive => return Ok(None),
        WaitStatus::Exited(_, code) => code << 8,
        WaitStatus::Signaled(_, signal, core_dumped) => {
            signal as i32 | if core_dumped { 0x80 } else { 0 }
        }
        _ => return Err(io::Error::other("unexpected TShark child status")),
    };
    // This owner keeps the exit status waitable until group cleanup finishes
    Ok(Some(ExitStatus::from_raw(raw)))
}

#[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
fn observe_exit(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    child.try_wait()
}

fn lost_child(error: &io::Error) -> bool {
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    {
        error.raw_os_error() == Some(nix::libc::ECHILD)
    }
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    {
        let _ = error;
        false
    }
}

fn stop_and_reap(child: &mut std::process::Child) {
    // A helper can keep stdout or stderr open after the direct child exits
    let Ok(exited) = stop_process_group(child) else {
        return;
    };
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn join_workers_after_stop<T, const WORKERS: usize>(workers: [JoinHandle<T>; WORKERS]) {
    let deadline = Instant::now() + WORKER_STOP_WAIT;
    while workers.iter().any(|worker| !worker.is_finished()) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(3)));
    }

    // A detached descendant can keep an inherited pipe open after the child is gone
    for worker in workers {
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}

fn lock_diagnostics(diagnostics: &SharedDiagnostics) -> MutexGuard<'_, DiagnosticState> {
    diagnostics
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn stop_process_group(child: &std::process::Child) -> io::Result<bool> {
    // A lost child cannot safely identify a group by its old PID
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    let exited = match observe_exit(child) {
        Ok(status) => status.is_some(),
        Err(error) if lost_child(&error) => return Err(error),
        // Other observation errors do not release the owned child
        Err(_) => false,
    };
    #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
    let exited = false;
    #[cfg(unix)]
    if let Ok(process_group) = i32::try_from(child.id())
        && process_group > 1
    {
        // The run created this group specifically for the child and its descendants
        let _ = killpg(Pid::from_raw(process_group), Signal::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child;
    Ok(exited)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn stop_group_before_final_scan(
    child: &Child,
    policy: StreamingPolicy<'_>,
) -> Result<(), ProcessError> {
    stop_process_group(child).map_err(ProcessError::Read)?;
    validate_proc_view().map_err(ProcessError::Read)?;
    let cleanup_deadline = Instant::now() + GROUP_STOP_WAIT;
    let deadline = policy.deadline.min(cleanup_deadline);
    group_stop_result(
        wait_for_group_stop(Path::new("/proc"), child.id(), deadline, policy.job),
        cleanup_deadline,
        policy.deadline,
    )?;
    check_group_stop_budget(policy.deadline, policy.job)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn group_stop_result(
    result: Result<(), ProcessError>,
    cleanup_deadline: Instant,
    operation_deadline: Instant,
) -> Result<(), ProcessError> {
    match result {
        Err(ProcessError::TimedOut) if cleanup_deadline < operation_deadline => {
            Err(ProcessError::Read(io::Error::new(
                io::ErrorKind::TimedOut,
                "TShark process group did not stop",
            )))
        }
        result => result,
    }
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn validate_proc_view() -> io::Result<()> {
    let self_pid = fs::read_link("/proc/self")?;
    if self_pid.to_str() != Some(std::process::id().to_string().as_str()) {
        return Err(io::Error::other("procfs uses a different PID namespace"));
    }
    validate_proc_mount(&fs::read_to_string("/proc/self/mountinfo")?)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn validate_proc_mount(mountinfo: &str) -> io::Result<()> {
    let mut found = false;
    for line in mountinfo.lines() {
        let (mount, filesystem) = line
            .split_once(" - ")
            .ok_or_else(|| io::Error::other("invalid procfs mount information"))?;
        found |= proc_mount_exposes_processes(mount, filesystem)?;
    }
    if !found {
        return Err(io::Error::other("procfs mount is unavailable"));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn proc_mount_exposes_processes(mount: &str, filesystem: &str) -> io::Result<bool> {
    let mut mount_fields = mount.split_whitespace();
    if mount_fields.nth(4) != Some("/proc") {
        return Ok(false);
    }
    let mount_options = mount_fields
        .next()
        .ok_or_else(|| io::Error::other("procfs mount options are unavailable"))?;
    let mut filesystem_fields = filesystem.split_whitespace();
    if filesystem_fields.next() != Some("proc") {
        return Err(io::Error::other("/proc is not a procfs mount"));
    }
    let options = filesystem_fields
        .nth(1)
        .ok_or_else(|| io::Error::other("procfs filesystem options are unavailable"))?;
    if mount_options
        .split(',')
        .chain(options.split(','))
        .any(|option| {
            (option == "hidepid" || option.starts_with("hidepid="))
                && !matches!(option, "hidepid=0" | "hidepid=off")
        })
    {
        return Err(io::Error::other("procfs hides processes"));
    }
    Ok(true)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn wait_for_group_stop(
    proc_root: &Path,
    process_group: u32,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<(), ProcessError> {
    while process_group_has_live_members(proc_root, process_group, deadline, job)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(3)));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn process_group_has_live_members(
    proc_root: &Path,
    process_group: u32,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<bool, ProcessError> {
    check_group_stop_budget(deadline, job)?;
    let entries = fs::read_dir(proc_root).map_err(ProcessError::Read)?;
    for entry in entries {
        check_group_stop_budget(deadline, job)?;
        if process_is_live_in_group(&entry.map_err(ProcessError::Read)?, process_group)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn process_is_live_in_group(
    entry: &fs::DirEntry,
    process_group: u32,
) -> Result<bool, ProcessError> {
    if entry
        .file_name()
        .to_str()
        .and_then(|name| name.parse::<u32>().ok())
        .is_none()
    {
        return Ok(false);
    }
    let stat = match fs::read_to_string(entry.path().join("stat")) {
        Ok(stat) => stat,
        // A process can disappear between listing procfs and reading its state
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(nix::libc::ESRCH) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(ProcessError::Read(error)),
    };
    let (state, group, threads) = parse_process_group_stat(&stat).map_err(ProcessError::Read)?;
    // A zombie leader can still have threads that can write
    Ok(group == process_group && (!matches!(state, "Z" | "X" | "x") || threads > 1))
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn check_group_stop_budget(deadline: Instant, job: Option<&Job>) -> Result<(), ProcessError> {
    if job.is_some_and(Job::is_cancelled) {
        return Err(ProcessError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(ProcessError::TimedOut);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
fn parse_process_group_stat(stat: &str) -> io::Result<(&str, u32, u32)> {
    let (_, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("invalid process metadata"))?;
    let mut fields = fields.split_whitespace();
    let state = fields
        .next()
        .filter(|state| state.len() == 1)
        .ok_or_else(|| io::Error::other("invalid process state"))?;
    let group = fields
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("invalid process group"))?;
    let threads = fields
        .nth(14)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("invalid process thread count"))?;
    Ok((state, group, threads))
}
