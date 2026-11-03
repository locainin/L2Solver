use super::budget::{
    ObjectExportBudget, ObjectExportLimit, ObjectExportResource, ObjectExportUsage,
    ObjectFileSnapshot, StableObject,
};
use l2_workbench::job::Job;
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
    fmt, fs,
    io::{self, Read},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    sync::{Arc, Mutex, MutexGuard},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const WORKER_STOP_WAIT: Duration = Duration::from_millis(100);

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/process.rs"]
mod tests;

/// Captured output and final child status
pub(super) struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
}

/// Exit status and a bounded tail of `TShark` diagnostics
pub(super) struct StreamOutput {
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    pub status: ExitStatus,
    pub object_usage: ObjectExportUsage,
    pub stable_objects: Vec<StableObject>,
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

impl Error for ProcessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Spawn(error) | Self::Read(error) | Self::WorkerSpawn { source: error, .. } => {
                Some(error)
            }
            _ => None,
        }
    }
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
pub(super) fn run(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
) -> Result<Output, ProcessError> {
    run_with_job(
        executable,
        arguments,
        environment,
        timeout,
        stdout_maximum,
        stderr_maximum,
        None,
    )
}

/// Run a bounded command while observing shared cancellation
pub(super) fn run_with_job(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    timeout: Duration,
    stdout_maximum: usize,
    stderr_maximum: usize,
    job: Option<&Job>,
) -> Result<Output, ProcessError> {
    run_with_job_and_spawner(
        executable,
        arguments,
        environment,
        CapturePolicy {
            timeout,
            stdout_maximum,
            stderr_maximum,
            job,
        },
        &mut ThreadSpawner,
    )
}

fn run_with_job_and_spawner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: CapturePolicy<'_>,
    spawner: &mut impl WorkerSpawner,
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
    let mut child = spawn(executable, arguments, environment)?;
    let Some(stdout) = child.stdout.take() else {
        stop_and_reap(&mut child);
        return Err(ProcessError::Read(io::Error::other(
            "stdout pipe unavailable",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        stop_and_reap(&mut child);
        return Err(ProcessError::Read(io::Error::other(
            "stderr pipe unavailable",
        )));
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
            stop_and_reap(&mut child);
            return Err(error);
        }
    };
    let stderr_worker = match start_worker(spawner, "stderr", move || {
        let _ = sender.send((false, capture(stderr, stderr_maximum)));
    }) {
        Ok(worker) => worker,
        Err(error) => {
            // Stop the process group so the first reader can finish before joining
            stop_and_reap(&mut child);
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
    )
}

fn wait_for_capture(
    child: &mut Child,
    receiver: &mpsc::Receiver<(bool, Result<Vec<u8>, ProcessError>)>,
    workers: [JoinHandle<()>; 2],
    deadline: Instant,
    job: Option<&Job>,
) -> Result<Output, ProcessError> {
    let [stdout_worker, stderr_worker] = workers;
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut status = None;

    loop {
        if job.is_some_and(Job::is_cancelled) {
            stop_and_reap(child);
            join_workers_after_stop([stdout_worker, stderr_worker]);
            return Err(ProcessError::Cancelled);
        }
        while let Ok((is_stdout, result)) = receiver.try_recv() {
            match result {
                Ok(bytes) if is_stdout => stdout_result = Some(bytes),
                Ok(bytes) => stderr_result = Some(bytes),
                Err(error) => {
                    stop_and_reap(child);
                    join_workers_after_stop([stdout_worker, stderr_worker]);
                    return Err(error);
                }
            }
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    stop_and_reap(child);
                    join_workers_after_stop([stdout_worker, stderr_worker]);
                    return Err(ProcessError::Read(error));
                }
            };
        }
        if status.is_some() && stdout_result.is_some() && stderr_result.is_some() {
            let _ = stdout_worker.join();
            let _ = stderr_worker.join();
            return Ok(Output {
                stdout: stdout_result.unwrap_or_default(),
                stderr: stderr_result.unwrap_or_default(),
                status: status.ok_or_else(|| {
                    ProcessError::Read(io::Error::other("TShark exit status unavailable"))
                })?,
            });
        }
        if Instant::now() >= deadline {
            stop_and_reap(child);
            join_workers_after_stop([stdout_worker, stderr_worker]);
            return Err(ProcessError::TimedOut);
        }
        thread::sleep(Duration::from_millis(3));
    }
}

/// Run `TShark` with discarded stdout, a bounded stderr tail, and one deadline
///
/// The isolated process group lets timeout cleanup stop helper processes too
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

fn run_streaming_with_spawner(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    policy: StreamingPolicy<'_>,
    spawner: &mut impl WorkerSpawner,
) -> Result<StreamOutput, ProcessError> {
    if policy.job.is_some_and(Job::is_cancelled) {
        return Err(ProcessError::Cancelled);
    }
    if Instant::now() >= policy.deadline {
        return Err(ProcessError::ObjectExportTimeout(ObjectExportTimeout {
            stderr: Vec::new(),
            stderr_truncated: false,
            stderr_complete: true,
            status: None,
            usage: ObjectExportUsage {
                protocol_directory_count: policy.protocol_directory_count,
                ..ObjectExportUsage::default()
            },
            stable_objects: Vec::new(),
        }));
    }
    let mut child = spawn_with_output(
        executable,
        arguments,
        environment,
        Stdio::null(),
        Stdio::piped(),
    )?;
    let Some(stderr) = child.stderr.take() else {
        stop_and_reap(&mut child);
        return Err(ProcessError::Read(io::Error::other(
            "stderr pipe unavailable",
        )));
    };
    let diagnostics = Arc::new(Mutex::new(DiagnosticState::default()));
    let worker_diagnostics = Arc::clone(&diagnostics);
    let worker = match start_worker(spawner, "stderr", move || {
        let result = drain_tail(stderr, policy.stderr_maximum, &worker_diagnostics);
        let mut state = lock_diagnostics(&worker_diagnostics);
        state.complete = true;
        if let Err(error) = result {
            state.error = Some(error.to_string());
        }
    }) {
        Ok(worker) => worker,
        Err(error) => {
            stop_and_reap(&mut child);
            return Err(error);
        }
    };
    let mut monitor = StreamingMonitor::new(policy, Arc::clone(&diagnostics));

    loop {
        if policy.job.is_some_and(Job::is_cancelled) {
            stop_and_reap(&mut child);
            join_workers_after_stop([worker]);
            return Err(ProcessError::Cancelled);
        }
        match monitor.poll(&mut child, policy) {
            Ok(Some(output)) => {
                let _ = worker.join();
                if !output.status.success() {
                    // A failed direct child can leave helpers alive after closing stderr
                    stop_process_group(&child);
                }
                return Ok(output);
            }
            Ok(None) => thread::sleep(Duration::from_millis(3)),
            Err(error) => {
                stop_and_reap(&mut child);
                join_workers_after_stop([worker]);
                if matches!(error, ProcessError::TimedOut) {
                    return Err(ProcessError::ObjectExportTimeout(monitor.timeout_receipt()));
                }
                return Err(error);
            }
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
        }
    }

    fn poll(
        &mut self,
        child: &mut Child,
        policy: StreamingPolicy<'_>,
    ) -> Result<Option<StreamOutput>, ProcessError> {
        self.receive_diagnostics()?;
        self.poll_child(child)?;
        if Instant::now() >= policy.deadline {
            return Err(ProcessError::TimedOut);
        }
        if self.status.is_some() && self.diagnostics.is_some() {
            self.scan_objects(policy)?;
            if Instant::now() >= policy.deadline {
                return Err(ProcessError::TimedOut);
            }
            return self.finish().map(Some);
        }
        if Instant::now() >= self.next_scan {
            self.scan_objects(policy)?;
            self.next_scan = Instant::now() + Duration::from_millis(50);
            if Instant::now() >= policy.deadline {
                return Err(ProcessError::TimedOut);
            }
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

    fn poll_child(&mut self, child: &mut Child) -> Result<(), ProcessError> {
        if self.status.is_none() {
            self.status = child.try_wait().map_err(ProcessError::Read)?;
        }
        Ok(())
    }

    fn scan_objects(&mut self, policy: StreamingPolicy<'_>) -> Result<(), ProcessError> {
        match observe_object_tree(
            policy.object_root,
            policy.protocol_directory_count,
            policy.object_budget,
            &mut self.usage,
        ) {
            Ok(current_objects) => {
                self.stable_objects =
                    intersect_object_scans(&self.previous_objects, &current_objects);
                self.previous_objects = current_objects;
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
            stable_objects: std::mem::take(&mut self.stable_objects),
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
    root: &Path,
    protocol_directory_count: u64,
    budget: ObjectExportBudget,
    usage: &mut ObjectExportUsage,
) -> Result<Vec<StableObject>, ProcessError> {
    usage.temporary_scan_complete = false;
    let root_metadata = fs::symlink_metadata(root).map_err(ProcessError::Read)?;
    if !root_metadata.file_type().is_dir() {
        return Err(ProcessError::Read(io::Error::new(
            io::ErrorKind::InvalidData,
            "TShark object output root is not a directory",
        )));
    }

    let mut directories = vec![root.to_owned()];
    let maximum_entries = budget
        .temporary_files
        .checked_add(protocol_directory_count)
        .ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark object entry budget overflow"))
        })?;
    let mut scan = ObjectTreeScan::default();
    while let Some(directory) = directories.pop() {
        let entries = fs::read_dir(directory).map_err(ProcessError::Read)?;
        for entry in entries {
            let entry = entry.map_err(ProcessError::Read)?;
            observe_tree_entry(
                &entry,
                &mut directories,
                root,
                &mut scan,
                maximum_entries,
                budget,
                usage,
            )?;
        }
    }
    usage.temporary_bytes_peak = usage.temporary_bytes_peak.max(scan.bytes);
    usage.temporary_files_peak = usage.temporary_files_peak.max(scan.files);
    usage.temporary_scan_complete = true;
    scan.stable_objects
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(scan.stable_objects)
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
    directories: &mut Vec<std::path::PathBuf>,
    root: &Path,
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
    let metadata = fs::symlink_metadata(&path).map_err(ProcessError::Read)?;
    if metadata.file_type().is_dir() {
        if scan.entries > maximum_entries {
            return Err(tree_entry_limit(maximum_entries, scan.entries, usage));
        }
        directories.push(path);
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
    if let Some(relative_path) = eligible_object_path(root, &path)
        && let Some(snapshot) = ObjectFileSnapshot::from_metadata(&metadata)
    {
        scan.stable_objects.push(StableObject {
            relative_path,
            snapshot,
        });
    }
    Ok(())
}

fn eligible_object_path(root: &Path, path: &Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    let relative_path = path.strip_prefix(root).ok()?;
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
) -> Result<Child, ProcessError> {
    spawn_with_output(
        executable,
        arguments,
        environment,
        Stdio::piped(),
        Stdio::piped(),
    )
}

fn spawn_with_output(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, ProcessError> {
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
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(ProcessError::Spawn)
}

fn capture(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>, ProcessError> {
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|size| size.checked_add(1))
        .ok_or(ProcessError::OutputLimit)?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(ProcessError::Read)?;
    if bytes.len() > maximum {
        return Err(ProcessError::OutputLimit);
    }
    Ok(bytes)
}

fn stop_and_reap(child: &mut std::process::Child) {
    // A helper can keep stdout or stderr open after the direct child exits
    stop_process_group(child);
    let _ = child.kill();
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

fn stop_process_group(child: &std::process::Child) {
    #[cfg(unix)]
    if let Ok(process_group) = i32::try_from(child.id())
        && process_group > 1
    {
        // The run created this group specifically for the child and its descendants
        let _ = killpg(Pid::from_raw(process_group), Signal::SIGKILL);
    }
    #[cfg(not(unix))]
    let _ = child;
}
