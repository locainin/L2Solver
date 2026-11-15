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
    io::{self, Read},
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
            status = match observe_exit(child) {
                Ok(status) => status,
                Err(error) => {
                    if !lost_child(&error) {
                        stop_and_reap(child);
                    }
                    join_workers_after_stop([stdout_worker, stderr_worker]);
                    return Err(ProcessError::Read(error));
                }
            };
        }
        if status.is_some() && stdout_result.is_some() && stderr_result.is_some() {
            let _ = stdout_worker.join();
            let _ = stderr_worker.join();
            // The waitable leader reserves its group until all capture helpers are signalled
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            stop_process_group(child).map_err(ProcessError::Read)?;
            #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
            let status = status.ok_or_else(|| {
                ProcessError::Read(io::Error::other("TShark exit status unavailable"))
            })?;
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            let status = child.wait().map_err(ProcessError::Read)?;
            return Ok(Output {
                stdout: stdout_result.unwrap_or_default(),
                stderr: stderr_result.unwrap_or_default(),
                status,
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
                #[cfg(not(all(target_os = "linux", not(target_env = "uclibc"))))]
                if !output.status.success() {
                    // A failed direct child can leave helpers alive after closing stderr
                    stop_process_group(&child).map_err(ProcessError::Read)?;
                }
                #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
                let output = StreamOutput {
                    status: child.wait().map_err(ProcessError::Read)?,
                    ..output
                };
                return Ok(output);
            }
            Ok(None) => thread::sleep(Duration::from_millis(3)),
            Err(error) => {
                if !matches!(&error, ProcessError::Read(source) if lost_child(source)) {
                    stop_and_reap(&mut child);
                }
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
            // Stop writers before the last scan while the leader still reserves the group ID
            #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
            stop_group_before_final_scan(child, policy)?;
            #[cfg(all(test, target_os = "linux", not(target_env = "uclibc")))]
            tests::before_final_scan();
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
        match observe_object_tree(
            policy.object_root,
            policy.protocol_directory_count,
            policy.object_budget,
            &mut self.usage,
        ) {
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
) -> Result<ObjectTreeScan, ProcessError> {
    usage.temporary_scan_complete = false;
    let root_directory = open_tree_directory(root).map_err(ProcessError::Read)?;
    let mut directories = vec![(std::path::PathBuf::new(), root_directory)];
    let maximum_entries = budget
        .temporary_files
        .checked_add(protocol_directory_count)
        .ok_or_else(|| {
            ProcessError::Read(io::Error::other("TShark object entry budget overflow"))
        })?;
    let mut scan = ObjectTreeScan::default();
    while let Some((relative_directory, directory)) = directories.pop() {
        // Each descriptor pins its directory even if the child replaces its name
        let directory_path = tree_directory_source(&directory).map_err(ProcessError::Read)?;
        let entries = fs::read_dir(directory_path).map_err(ProcessError::Read)?;
        for entry in entries {
            let entry = entry.map_err(ProcessError::Read)?;
            observe_tree_entry(
                &entry,
                &mut directories,
                &relative_directory,
                &mut scan,
                maximum_entries,
                budget,
                usage,
            )?;
            #[cfg(all(test, target_os = "linux"))]
            tests::after_tree_entry();
        }
    }
    usage.temporary_bytes_peak = usage.temporary_bytes_peak.max(scan.bytes);
    usage.temporary_files_peak = usage.temporary_files_peak.max(scan.files);
    usage.temporary_scan_complete = true;
    scan.stable_objects
        .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
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
        .stdin(Stdio::null())
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
