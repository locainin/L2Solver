use super::{
    budget::{ObjectExportBudget, ObjectExportStatus, ObjectExportUsage, StableObject},
    executable::verify_executable_unchanged,
    inspection::{inspect_preferences, inspect_version},
    phase::run_phase,
    preparation::{PreparedCapture, prepare_export_capture, verify_prepared_capture},
    process,
    process::StreamingPolicy,
    profile::PROFILE,
    secure_files::Workspace,
    snapshot::HashControl,
};
use l2_workbench::job::Job;

use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/objects.rs"]
mod tests;

/// Export-object directories kept alive with the capture snapshot and profile
pub struct ExportObjectSet {
    pub temporary_directory: Workspace,
    /// Snapshot directories containing only post-termination-verified objects
    pub directories: Vec<(String, PathBuf)>,
    pub source_identity: l2_workbench::tshark::SourceIdentity,
    pub budget: ObjectExportBudget,
    pub usage: ObjectExportUsage,
    pub status: ObjectExportStatus,
    pub issues: Vec<String>,
    pub containment: Option<l2_workbench::tshark::ScopeReceipt>,
}

struct ObjectExportInvocation {
    protocols: Vec<String>,
    arguments: Vec<OsString>,
}

struct PartialObjectSnapshot {
    directories: Vec<(String, PathBuf)>,
    omitted_unstable: bool,
    deadline_reached: bool,
}

struct ResolvedObjectExport {
    usage: ObjectExportUsage,
    status: ObjectExportStatus,
    issues: Vec<String>,
    directories: Vec<(String, PathBuf)>,
}

/// Export `TShark` objects with the shared isolated profile and cooperative cancellation state
pub fn export_objects_with_job(
    capture: &Path,
    indexed: &super::super::full_source::IndexedSource,
    temporary_parent: &Path,
    budget: ObjectExportBudget,
    job: Option<&Job>,
) -> Result<ExportObjectSet, Box<dyn Error>> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let mut prepared = prepare_indexed_capture(capture, indexed, temporary_parent, budget, job)?;
    let budget = ObjectExportBudget {
        temporary_bytes: prepared.resources.limits().object_bytes.get(),
        temporary_files: prepared.resources.limits().object_files.get(),
    };
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    inspect_version(&prepared)?;
    inspect_preferences(&prepared)?;
    let types = available_types(&prepared)?;
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let object_root = prepared.directory.path().join("export-objects");
    let invocation = build_object_arguments(&prepared, &object_root, types);
    let mut launch = prepared.sandbox.command(
        &invocation.arguments,
        &prepared.environment,
        Some(&invocation.protocols),
    )?;

    let output = process::run_streaming_launch(
        &mut launch,
        StreamingPolicy {
            stderr_maximum: 16 * 1024,
            deadline: prepared.deadline,
            object_root: &object_root,
            protocol_directory_count: u64::try_from(invocation.protocols.len())?,
            object_budget: budget,
            job,
        },
    );
    let (resolved, containment) = resolve_launched_export(
        &prepared,
        &launch,
        output,
        object_root,
        invocation.protocols,
        job,
    )?;
    verify_prepared_capture(&mut prepared, job)?;
    verify_executable_unchanged(
        &mut prepared.executable.file,
        prepared.executable_bytes,
        &prepared.executable_sha256,
        HashControl {
            deadline: prepared.deadline,
            job,
        },
    )?;
    Ok(ExportObjectSet {
        temporary_directory: prepared.directory,
        directories: resolved.directories,
        source_identity: prepared.source.identity.clone(),
        budget,
        usage: resolved.usage,
        status: resolved.status,
        issues: resolved.issues,
        containment,
    })
}

fn prepare_indexed_capture(
    capture: &Path,
    indexed: &super::super::full_source::IndexedSource,
    temporary_parent: &Path,
    budget: ObjectExportBudget,
    job: Option<&Job>,
) -> Result<PreparedCapture, Box<dyn Error>> {
    let mut source_file = indexed.store.open_retained_source(&indexed.receipt)?;
    let identity = l2_workbench::tshark::SourceIdentity {
        label: super::super::label(capture, "capture").to_owned(),
        length: indexed.receipt.bytes,
        sha256: indexed
            .receipt
            .source_id
            .strip_prefix("sha256:")
            .ok_or("indexed source identity lacks its SHA-256 prefix")?
            .to_owned(),
    };
    prepare_export_capture(
        capture,
        &mut source_file,
        &identity,
        temporary_parent,
        budget,
        job,
    )
}

fn resolve_launched_export(
    prepared: &PreparedCapture,
    launch: &super::sandbox::Launch,
    output: Result<process::StreamOutput, process::ProcessError>,
    object_root: PathBuf,
    protocols: Vec<String>,
    job: Option<&Job>,
) -> Result<
    (
        ResolvedObjectExport,
        Option<l2_workbench::tshark::ScopeReceipt>,
    ),
    Box<dyn Error>,
> {
    #[cfg(not(target_os = "linux"))]
    let _ = launch;
    #[cfg(target_os = "linux")]
    let pinned_root = launch
        .output_storage
        .as_ref()
        .map(super::output_storage::OutputStorage::path)
        .transpose()?;
    #[cfg(not(target_os = "linux"))]
    let pinned_root: Option<PathBuf> = None;
    if output.is_ok() && pinned_root.is_none() {
        return Err("TShark object output mount was not pinned".into());
    }
    let object_root = pinned_root.unwrap_or(object_root);
    let directories = protocols
        .into_iter()
        .map(|protocol| {
            let path = object_root.join(&protocol);
            (protocol, path)
        })
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let output_full = launch
        .output_storage
        .as_ref()
        .map(super::output_storage::OutputStorage::is_full)
        .transpose()?
        .unwrap_or(false);
    #[cfg(not(target_os = "linux"))]
    let output_full = false;
    #[cfg(target_os = "linux")]
    let containment = launch
        .scope
        .as_ref()
        .and_then(super::resource_scope::Gate::receipt);
    #[cfg(not(target_os = "linux"))]
    let containment = None;
    let mut resolved = resolve_object_export(
        output,
        &object_root,
        &prepared.directory.path().join("partial-export-objects"),
        &directories,
        prepared.deadline,
        job,
        containment.as_ref(),
    )?;
    if output_full {
        resolved.status = ObjectExportStatus::Partial;
        resolved.issues.push(String::from(
            "TShark object output filesystem reached its capacity; output may be incomplete",
        ));
    }
    Ok((resolved, containment))
}

fn resolve_object_export(
    output: Result<process::StreamOutput, process::ProcessError>,
    object_root: &Path,
    partial_root: &Path,
    complete_directories: &[(String, PathBuf)],
    deadline: Instant,
    job: Option<&Job>,
    containment: Option<&l2_workbench::tshark::ScopeReceipt>,
) -> Result<ResolvedObjectExport, Box<dyn Error>> {
    let retain_partial = |usage: ObjectExportUsage,
                          stable_objects: &[StableObject],
                          issue: String|
     -> Result<ResolvedObjectExport, Box<dyn Error>> {
        let snapshot = retain_stable_objects(
            object_root,
            partial_root,
            stable_objects,
            complete_directories,
            deadline,
            job,
        )?;
        let mut issues = vec![issue];
        if snapshot.omitted_unstable {
            issues.push(String::from(
                "TShark objects that changed or failed identity checks at the budget stop were omitted",
            ));
        }
        add_snapshot_timeout(&mut issues, snapshot.deadline_reached);
        Ok(ResolvedObjectExport {
            usage,
            status: ObjectExportStatus::Partial,
            issues,
            directories: snapshot.directories,
        })
    };
    let resolved: Result<ResolvedObjectExport, Box<dyn Error>> = match output {
        Ok(output) if output.status.success() => retain_complete_export(
            &output,
            object_root,
            partial_root,
            complete_directories,
            deadline,
            job,
        ),
        Ok(output) => retain_partial(
            output.object_usage,
            &output.objects,
            describe_failed_export(&output),
        ),
        Err(process::ProcessError::ObjectExportLimit(limit)) => {
            retain_partial(limit.usage, &limit.stable_objects, limit.describe())
        }
        Err(process::ProcessError::ObjectExportTimeout(timeout)) => {
            retain_partial(timeout.usage, &timeout.stable_objects, timeout.describe())
        }
        // Keep cancellation typed when returning through the recovery job
        Err(process::ProcessError::Cancelled) => Err(l2_workbench::job::JobError::Cancelled.into()),
        Err(error) => Err(error.into()),
    };
    let mut resolved = resolved?;
    note_resource_limits(&mut resolved, containment);
    Ok(resolved)
}

fn retain_complete_export(
    output: &process::StreamOutput,
    object_root: &Path,
    partial_root: &Path,
    directories: &[(String, PathBuf)],
    deadline: Instant,
    job: Option<&Job>,
) -> Result<ResolvedObjectExport, Box<dyn Error>> {
    let valid_directories = safe_directory(object_root)
        && directories.iter().all(|(protocol, directory)| {
            valid_type(protocol)
                && *directory == object_root.join(protocol)
                && safe_directory(directory)
        });
    let snapshot = retain_stable_objects(
        object_root,
        partial_root,
        &output.objects,
        directories,
        deadline,
        job,
    )?;
    // Only the private snapshot may be used after validating the final tree
    let mut issues = Vec::new();
    if !valid_directories || output.unsafe_entries || snapshot.omitted_unstable {
        issues.push(String::from(
            "TShark object output contained unsafe or changed entries",
        ));
    }
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    if output.stderr_truncated
        || diagnostic.lines().any(|line| {
            line.contains("/output/")
                || line.contains("Failed to create export objects output directory")
                || (line.contains("Can't register ") && line.contains(" tap:"))
        })
    {
        let mut issue =
            String::from("TShark object export diagnostics indicate output may be incomplete");
        if !diagnostic.trim().is_empty() {
            issue.push_str(": ");
            issue.push_str(diagnostic.trim());
        }
        if output.stderr_truncated {
            issue.push_str(" [diagnostic output truncated]");
        }
        issues.push(issue);
    }
    add_snapshot_timeout(&mut issues, snapshot.deadline_reached);
    let status = if issues.is_empty() {
        ObjectExportStatus::Complete
    } else {
        ObjectExportStatus::Partial
    };
    Ok(ResolvedObjectExport {
        usage: output.object_usage,
        status,
        issues,
        directories: snapshot.directories,
    })
}

fn note_resource_limits(
    resolved: &mut ResolvedObjectExport,
    containment: Option<&l2_workbench::tshark::ScopeReceipt>,
) {
    let resource_issue = match containment.and_then(process::resource_limit) {
        Some(process::ResourceLimit::Memory) => {
            Some("TShark object export reached an out-of-memory condition in its resource scope")
        }
        Some(process::ResourceLimit::Tasks) => {
            Some("TShark object export reached the task limit in its resource scope")
        }
        None => None,
    };
    if let Some(issue) = resource_issue {
        resolved.status = ObjectExportStatus::Partial;
        resolved.issues.push(issue.to_owned());
    }
    let counters_available = containment
        .and_then(|receipt| receipt.usage)
        .is_some_and(|usage| {
            (usage.observed_after_stop || usage.observed_while_frozen)
                && usage.memory_events.is_some()
                && usage.tasks_max_events.is_some()
        });
    if !counters_available {
        resolved.status = ObjectExportStatus::Partial;
        resolved.issues.push(String::from(
            "TShark resource event counters unavailable; output completeness could not be verified",
        ));
    }
}

fn describe_failed_export(output: &process::StreamOutput) -> String {
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    let mut failure = format!(
        "TShark object export failed with exit status {}",
        output.status
    );
    if !diagnostic.trim().is_empty() {
        failure.push_str(": ");
        failure.push_str(diagnostic.trim());
    }
    if output.stderr_truncated {
        failure.push_str(" [diagnostic output truncated]");
    }
    failure
}

fn add_snapshot_timeout(issues: &mut Vec<String>, deadline_reached: bool) {
    if deadline_reached {
        issues.push(String::from(
            "TShark object snapshot stopped at its time budget; remaining objects were omitted",
        ));
    }
}

/// Copy only unchanged, private regular objects from the stopped process snapshot
fn retain_stable_objects(
    object_root: &Path,
    snapshot_root: &Path,
    stable_objects: &[StableObject],
    allowed_directories: &[(String, PathBuf)],
    deadline: Instant,
    job: Option<&Job>,
) -> Result<PartialObjectSnapshot, Box<dyn Error>> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    if stable_objects.is_empty() {
        return Ok(PartialObjectSnapshot {
            directories: Vec::new(),
            omitted_unstable: false,
            deadline_reached: false,
        });
    }
    if Instant::now() >= deadline {
        return Ok(PartialObjectSnapshot {
            directories: Vec::new(),
            omitted_unstable: false,
            deadline_reached: true,
        });
    }
    if !safe_directory(object_root) {
        return Ok(PartialObjectSnapshot {
            directories: Vec::new(),
            omitted_unstable: true,
            deadline_reached: false,
        });
    }
    fs::create_dir(snapshot_root)?;
    let mut directories = std::collections::BTreeMap::<String, PathBuf>::new();
    let mut omitted_unstable = false;
    let mut deadline_reached = false;
    for object in stable_objects {
        match copy_stable_object(
            object_root,
            snapshot_root,
            object,
            allowed_directories,
            &mut directories,
            deadline,
            job,
        )? {
            CopyOutcome::Copied => {}
            CopyOutcome::Changed => omitted_unstable = true,
            CopyOutcome::Deadline => {
                deadline_reached = true;
                break;
            }
        }
    }
    Ok(PartialObjectSnapshot {
        directories: directories.into_iter().collect(),
        omitted_unstable,
        deadline_reached,
    })
}

enum CopyOutcome {
    Copied,
    Changed,
    Deadline,
}

fn copy_stable_object(
    object_root: &Path,
    snapshot_root: &Path,
    object: &StableObject,
    allowed_directories: &[(String, PathBuf)],
    directories: &mut std::collections::BTreeMap<String, PathBuf>,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<CopyOutcome, Box<dyn Error>> {
    if !copy_has_time(deadline, job)? {
        return Ok(CopyOutcome::Deadline);
    }
    let Some((protocol, filename)) = stable_object_path(&object.relative_path) else {
        return Ok(CopyOutcome::Changed);
    };
    let source_directory = object_root.join(&protocol);
    if !allowed_directories
        .iter()
        .any(|(allowed_protocol, path)| allowed_protocol == &protocol && path == &source_directory)
    {
        return Ok(CopyOutcome::Changed);
    }
    if !safe_directory(&source_directory) {
        return Ok(CopyOutcome::Changed);
    }
    let source_path = source_directory.join(&filename);
    let Ok(source_link_metadata) = fs::symlink_metadata(&source_path) else {
        return Ok(CopyOutcome::Changed);
    };
    if !object.snapshot.matches(&source_link_metadata) {
        return Ok(CopyOutcome::Changed);
    }
    let Ok(mut source) = open_stable_object(&source_path) else {
        return Ok(CopyOutcome::Changed);
    };
    let Ok(source_metadata) = source.metadata() else {
        return Ok(CopyOutcome::Changed);
    };
    if !object.snapshot.matches(&source_metadata) {
        return Ok(CopyOutcome::Changed);
    }

    let (destination_directory, new_directory) = if let Some(directory) = directories.get(&protocol)
    {
        (directory.clone(), false)
    } else {
        let directory = snapshot_root.join(&protocol);
        fs::create_dir(&directory)?;
        (directory, true)
    };
    let destination_path = destination_directory.join(&filename);
    let mut destination_options = OpenOptions::new();
    destination_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        destination_options.mode(0o600);
    }
    let mut destination = destination_options.open(&destination_path)?;
    // Never read beyond the length verified by the completed tree scan
    let copied = copy_object_data(
        &mut source,
        &mut destination,
        source_metadata.len(),
        deadline,
        job,
    );
    drop(destination);
    let source_matches = source
        .metadata()
        .is_ok_and(|metadata| object.snapshot.matches(&metadata))
        && fs::symlink_metadata(&source_path)
            .is_ok_and(|metadata| object.snapshot.matches(&metadata));
    if !matches!(copied, Ok(CopyOutcome::Copied)) || !source_matches {
        let _ = fs::remove_file(&destination_path);
        if new_directory {
            let _ = fs::remove_dir(&destination_directory);
        }
        return match copied {
            Ok(CopyOutcome::Copied) => Ok(CopyOutcome::Changed),
            other => other,
        };
    }
    directories.insert(protocol, destination_directory);
    Ok(CopyOutcome::Copied)
}

fn copy_has_time(deadline: Instant, job: Option<&Job>) -> Result<bool, Box<dyn Error>> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    Ok(Instant::now() < deadline)
}

fn copy_object_data(
    source: &mut File,
    destination: &mut File,
    mut remaining: u64,
    deadline: Instant,
    job: Option<&Job>,
) -> Result<CopyOutcome, Box<dyn Error>> {
    let mut buffer = crate::input::io_buffer()?;
    if !copy_has_time(deadline, job)? {
        return Ok(CopyOutcome::Deadline);
    }
    while remaining != 0 {
        if !copy_has_time(deadline, job)? {
            return Ok(CopyOutcome::Deadline);
        }
        let count = usize::try_from(remaining.min(u64::try_from(buffer.len())?))?;
        let target = buffer
            .get_mut(..count)
            .ok_or("invalid object copy buffer")?;
        let read = match source.read(target) {
            Ok(0) => return Ok(CopyOutcome::Changed),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = buffer.get(..read).ok_or("invalid object copy length")?;
        while !bytes.is_empty() {
            if !copy_has_time(deadline, job)? {
                return Ok(CopyOutcome::Deadline);
            }
            let written = match destination.write(bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            bytes = bytes.get(written..).ok_or("invalid object write length")?;
        }
        remaining -= u64::try_from(read)?;
    }
    Ok(CopyOutcome::Copied)
}

fn stable_object_path(path: &Path) -> Option<(String, std::ffi::OsString)> {
    use std::path::Component;

    let mut components = path.components();
    let Component::Normal(protocol) = components.next()? else {
        return None;
    };
    let protocol = protocol.to_str()?;
    if !valid_type(protocol) {
        return None;
    }
    let Component::Normal(filename) = components.next()? else {
        return None;
    };
    if components.next().is_some() {
        return None;
    }
    Some((protocol.to_owned(), filename.to_owned()))
}

fn safe_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn open_stable_object(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let source = options.open(path)?;
    Ok(source)
}

fn build_object_arguments(
    prepared: &PreparedCapture,
    object_root: &Path,
    types: Vec<String>,
) -> ObjectExportInvocation {
    let mut arguments = vec![
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
        OsString::from("-r"),
        prepared.source.path.as_os_str().to_os_string(),
    ];
    for protocol in &types {
        let directory = object_root.join(protocol);
        let mut specification = OsString::from(protocol);
        specification.push(",");
        specification.push(directory.as_os_str());
        arguments.extend([OsString::from("--export-objects"), specification]);
    }
    ObjectExportInvocation {
        protocols: types,
        arguments,
    }
}

fn available_types(prepared: &PreparedCapture) -> Result<Vec<String>, Box<dyn Error>> {
    let arguments = [
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
        OsString::from("--export-objects"),
        OsString::from("help"),
    ];
    let output = run_phase(prepared, &arguments, prepared.metadata_maximum)?;
    if !output.status.success() {
        let mut failure = format!(
            "TShark export-object type discovery failed with exit status {}",
            output.status
        );
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        if !diagnostic.trim().is_empty() {
            failure.push_str(": ");
            failure.push_str(diagnostic.trim());
        }
        return Err(failure.into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(parse_types(&format!("{stdout}\n{stderr}"))?)
}

#[derive(Debug, Eq, PartialEq)]
enum InventoryError {
    MissingHeader,
    Empty,
    InvalidType,
}

impl std::fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingHeader => "TShark did not list its export object types",
            Self::Empty => "TShark returned no usable export object types",
            Self::InvalidType => "TShark returned an unsafe export object type",
        })
    }
}

impl Error for InventoryError {}

fn parse_types(output: &str) -> Result<Vec<String>, InventoryError> {
    let Some(header) = output.lines().position(|line| {
        line.to_ascii_lowercase()
            .contains("available export object types")
    }) else {
        return Err(InventoryError::MissingHeader);
    };

    let mut types = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in output.lines().skip(header + 1) {
        let protocol = line.trim();
        if protocol.is_empty() {
            continue;
        }
        // Upstream emits no footer, so every nonblank line must be a type
        if !valid_type(protocol) {
            return Err(InventoryError::InvalidType);
        }
        if seen.insert(protocol) {
            types.push(protocol.to_owned());
        }
    }
    if types.is_empty() {
        return Err(InventoryError::Empty);
    }
    Ok(types)
}

pub(super) fn valid_type(protocol: &str) -> bool {
    !protocol.is_empty()
        && protocol
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
