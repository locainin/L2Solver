use super::{
    PROFILE, PreparedCapture,
    budget::{ObjectExportBudget, ObjectExportStatus, ObjectExportUsage, StableObject},
    prepare_export_capture, process,
    process::StreamingPolicy,
    run_phase, verify_executable_unchanged, verify_prepared_capture,
};
use l2_workbench::job::Job;

use std::{
    error::Error,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/objects.rs"]
mod tests;

/// Export-object directories kept alive with the capture snapshot and profile
pub struct ExportObjectSet {
    pub temporary_directory: tempfile::TempDir,
    pub directories: Vec<(String, PathBuf)>,
    /// Snapshot directories containing only post-termination-verified partial objects
    pub(crate) partial_directories: Vec<(String, PathBuf)>,
    pub source_identity: l2_workbench::tshark::SourceIdentity,
    pub budget: ObjectExportBudget,
    pub usage: ObjectExportUsage,
    pub status: ObjectExportStatus,
    pub issues: Vec<String>,
}

struct ObjectExportInvocation {
    directories: Vec<(String, PathBuf)>,
    arguments: Vec<OsString>,
}

struct PartialObjectSnapshot {
    directories: Vec<(String, PathBuf)>,
    omitted_unstable: bool,
}

struct PartialObjectExport {
    usage: ObjectExportUsage,
    issues: Vec<String>,
    directories: Vec<(String, PathBuf)>,
}

struct ResolvedObjectExport {
    usage: ObjectExportUsage,
    status: ObjectExportStatus,
    issues: Vec<String>,
    directories: Vec<(String, PathBuf)>,
    partial_directories: Vec<(String, PathBuf)>,
}

/// Export TShark objects with the shared isolated profile and cooperative cancellation state
pub fn export_objects_with_job(
    capture: &Path,
    temporary_parent: &Path,
    budget: ObjectExportBudget,
    job: Option<&Job>,
) -> Result<ExportObjectSet, Box<dyn Error>> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let mut prepared = prepare_export_capture(capture, temporary_parent)?;
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let types = available_types(&prepared)?;
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let object_root = prepared.directory.path().join("export-objects");
    fs::create_dir(&object_root)?;
    let invocation = build_object_arguments(&prepared, &object_root, types)?;

    let output = process::run_streaming(
        &prepared.executable,
        &invocation.arguments,
        &prepared.environment,
        StreamingPolicy {
            stderr_maximum: 16 * 1024,
            deadline: prepared.deadline,
            object_root: &object_root,
            protocol_directory_count: u64::try_from(invocation.directories.len())?,
            object_budget: budget,
            job,
        },
    );
    let resolved = resolve_object_export(
        output,
        &object_root,
        &prepared.directory.path().join("partial-export-objects"),
        invocation.directories,
    )?;
    verify_prepared_capture(&mut prepared)?;
    verify_executable_unchanged(
        &prepared.executable,
        prepared.executable_bytes,
        &prepared.executable_sha256,
    )?;

    Ok(ExportObjectSet {
        temporary_directory: prepared.directory,
        directories: resolved.directories,
        partial_directories: resolved.partial_directories,
        source_identity: prepared.source.identity.clone(),
        budget,
        usage: resolved.usage,
        status: resolved.status,
        issues: resolved.issues,
    })
}

fn resolve_object_export(
    output: Result<process::StreamOutput, process::ProcessError>,
    object_root: &Path,
    partial_root: &Path,
    complete_directories: Vec<(String, PathBuf)>,
) -> Result<ResolvedObjectExport, Box<dyn Error>> {
    let partial = match output {
        Ok(output) if output.status.success() => {
            return Ok(ResolvedObjectExport {
                usage: output.object_usage,
                status: ObjectExportStatus::Complete,
                issues: Vec::new(),
                directories: complete_directories,
                partial_directories: Vec::new(),
            });
        }
        Ok(output) => retain_partial_export(
            object_root,
            partial_root,
            output.object_usage,
            &output.stable_objects,
            describe_failed_export(&output),
        )?,
        Err(process::ProcessError::ObjectExportLimit(limit)) => retain_partial_export(
            object_root,
            partial_root,
            limit.usage,
            &limit.stable_objects,
            limit.describe(),
        )?,
        Err(process::ProcessError::ObjectExportTimeout(timeout)) => retain_partial_export(
            object_root,
            partial_root,
            timeout.usage,
            &timeout.stable_objects,
            timeout.describe(),
        )?,
        Err(error @ process::ProcessError::Cancelled) => return Err(error.into()),
        Err(error) => return Err(error.into()),
    };
    Ok(ResolvedObjectExport {
        usage: partial.usage,
        status: ObjectExportStatus::Partial,
        issues: partial.issues,
        directories: Vec::new(),
        partial_directories: partial.directories,
    })
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

fn retain_partial_export(
    object_root: &Path,
    snapshot_root: &Path,
    usage: ObjectExportUsage,
    stable_objects: &[StableObject],
    issue: String,
) -> Result<PartialObjectExport, Box<dyn Error>> {
    let snapshot = retain_stable_objects(object_root, snapshot_root, stable_objects)?;
    let mut issues = vec![issue];
    if snapshot.omitted_unstable {
        issues.push(String::from(
            "TShark objects that changed or failed identity checks at the budget stop were omitted",
        ));
    }
    Ok(PartialObjectExport {
        usage,
        issues,
        directories: snapshot.directories,
    })
}

/// Move only unchanged, private regular objects from the stopped process snapshot
fn retain_stable_objects(
    object_root: &Path,
    snapshot_root: &Path,
    stable_objects: &[StableObject],
) -> Result<PartialObjectSnapshot, Box<dyn Error>> {
    if stable_objects.is_empty() {
        return Ok(PartialObjectSnapshot {
            directories: Vec::new(),
            omitted_unstable: false,
        });
    }
    if !safe_directory(object_root) {
        return Ok(PartialObjectSnapshot {
            directories: Vec::new(),
            omitted_unstable: true,
        });
    }
    fs::create_dir(snapshot_root)?;
    let mut directories = std::collections::BTreeMap::<String, PathBuf>::new();
    let mut omitted_unstable = false;
    for object in stable_objects {
        if !move_stable_object(object_root, snapshot_root, object, &mut directories) {
            omitted_unstable = true;
        }
    }
    Ok(PartialObjectSnapshot {
        directories: directories.into_iter().collect(),
        omitted_unstable,
    })
}

fn move_stable_object(
    object_root: &Path,
    snapshot_root: &Path,
    object: &StableObject,
    directories: &mut std::collections::BTreeMap<String, PathBuf>,
) -> bool {
    let Some((protocol, filename)) = stable_object_path(&object.relative_path) else {
        return false;
    };
    let source_directory = object_root.join(&protocol);
    if !safe_directory(&source_directory) {
        return false;
    }
    let source_path = source_directory.join(&filename);
    let Ok(source_link_metadata) = fs::symlink_metadata(&source_path) else {
        return false;
    };
    if !object.snapshot.matches(&source_link_metadata) {
        return false;
    }
    let Ok(source) = open_stable_object(&source_path) else {
        return false;
    };
    let Ok(source_metadata) = source.metadata() else {
        return false;
    };
    if !object.snapshot.matches(&source_metadata) {
        return false;
    }

    let (destination_directory, new_directory) = if let Some(directory) = directories.get(&protocol)
    {
        (directory.clone(), false)
    } else {
        let directory = snapshot_root.join(&protocol);
        if fs::create_dir(&directory).is_err() {
            return false;
        }
        (directory, true)
    };
    let destination_path = destination_directory.join(&filename);
    if fs::rename(&source_path, &destination_path).is_err() {
        if new_directory {
            let _ = fs::remove_dir(&destination_directory);
        }
        return false;
    }
    // Moving avoids doubling temporary storage; the open handle checks the moved inode
    let source_matches = source
        .metadata()
        .is_ok_and(|metadata| object.snapshot.matches_after_move(&metadata));
    let destination_matches = fs::symlink_metadata(&destination_path)
        .is_ok_and(|metadata| object.snapshot.matches_after_move(&metadata));
    if !source_matches || !destination_matches {
        let _ = fs::remove_file(&destination_path);
        if new_directory {
            let _ = fs::remove_dir(&destination_directory);
        }
        return false;
    }
    directories.insert(protocol, destination_directory);
    true
}

fn stable_object_path(path: &Path) -> Option<(String, std::ffi::OsString)> {
    use std::path::Component;

    let mut components = path.components();
    let Component::Normal(protocol) = components.next()? else {
        return None;
    };
    let protocol = protocol.to_str()?;
    if validate_type(protocol).is_err() {
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
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let source = options.open(path)?;
    Ok(source)
}

fn build_object_arguments(
    prepared: &PreparedCapture,
    object_root: &Path,
    types: Vec<String>,
) -> Result<ObjectExportInvocation, Box<dyn Error>> {
    let mut directories = Vec::with_capacity(types.len());
    let mut arguments = vec![
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
        OsString::from("-r"),
        prepared.source.path.as_os_str().to_os_string(),
    ];
    for protocol in types {
        let directory = object_root.join(&protocol);
        fs::create_dir(&directory)?;
        let mut specification = OsString::from(&protocol);
        specification.push(",");
        specification.push(directory.as_os_str());
        arguments.extend([OsString::from("--export-objects"), specification]);
        directories.push((protocol, directory));
    }
    Ok(ObjectExportInvocation {
        directories,
        arguments,
    })
}

fn available_types(prepared: &PreparedCapture) -> Result<Vec<String>, Box<dyn Error>> {
    let arguments = [
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
        OsString::from("--export-objects"),
        OsString::from("help"),
    ];
    let output = run_phase(
        &prepared.executable,
        &arguments,
        &prepared.environment,
        prepared.deadline,
        prepared.metadata_maximum,
        prepared.diagnostic_maximum,
    )?;
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
    parse_types(&format!("{stdout}\n{stderr}"))
}

fn parse_types(output: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let Some(header) = output.lines().position(|line| {
        line.to_ascii_lowercase()
            .contains("available export object types")
    }) else {
        return Err("TShark did not list its export object types".into());
    };

    let mut types = Vec::new();
    for line in output.lines().skip(header + 1) {
        let protocol = line.trim();
        if protocol.is_empty() {
            if !types.is_empty() {
                break;
            }
            continue;
        }
        if validate_type(protocol).is_err() {
            if types.is_empty() {
                continue;
            }
            break;
        }
        if !types.iter().any(|known| known == protocol) {
            types.push(protocol.to_owned());
        }
    }
    if types.is_empty() {
        return Err("TShark returned no usable export object types".into());
    }
    Ok(types)
}

fn validate_type(protocol: &str) -> Result<(), Box<dyn Error>> {
    if !protocol.is_empty()
        && protocol
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        Ok(())
    } else {
        Err("TShark returned an unsafe export object type".into())
    }
}
