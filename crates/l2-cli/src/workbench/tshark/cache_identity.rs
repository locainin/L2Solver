//! Describe the selected `TShark` using bounded, non-authoritative metadata

use super::{
    executable::resolve_executable_in_search_path,
    process, resources, sandbox,
    secure_files::{VerifiedExecutable, Workspace},
    version,
};
use l2_workbench::job::Job;
use serde_json::{Value, json};
use std::{
    env,
    ffi::{OsStr, OsString},
    fs, io,
    path::Path,
    time::{Duration, Instant, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

const ARGUMENTS_EPOCH: u32 = 3;
const VERSION_ARGUMENTS: [&str; 2] = ["-n", "-v"];
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_STDOUT_MAXIMUM: usize = 4 * 1024;
const VERSION_STDERR_MAXIMUM: usize = 4 * 1024;

/// Return a cache identity even when `TShark` is absent or its version is unavailable
pub fn identity(job: Option<&Job>) -> Value {
    let search_path = env::var_os("PATH");
    let mut identity = identity_for_path(search_path.as_deref(), job);
    let configuration =
        resources::operator_configuration(Some(super::ObjectExportBudget::DEFAULT), env::var_os);
    let requests = match configuration {
        Ok(configuration) => configuration_identity(configuration),
        Err(error) => json!({"error": error.to_string()}),
    };
    let Some(fields) = identity.as_object_mut() else {
        return json!({"arguments_epoch": ARGUMENTS_EPOCH, "resource_requests": requests, "error": "invalid TShark identity"});
    };
    fields.insert("resource_requests".to_owned(), requests);
    identity
}

fn configuration_identity(configuration: resources::OperatorConfiguration) -> Value {
    json!({
        "memory_bytes": configuration.memory_bytes,
        "swap_bytes": configuration.swap_bytes,
        "tasks": configuration.tasks,
        "temporary_bytes": configuration.temporary_bytes,
        "tmp_bytes": configuration.tmp_bytes,
        "shm_bytes": configuration.shm_bytes,
        "object_bytes": configuration.objects.map(|request| request.budget.temporary_bytes),
        "object_files": configuration.objects.map(|request| request.budget.temporary_files),
        "object_explicit": configuration.objects.map(|request| request.mode == l2_workbench::job::ObjectLimitMode::Explicit),
    })
}

fn identity_for_path(search_path: Option<&OsStr>, job: Option<&Job>) -> Value {
    let Some(search_path) = search_path else {
        let executable = json!({"status": "missing"});
        let version = unavailable("path_unset");
        return cache_identity(&executable, &version);
    };

    // Use the same PATH selection and executable check as TShark workbench commands
    let executable = match resolve_executable_in_search_path(Path::new("tshark"), search_path) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let executable = json!({"status": "missing"});
            let version = unavailable("executable_not_found");
            return cache_identity(&executable, &version);
        }
        Err(error) => {
            let executable = json!({
                "status": "selection_failed",
                "error_kind": format!("{:?}", error.kind())
            });
            let version = unavailable("selection_failed");
            return cache_identity(&executable, &version);
        }
    };

    // The privilege gate applies before even a version probe may start
    if let Err(error) = sandbox::check_privileges() {
        let executable = json!({
            "status": "verification_unavailable",
            "path_hex": encode_path(&executable),
            "error_kind": format!("{:?}", error.kind())
        });
        let version = if job.is_some_and(Job::is_cancelled) {
            json!({"status": "cancelled"})
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            unavailable("privileged_context")
        } else {
            unavailable("sandbox_unavailable")
        };
        return cache_identity(&executable, &version);
    }

    let verified = match VerifiedExecutable::open(&executable) {
        Ok(verified) => verified,
        Err(error) => {
            let executable_metadata = json!({
                "status": "verification_failed",
                "path_hex": encode_path(&executable),
                "error_kind": format!("{:?}", error.kind())
            });
            let version = unavailable("verification_failed");
            return cache_identity(&executable_metadata, &version);
        }
    };
    let metadata = match verified.file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            let executable_metadata = json!({
                "status": "metadata_unavailable",
                "path_hex": encode_path(&executable),
                "error_kind": format!("{:?}", error.kind())
            });
            let version = unavailable("metadata_unavailable");
            return cache_identity(&executable_metadata, &version);
        }
    };

    // File metadata keeps this lookup quick; it does not claim to be a content hash
    let executable_metadata = executable_metadata(&verified.path, &metadata);
    let version = version_identity(&verified, job);
    cache_identity(&executable_metadata, &version)
}

fn cache_identity(executable: &Value, version: &Value) -> Value {
    json!({
        "schema_version": 1,
        "trust": "fast_metadata_hint",
        "arguments_epoch": ARGUMENTS_EPOCH,
        "version_arguments": VERSION_ARGUMENTS,
        "executable": executable,
        "version": version
    })
}

fn executable_metadata(path: &Path, metadata: &fs::Metadata) -> Value {
    let modified = metadata.modified().ok().and_then(|time| {
        time.duration_since(UNIX_EPOCH).ok().map(|duration| {
            json!({
                "seconds": duration.as_secs(),
                "nanoseconds": duration.subsec_nanos()
            })
        })
    });
    let mut value = json!({
        "status": "selected",
        "path_hex": encode_path(path),
        "path_encoding": path_encoding(),
        "length": metadata.len(),
        "modified_unix": modified
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if let Some(fields) = value.as_object_mut() {
            fields.insert("device".to_owned(), json!(metadata.dev()));
            fields.insert("inode".to_owned(), json!(metadata.ino()));
        }
    }

    value
}

fn version_identity(executable: &VerifiedExecutable, job: Option<&Job>) -> Value {
    let Some(deadline) = Instant::now().checked_add(VERSION_PROBE_TIMEOUT) else {
        return unavailable("timed_out");
    };
    if job.is_some_and(Job::is_cancelled) {
        return json!({"status": "cancelled"});
    }
    let Ok(parent_bytes) = u64::try_from(VERSION_STDOUT_MAXIMUM + VERSION_STDERR_MAXIMUM) else {
        return unavailable("resource_plan_unavailable");
    };
    let ceiling = match resources::job_ceiling(job, parent_bytes) {
        Ok(ceiling) => ceiling,
        Err(error) => {
            return json!({"status":"unavailable", "reason":"resource_plan_unavailable", "error":error.to_string()});
        }
    };
    let configuration = match resources::operator_configuration(None, env::var_os) {
        Ok(configuration) => configuration,
        Err(error) => {
            return json!({"status":"unavailable", "reason":"resource_plan_unavailable", "error":error.to_string()});
        }
    };
    let (plan, parent) = match resources::resolve(
        None,
        l2_workbench::job::InputSize {
            capture_bytes: Some(0),
            keylog_bytes: 0,
        },
        None,
        configuration,
        VERSION_PROBE_TIMEOUT,
        ceiling,
        parent_bytes,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return json!({"status":"unavailable", "reason":"resource_plan_unavailable", "error":error.to_string()});
        }
    };
    let _reservation = match resources::reserve(job, &plan, parent_bytes) {
        Ok(reservation) => reservation,
        Err(error) => {
            return json!({"status":"unavailable", "reason":"resource_plan_unavailable", "error":error.to_string()});
        }
    };
    let workspace = match Workspace::in_parent(parent) {
        Ok(workspace) => workspace,
        Err(error) => return unavailable_error("workspace_unavailable", &error),
    };
    let sandbox = match sandbox::Sandbox::new(&workspace, executable, None, None, &plan, deadline) {
        Ok(sandbox) => sandbox,
        Err(error) => return unavailable_error("sandbox_unavailable", &error),
    };
    let arguments = VERSION_ARGUMENTS.map(OsString::from);
    let mut launch = match sandbox.command(&arguments, &[], None) {
        Ok(launch) => launch,
        Err(error) => return unavailable_error("sandbox_unavailable", &error),
    };
    // Launch owns the descriptors used by the sandbox until the process exits
    let output = match process::run_launch(
        &mut launch,
        deadline.saturating_duration_since(Instant::now()),
        VERSION_STDOUT_MAXIMUM,
        VERSION_STDERR_MAXIMUM,
        job,
    ) {
        Ok(output) => output,
        Err(error) => return process_unavailable(&error),
    };

    version_output(&output)
}

fn version_output(output: &process::Output) -> Value {
    if !output.status.success() {
        return json!({
            "status": "unavailable",
            "reason": "nonzero_exit",
            "exit_code": output.status.code()
        });
    }

    let version = match std::str::from_utf8(&output.stdout) {
        Ok(text) => text.lines().next().map(str::trim).unwrap_or_default(),
        Err(_) => return unavailable("invalid_utf8"),
    };
    if version.is_empty() {
        unavailable("empty_version")
    } else if version::validate(version).is_err() {
        unavailable("unsupported_version")
    } else {
        json!({"status": "available", "public_version": version})
    }
}

fn process_unavailable(error: &process::ProcessError) -> Value {
    use process::ProcessError;
    match error {
        ProcessError::Cancelled => json!({"status":"cancelled"}),
        ProcessError::TimedOut => unavailable("timed_out"),
        ProcessError::OutputLimit => unavailable("output_limit"),
        ProcessError::Spawn(error) => unavailable_error("spawn_failed", error),
        ProcessError::WorkerSpawn { source, .. } => {
            unavailable_error("worker_spawn_failed", source)
        }
        ProcessError::Read(error) => unavailable_error("output_read_failed", error),
        ProcessError::Containment(error) => unavailable_error("containment_unavailable", error),
        ProcessError::MemoryLimit(receipt) => {
            json!({"status":"unavailable", "reason":"memory_limit", "containment":receipt})
        }
        ProcessError::TaskLimit(receipt) => {
            json!({"status":"unavailable", "reason":"task_limit", "containment":receipt})
        }
        ProcessError::ScopeCleanup { .. } => {
            json!({"status":"unavailable", "reason":"containment_cleanup_failed", "error":error.to_string()})
        }
        ProcessError::ObjectExportLimit(_) | ProcessError::ObjectExportTimeout(_) => {
            unavailable("unexpected_process_result")
        }
    }
}

fn unavailable(reason: &str) -> Value {
    json!({"status": "unavailable", "reason": reason})
}

fn unavailable_error(reason: &str, error: &io::Error) -> Value {
    json!({"status": "unavailable", "reason": reason, "error_kind": format!("{:?}", error.kind())})
}

fn encode_path(path: &Path) -> String {
    // Hex preserves non-UTF-8 paths without lossy JSON conversion
    let mut encoded = String::new();
    for byte in path_bytes(path.as_os_str()) {
        encoded.push(char::from(hex_digit(byte >> 4)));
        encoded.push(char::from(hex_digit(byte & 0x0f)));
    }
    encoded
}

#[cfg(unix)]
const fn path_encoding() -> &'static str {
    "unix_bytes"
}

#[cfg(windows)]
const fn path_encoding() -> &'static str {
    "windows_utf16le"
}

#[cfg(not(any(unix, windows)))]
const fn path_encoding() -> &'static str {
    "lossy_utf8"
}

const fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

#[cfg(unix)]
fn path_bytes(path: &OsStr) -> Vec<u8> {
    path.as_bytes().to_vec()
}

#[cfg(windows)]
fn path_bytes(path: &OsStr) -> Vec<u8> {
    path.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, windows)))]
fn path_bytes(path: &OsStr) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/cache_identity.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../../tests/workbench/tshark/cache_identity_security.rs"]
mod security_tests;
