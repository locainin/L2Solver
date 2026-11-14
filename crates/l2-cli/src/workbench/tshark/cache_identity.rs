//! Describe the selected `TShark` using bounded, non-authoritative metadata

use super::{
    executable::resolve_executable_in_search_path,
    process, sandbox,
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
    time::{Duration, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

const ARGUMENTS_EPOCH: u32 = 2;
const VERSION_ARGUMENTS: [&str; 2] = ["-n", "-v"];
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_STDOUT_MAXIMUM: usize = 4 * 1024;
const VERSION_STDERR_MAXIMUM: usize = 4 * 1024;

/// Return a cache identity even when `TShark` is absent or its version is unavailable
pub fn identity(job: Option<&Job>) -> Value {
    let search_path = env::var_os("PATH");
    identity_for_path(search_path.as_deref(), job)
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
    if job.is_some_and(Job::is_cancelled) {
        return json!({"status": "cancelled"});
    }
    let workspace = match Workspace::new(None) {
        Ok(workspace) => workspace,
        Err(error) => return unavailable_error("workspace_unavailable", &error),
    };
    let sandbox = match sandbox::Sandbox::new(&workspace, executable, None, None) {
        Ok(sandbox) => sandbox,
        Err(error) => return unavailable_error("sandbox_unavailable", &error),
    };
    let arguments = VERSION_ARGUMENTS.map(OsString::from);
    let launch = match sandbox.command(&arguments, &[], None) {
        Ok(launch) => launch,
        Err(error) => return unavailable_error("sandbox_unavailable", &error),
    };
    // Launch owns the descriptors used by the sandbox until the process exits
    let output = match process::run_with_job(
        &launch.executable,
        &launch.arguments,
        &launch.environment,
        VERSION_PROBE_TIMEOUT,
        VERSION_STDOUT_MAXIMUM,
        VERSION_STDERR_MAXIMUM,
        job,
    ) {
        Ok(output) => output,
        Err(process::ProcessError::Cancelled) => {
            return json!({"status": "cancelled"});
        }
        Err(process::ProcessError::TimedOut) => {
            return unavailable("timed_out");
        }
        Err(process::ProcessError::OutputLimit) => {
            return unavailable("output_limit");
        }
        Err(process::ProcessError::Spawn(error)) => {
            return unavailable_error("spawn_failed", &error);
        }
        Err(process::ProcessError::WorkerSpawn { source, .. }) => {
            return unavailable_error("worker_spawn_failed", &source);
        }
        Err(process::ProcessError::Read(error)) => {
            return unavailable_error("output_read_failed", &error);
        }
        Err(
            process::ProcessError::ObjectExportLimit(_)
            | process::ProcessError::ObjectExportTimeout(_),
        ) => {
            return unavailable("unexpected_process_result");
        }
    };

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
