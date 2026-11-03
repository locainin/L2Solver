//! Describe the selected `TShark` using bounded, non-authoritative metadata

use super::{process, resolve_executable_in_search_path};
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

const ARGUMENTS_EPOCH: u32 = 1;
const VERSION_ARGUMENTS: [&str; 2] = ["-n", "-v"];
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_STDOUT_MAXIMUM: usize = 4 * 1024;
const VERSION_STDERR_MAXIMUM: usize = 4 * 1024;

/// Return a cache identity even when `TShark` is absent or its version is unavailable
pub(super) fn identity(job: Option<&Job>) -> Value {
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

    let metadata = match fs::metadata(&executable) {
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
    let executable_metadata = executable_metadata(&executable, &metadata);
    let version = version_identity(&executable, job);
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

fn version_identity(executable: &Path, job: Option<&Job>) -> Value {
    let arguments = VERSION_ARGUMENTS.map(OsString::from);
    let output = match process::run_with_job(
        executable,
        &arguments,
        &[],
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
            return json!({
                "status": "unavailable",
                "reason": "spawn_failed",
                "error_kind": format!("{:?}", error.kind())
            });
        }
        Err(process::ProcessError::WorkerSpawn { source, .. }) => {
            return json!({
                "status": "unavailable",
                "reason": "worker_spawn_failed",
                "error_kind": format!("{:?}", source.kind())
            });
        }
        Err(process::ProcessError::Read(error)) => {
            return json!({
                "status": "unavailable",
                "reason": "output_read_failed",
                "error_kind": format!("{:?}", error.kind())
            });
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
    } else {
        json!({"status": "available", "public_version": version})
    }
}

fn unavailable(reason: &str) -> Value {
    json!({"status": "unavailable", "reason": reason})
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
