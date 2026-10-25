#![cfg(unix)]

use super::identity_for_path;
use l2_workbench::job::Job;
use serde_json::Value;
use std::{
    error::Error,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};

fn executable_script(path: &Path, body: &str) -> Result<(), Box<dyn Error>> {
    fs::write(path, format!("#!/bin/sh\n{body}\n"))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn selected_path(identity: &Value) -> Result<PathBuf, Box<dyn Error>> {
    let encoded = identity
        .pointer("/executable/path_hex")
        .and_then(Value::as_str)
        .ok_or("selected executable path is missing")?;
    #[cfg(unix)]
    {
        let mut digits = encoded.bytes();
        let mut bytes = Vec::new();
        loop {
            let Some(high) = digits.next() else {
                break;
            };
            let low = digits
                .next()
                .ok_or("selected executable path hex is incomplete")?;
            bytes.push((hex_value(high)? << 4) | hex_value(low)?);
        }
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(encoded))
    }
}

fn hex_value(digit: u8) -> Result<u8, Box<dyn Error>> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err("selected executable path is not hex encoded".into()),
    }
}

fn field<'a>(identity: &'a Value, path: &str) -> Result<&'a Value, Box<dyn Error>> {
    identity
        .pointer(path)
        .ok_or_else(|| format!("identity field {path:?} is missing").into())
}

#[test]
fn selected_executable_reports_public_version_and_fast_metadata() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let executable = temporary.path().join("tshark");
    executable_script(
        &executable,
        "[ \"$1\" = \"-n\" ] && [ \"$2\" = \"-v\" ] || exit 9\nprintf 'TShark (Wireshark) 4.4.2\\n'",
    )?;
    let search_path = std::env::join_paths([temporary.path()])?;

    let identity = identity_for_path(Some(search_path.as_os_str()), None);

    assert_eq!(field(&identity, "/executable/status")?, "selected");
    assert_eq!(field(&identity, "/version/status")?, "available");
    assert_eq!(
        field(&identity, "/version/public_version")?,
        "TShark (Wireshark) 4.4.2"
    );
    assert_eq!(field(&identity, "/arguments_epoch")?, 1);
    assert_eq!(
        field(&identity, "/executable/length")?,
        fs::metadata(&executable)?.len()
    );
    assert_eq!(selected_path(&identity)?, executable.canonicalize()?);
    Ok(())
}

#[test]
fn unsupported_version_probe_keeps_executable_metadata_identity() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let executable = temporary.path().join("tshark");
    executable_script(&executable, "printf 'unsupported options\\n' >&2; exit 2")?;
    let search_path = std::env::join_paths([temporary.path()])?;

    let identity = identity_for_path(Some(search_path.as_os_str()), None);

    assert_eq!(field(&identity, "/executable/status")?, "selected");
    assert!(field(&identity, "/executable/length")?.as_u64().is_some());
    assert_eq!(field(&identity, "/version/status")?, "unavailable");
    assert_eq!(field(&identity, "/version/reason")?, "nonzero_exit");
    Ok(())
}

#[test]
fn missing_executable_returns_optional_identity_without_running_a_process()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let search_path = std::env::join_paths([temporary.path()])?;

    let identity = identity_for_path(Some(search_path.as_os_str()), None);

    assert_eq!(field(&identity, "/executable/status")?, "missing");
    assert_eq!(field(&identity, "/version/status")?, "unavailable");
    assert_eq!(field(&identity, "/version/reason")?, "executable_not_found");
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_search_path_and_executable_are_encoded_without_panicking() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let directory = temporary
        .path()
        .join(OsString::from_vec(b"tool-\xff".to_vec()));
    fs::create_dir(&directory)?;
    let executable = directory.join("tshark");
    executable_script(&executable, "printf 'TShark 4.4.2\\n'")?;
    let search_path = std::env::join_paths([&directory])?;

    let identity = identity_for_path(Some(&search_path), None);

    assert_eq!(field(&identity, "/executable/status")?, "selected");
    assert_eq!(field(&identity, "/version/public_version")?, "TShark 4.4.2");
    assert_eq!(selected_path(&identity)?, executable.canonicalize()?);
    assert!(field(&identity, "/executable/path_hex")?.as_str().is_some());
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_executable_shadow_file_does_not_hide_or_run_the_next_executable()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let shadow = temporary.path().join("shadow");
    let executable_directory = temporary.path().join("valid");
    fs::create_dir(&shadow)?;
    fs::create_dir(&executable_directory)?;
    let shadow_path = shadow.join("tshark");
    fs::write(&shadow_path, "this file must not run")?;
    let executable = executable_directory.join("tshark");
    executable_script(
        &executable,
        "printf '%s %s' \"$1\" \"$2\" > \"${0}.args\"\nprintf 'TShark 4.4.2\\n'",
    )?;
    let search_path = std::env::join_paths([&shadow, &executable_directory])?;

    let identity = identity_for_path(Some(&search_path), None);

    assert_eq!(field(&identity, "/version/public_version")?, "TShark 4.4.2");
    assert_eq!(selected_path(&identity)?, executable.canonicalize()?);
    assert_eq!(
        fs::read_to_string(executable.with_extension("args"))?,
        "-n -v"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn version_probe_stops_when_the_shared_job_is_cancelled() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let executable = temporary.path().join("tshark");
    executable_script(&executable, "exec sleep 30")?;
    let search_path = std::env::join_paths([temporary.path()])?;
    let job = Job::new("test version probe cancellation");
    let cancellation_job = job.clone();
    let cancellation = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        cancellation_job.request_cancel();
    });

    let identity = identity_for_path(Some(&search_path), Some(&job));

    cancellation
        .join()
        .map_err(|_| "cancellation thread panicked")?;
    assert_eq!(field(&identity, "/executable/status")?, "selected");
    assert_eq!(field(&identity, "/version/status")?, "cancelled");
    Ok(())
}
