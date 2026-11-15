use super::super::{
    executable::{resolve_executable_in_search_path, verify_executable_unchanged},
    phase::run_phase,
    preparation::{
        CapturePreparation, prepare_capture, prepare_capture_from_at, prepare_export_capture,
        verify_prepared_capture,
    },
    secure_files::Workspace,
    snapshot::{ensure_before_deadline, snapshot_with_clock, verify_source_unchanged},
};
use crate::arguments::TsharkOptions;
use std::{
    error::Error,
    fs::{self, File, Permissions},
    io,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

fn executable(path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, Permissions::from_mode(0o700))
}

#[test]
fn expired_snapshot_deadline() {
    assert!(matches!(
        ensure_before_deadline(Instant::now()),
        Err(super::super::process::ProcessError::TimedOut)
    ));
}

#[test]
fn source_object_identity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source");
    let held_path = directory.path().join("held");
    let original = b"original";
    let digest = l2_workbench::sha256(original);
    fs::write(&source, original)?;
    let mut held = File::open(&source)?;
    fs::rename(&source, &held_path)?;

    // A replacement pathname and the originally opened object are independent
    for (path_bytes, held_bytes) in [(b"modified", original), (original, b"modified")] {
        fs::write(&source, path_bytes)?;
        fs::write(&held_path, held_bytes)?;
        let error = verify_source_unchanged(&mut held, &source, &digest, 8)
            .err()
            .ok_or("changed source object was accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    Ok(())
}

#[test]
fn executable_integrity_same_length() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("tshark");
    fs::write(&path, b"original")?;
    let mut file = File::open(&path)?;
    let digest = l2_workbench::sha256(b"original");

    verify_executable_unchanged(&mut file, 8, &digest)?;
    // Rewriting in place keeps the held descriptor and byte count unchanged
    fs::write(&path, b"changed!")?;
    assert_eq!(
        verify_executable_unchanged(&mut file, 8, &digest)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn executable_search_error() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;
    let selected = second.join("tshark");
    executable(&selected, b"fixture")?;
    let search_path = std::env::join_paths([&first, &second])?;

    assert_eq!(
        resolve_executable_in_search_path(Path::new("tshark"), &search_path)?,
        selected.canonicalize()?
    );
    // A loop is an error, not a missing entry that permits a later tool
    symlink("tshark", first.join("tshark"))?;
    assert_eq!(
        resolve_executable_in_search_path(Path::new("tshark"), &search_path)
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(libc::ELOOP)
    );
    Ok(())
}

#[test]
fn snapshot_input_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("capture");
    fs::write(&source, b"12345678")?;
    let workspace = Workspace::new(Some(directory.path()))?;
    let deadline = Instant::now() + Duration::from_secs(10);

    // The size limit is inclusive for the initial check and the copy
    let snapshot = snapshot_with_clock(
        &source,
        &workspace,
        "exact",
        8,
        "capture",
        deadline,
        Instant::now,
    )?;
    assert_eq!(snapshot.identity.length, 8);
    assert_eq!(fs::read(&snapshot.path)?, b"12345678");
    let error = snapshot_with_clock(
        &source,
        &workspace,
        "oversize",
        7,
        "capture",
        deadline,
        Instant::now,
    )
    .err()
    .ok_or("oversize input was accepted")?;
    assert!(error.to_string().contains("input budget"));
    Ok(())
}

#[test]
fn prepared_input_integrity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture");
    let keylog = directory.path().join("keylog");
    let tool = directory.path().join("tshark");
    fs::write(&capture, b"capture")?;
    fs::write(&keylog, b"key-log")?;
    executable(&tool, b"#!/bin/sh\nexit 0\n")?;
    let preparation = CapturePreparation {
        capture: capture.clone(),
        executable: tool,
        keylog: Some(keylog.clone()),
        timeout: Duration::from_secs(15),
        timeout_seconds: 15,
        input_maximum: 1024,
        metadata_maximum: 1024,
        output_maximum: 1024,
        diagnostic_maximum: 1024,
    };
    let mut prepared =
        prepare_capture_from_at(preparation, Some(directory.path()), Instant::now())?;
    let snapshot = prepared.source.path.clone();
    let keylog_snapshot = prepared
        .keylog
        .as_ref()
        .ok_or("keylog snapshot missing")?
        .path
        .clone();
    verify_prepared_capture(&mut prepared)?;

    // Keep lengths fixed so each check must compare the digest
    for path in [&capture, &keylog, &snapshot, &keylog_snapshot] {
        let original = fs::read(path)?;
        let mut changed = original.clone();
        *changed.first_mut().ok_or("empty test input")? ^= 1;
        fs::write(path, &changed)?;
        let result = verify_prepared_capture(&mut prepared);
        fs::write(path, &original)?;
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData),
            "{}",
            path.display()
        );
        verify_prepared_capture(&mut prepared)?;
    }
    Ok(())
}

#[test]
fn mib_budget_units() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture");
    let tool = directory.path().join("tshark");
    fs::write(&capture, b"capture")?;
    executable(&tool, b"#!/bin/sh\nexit 0\n")?;
    let options = TsharkOptions {
        capture,
        executable: tool,
        tls_keylog: None,
        output: None,
        timeout_seconds: 15,
        max_input_mib: 1,
        max_metadata_mib: 2,
        max_output_mib: 3,
        max_diagnostics_mib: 4,
    };

    // Each option is in MiB, even when its stored byte type differs
    let prepared = prepare_capture(&options)?;
    assert_eq!(prepared.input_maximum, 1_048_576);
    assert_eq!(prepared.metadata_maximum, 2_097_152);
    assert_eq!(prepared.output_maximum, 3_145_728);
    assert_eq!(prepared.diagnostic_maximum, 4_194_304);
    Ok(())
}

#[test]
fn export_output_budgets() -> Result<(), Box<dyn Error>> {
    const CHILD: &str = "L2_TSHARK_EXPORT_BUDGET_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        let directory = Path::new(&directory);
        let prepared = prepare_export_capture(&directory.join("capture"), directory)?;
        let output = run_phase(&prepared, &[], prepared.metadata_maximum)?;
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 4096);
        assert_eq!(output.stderr.len(), 4096);
        return Ok(());
    }

    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("capture"), b"capture")?;
    // This output exceeds accidental 1-byte and 2-KiB limits
    executable(
        &directory.path().join("tshark"),
        b"#!/bin/sh\nprintf '%04096d' 0\nprintf '%04096d' 0 >&2\n",
    )?;
    // The child owns its PATH so concurrent tests cannot observe a change
    let status = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "workbench::tshark::tests::integrity::export_output_budgets",
        ])
        .env(CHILD, directory.path())
        .env("PATH", directory.path())
        .status()?;
    assert!(status.success(), "export budget child failed: {status}");
    Ok(())
}
