#![cfg(unix)]

use super::{BODY, capture_with_http_body, install_tshark, repeated};
use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Output,
};

#[test]
fn availability_change_conflicts_until_refresh() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.1")?;
    let empty_path = fixture.root.join("empty-path");
    fs::create_dir(&empty_path)?;

    let missing = run(&fixture, &fixture.destination, &empty_path, &[])?;
    assert_success(&missing);
    let missing_manifest = manifest_bytes(&fixture.destination)?;
    let missing_artifacts = repeated::artifact_contents(&fixture.destination)?;
    assert_eq!(
        manifest(&fixture.destination)?
            .pointer("/l2solver_result/identity/settings/tshark/executable/status")
            .and_then(serde_json::Value::as_str),
        Some("missing")
    );

    let available_without_refresh = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_identity_conflict(
        &fixture,
        &fixture.destination,
        &available_without_refresh,
        &missing_manifest,
        &[],
    )?;

    let refreshed = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--refresh"],
    )?;
    assert_success(&refreshed);
    assert_ne!(manifest_bytes(&fixture.destination)?, missing_manifest);
    assert_eq!(
        repeated::artifact_contents(&fixture.destination)?,
        missing_artifacts
    );
    assert_eq!(
        tshark_version(&fixture.destination)?,
        "TShark (Wireshark) 4.4.1"
    );
    assert!(!invocation_log(&fixture)?.is_empty());
    Ok(())
}

#[test]
fn public_version_change_conflicts_until_refresh_and_keeps_stage_cache_reusable()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.1")?;
    let initial = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_success(&initial);
    let initial_manifest = manifest_bytes(&fixture.destination)?;
    let initial_artifacts = repeated::artifact_contents(&fixture.destination)?;
    let initial_invocations = invocation_log(&fixture)?;
    assert_eq!(
        tshark_version(&fixture.destination)?,
        "TShark (Wireshark) 4.4.1"
    );

    set_version(&fixture, "TShark (Wireshark) 4.4.2")?;
    let changed_without_refresh = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_identity_conflict(
        &fixture,
        &fixture.destination,
        &changed_without_refresh,
        &initial_manifest,
        &initial_invocations,
    )?;

    let refreshed = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--refresh"],
    )?;
    assert_success(&refreshed);
    let refreshed_manifest = manifest_bytes(&fixture.destination)?;
    assert_ne!(refreshed_manifest, initial_manifest);
    assert_eq!(
        repeated::artifact_contents(&fixture.destination)?,
        initial_artifacts
    );
    assert_eq!(
        tshark_version(&fixture.destination)?,
        "TShark (Wireshark) 4.4.2"
    );

    let warm_destination = fixture.root.join("warm-result");
    let warm = run(&fixture, &warm_destination, &fixture.tshark, &[])?;
    assert_success(&warm);
    assert_eq!(
        repeated::artifact_contents(&fixture.destination)?,
        repeated::artifact_contents(&warm_destination)?
    );
    let refreshed_counters = repeated::result_counters(&fixture.destination)?;
    let warm_counters = repeated::result_counters(&warm_destination)?;
    assert!(
        warm_counters.cache_hits > 0,
        "refreshed work was not reusable"
    );
    assert!(
        warm_counters.candidates_examined < refreshed_counters.candidates_examined,
        "warm output repeated completed recovery work"
    );
    Ok(())
}

#[test]
fn require_tshark_change_conflicts_until_refresh() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.3")?;
    let optional = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_success(&optional);
    let optional_manifest = manifest_bytes(&fixture.destination)?;
    let optional_artifacts = repeated::artifact_contents(&fixture.destination)?;
    let optional_invocations = invocation_log(&fixture)?;
    assert_eq!(
        manifest(&fixture.destination)?
            .pointer("/l2solver_result/identity/settings/require_tshark")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    let required_without_refresh = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
    assert_identity_conflict(
        &fixture,
        &fixture.destination,
        &required_without_refresh,
        &optional_manifest,
        &optional_invocations,
    )?;

    let required_refresh = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark", "--refresh"],
    )?;
    assert_success(&required_refresh);
    assert_ne!(manifest_bytes(&fixture.destination)?, optional_manifest);
    assert_eq!(
        repeated::artifact_contents(&fixture.destination)?,
        optional_artifacts
    );
    assert!(required_tshark(&fixture.destination)?);
    Ok(())
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    capture: PathBuf,
    destination: PathBuf,
    tshark: PathBuf,
}

impl Fixture {
    fn new(version: &str) -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_owned();
        let capture = root.join("capture.pcap");
        let destination = root.join("result");
        let tshark = install_tshark(&root, "")?;
        fs::rename(tshark.join("tshark"), tshark.join("tshark-export"))?;
        fs::write(tshark.join("version.txt"), format!("{version}\n"))?;
        let wrapper = tshark.join("tshark");
        fs::write(&wrapper, include_bytes!("fake_tshark_version.sh"))?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
        fs::write(&capture, capture_with_http_body(BODY)?)?;
        Ok(Self {
            _temporary: temporary,
            root,
            capture,
            destination,
            tshark,
        })
    }
}

fn run(
    fixture: &Fixture,
    destination: &Path,
    path: &Path,
    flags: &[&str],
) -> std::io::Result<Output> {
    let mut command = repeated::extraction_command(&fixture.root, &fixture.capture, destination);
    command.env("PATH", path).args(flags).output()
}

fn assert_success(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_identity_conflict(
    fixture: &Fixture,
    destination: &Path,
    output: &Output,
    manifest_before: &[u8],
    invocations_before: &[u8],
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("result policy or algorithm version differs")
    );
    assert_eq!(manifest_bytes(destination)?, manifest_before);
    assert_eq!(invocation_log(fixture)?, invocations_before);
    Ok(())
}

fn manifest_bytes(directory: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(directory.join("manifest.json"))
}

fn manifest(directory: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&manifest_bytes(directory)?)?)
}

fn tshark_version(directory: &Path) -> Result<String, Box<dyn Error>> {
    manifest(directory)?
        .pointer("/l2solver_result/identity/settings/tshark/version/public_version")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "result identity is missing the selected TShark version".into())
}

fn required_tshark(directory: &Path) -> Result<bool, Box<dyn Error>> {
    manifest(directory)?
        .pointer("/l2solver_result/identity/settings/require_tshark")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "result identity is missing its TShark requirement setting".into())
}

fn set_version(fixture: &Fixture, version: &str) -> std::io::Result<()> {
    fs::write(fixture.tshark.join("version.txt"), format!("{version}\n"))
}

fn invocation_log(fixture: &Fixture) -> std::io::Result<Vec<u8>> {
    match fs::read(fixture.tshark.join("invocations.txt")) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}
