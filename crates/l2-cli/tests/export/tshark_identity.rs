#![cfg(unix)]

use super::{BODY, capture_with_http_body, install_tshark, repeated};
use std::{
    error::Error,
    fs::{self, FileTimes, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Output,
};

const EXPORTED_OBJECT: &[u8] = b"identity fixture exported object";

#[test]
fn required_export_failure() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.19")?;
    fixture.set_script("TShark (Wireshark) 4.4.19", ExportMode::Fails)?;

    let result = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;

    assert_eq!(result.status.code(), Some(3));
    let summary = fs::read_to_string(fixture.destination.join("summary.txt"))?;
    assert!(summary.contains("unexpected fixture export"));
    assert!(summary.contains("TShark export: partial"));
    Ok(())
}

#[test]
fn availability_change_conflicts_until_refresh() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.19")?;
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

    fixture.set_script("TShark (Wireshark) 4.4.19", ExportMode::Fails)?;
    let available_without_refresh = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_identity_conflict(
        &fixture.destination,
        &available_without_refresh,
        &missing_manifest,
        &missing_artifacts,
    )?;
    // Required mode would fail if collection reached the deliberately failing fixture
    let required_without_refresh = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
    assert_identity_conflict(
        &fixture.destination,
        &required_without_refresh,
        &missing_manifest,
        &missing_artifacts,
    )?;

    fixture.set_script("TShark (Wireshark) 4.4.19", ExportMode::Ready)?;
    let refreshed = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--refresh"],
    )?;
    assert_success(&refreshed);
    assert_ne!(manifest_bytes(&fixture.destination)?, missing_manifest);
    let refreshed_artifacts = repeated::artifact_contents(&fixture.destination)?;
    assert_eq!(refreshed_artifacts.len(), missing_artifacts.len() + 1);
    assert!(
        missing_artifacts
            .iter()
            .all(|item| refreshed_artifacts.contains(item))
    );
    assert_exported_object(&fixture.destination)?;
    assert_eq!(
        tshark_version(&fixture.destination)?,
        "TShark (Wireshark) 4.4.19"
    );
    Ok(())
}

#[test]
fn public_version_change_conflicts_until_refresh_and_keeps_stage_cache_reusable()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("TShark (Wireshark) 4.4.19")?;
    let initial = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
    assert_success(&initial);
    assert_exported_object(&fixture.destination)?;
    let initial_manifest = manifest_bytes(&fixture.destination)?;
    let executable_identity = manifest(&fixture.destination)?
        .pointer("/l2solver_result/identity/settings/tshark/executable")
        .cloned()
        .ok_or("selected executable identity missing")?;
    let initial_artifacts = repeated::artifact_contents(&fixture.destination)?;
    assert_eq!(
        tshark_version(&fixture.destination)?,
        "TShark (Wireshark) 4.4.19"
    );

    fixture.set_script("TShark (Wireshark) 4.4.20", ExportMode::Fails)?;
    let changed_without_refresh = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
    assert_identity_conflict(
        &fixture.destination,
        &changed_without_refresh,
        &initial_manifest,
        &initial_artifacts,
    )?;

    fixture.set_script("TShark (Wireshark) 4.4.20", ExportMode::Ready)?;
    let refreshed = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark", "--refresh"],
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
        "TShark (Wireshark) 4.4.20"
    );
    assert_eq!(
        manifest(&fixture.destination)?
            .pointer("/l2solver_result/identity/settings/tshark/executable"),
        Some(&executable_identity),
        "the version alone must change the selected executable identity"
    );

    let warm_destination = fixture.root.join("warm-result");
    let warm = run(
        &fixture,
        &warm_destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
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
    let fixture = Fixture::new("TShark (Wireshark) 4.4.21")?;
    let optional = run(&fixture, &fixture.destination, &fixture.tshark, &[])?;
    assert_success(&optional);
    let optional_manifest = manifest_bytes(&fixture.destination)?;
    let optional_artifacts = repeated::artifact_contents(&fixture.destination)?;
    assert_exported_object(&fixture.destination)?;
    assert_eq!(
        manifest(&fixture.destination)?
            .pointer("/l2solver_result/identity/settings/require_tshark")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    fixture.set_script("TShark (Wireshark) 4.4.21", ExportMode::Fails)?;
    let required_without_refresh = run(
        &fixture,
        &fixture.destination,
        &fixture.tshark,
        &["--require-tshark"],
    )?;
    assert_identity_conflict(
        &fixture.destination,
        &required_without_refresh,
        &optional_manifest,
        &optional_artifacts,
    )?;

    fixture.set_script("TShark (Wireshark) 4.4.21", ExportMode::Ready)?;
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
    export_script: String,
}

#[derive(Clone, Copy)]
enum ExportMode {
    Ready,
    Fails,
}

impl Fixture {
    fn new(version: &str) -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().to_owned();
        let capture = root.join("capture.pcap");
        let destination = root.join("result");
        let tshark = install_tshark(
            &root,
            "printf '%s' 'identity fixture exported object' > \"$destination/identity-fixture.txt\"",
        )?;
        let wrapper = tshark.join("tshark");
        let export_script = fs::read_to_string(&wrapper)?;
        fs::write(
            &wrapper,
            versioned_script(&export_script, version, ExportMode::Ready)?,
        )?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
        fs::write(&capture, capture_with_http_body(BODY)?)?;
        Ok(Self {
            _temporary: temporary,
            root,
            capture,
            destination,
            tshark,
            export_script,
        })
    }

    fn set_script(&self, version: &str, mode: ExportMode) -> Result<(), Box<dyn Error>> {
        let path = self.tshark.join("tshark");
        let metadata = fs::metadata(&path)?;
        let script = versioned_script(&self.export_script, version, mode)?;
        if u64::try_from(script.len())? != metadata.len() {
            return Err("fixture rewrite must preserve executable length".into());
        }
        // Keep the fast metadata hint fixed so a version change is tested independently
        let mut file = OpenOptions::new().write(true).truncate(true).open(&path)?;
        file.write_all(script.as_bytes())?;
        file.sync_all()?;
        file.set_times(FileTimes::new().set_modified(metadata.modified()?))?;
        Ok(())
    }
}

fn versioned_script(
    export_script: &str,
    version: &str,
    mode: ExportMode,
) -> Result<String, Box<dyn Error>> {
    if version.contains(['\'', '\n', '\r']) {
        return Err("fixture version contains shell quoting characters".into());
    }
    let mode = match mode {
        ExportMode::Ready => "ready",
        ExportMode::Fails => "fails",
    };
    Ok(include_str!("fake_tshark_version.sh")
        .replace("__VERSION__", version)
        .replace("__EXPORT_MODE__", mode)
        .replace("__EXPORT_SCRIPT__", export_script))
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
    destination: &Path,
    output: &Output,
    manifest_before: &[u8],
    artifacts_before: &repeated::ArtifactContents,
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
    assert_eq!(&repeated::artifact_contents(destination)?, artifacts_before);
    Ok(())
}

fn assert_exported_object(directory: &Path) -> Result<(), Box<dyn Error>> {
    let artifacts = repeated::artifact_contents(directory)?;
    assert_eq!(
        artifacts
            .iter()
            .filter(|(_, bytes)| bytes == EXPORTED_OBJECT)
            .count(),
        1,
        "the fake TShark object must be published exactly once"
    );
    assert_eq!(
        manifest(directory)?
            .pointer("/tshark/status")
            .and_then(serde_json::Value::as_str),
        Some("complete")
    );
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
