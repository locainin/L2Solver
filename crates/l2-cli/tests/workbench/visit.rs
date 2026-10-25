use super::support::{empty_capture, ipv4_header_frame, path_arg, run};
use l2_workbench::{evidence::Case, sha256};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn capture(records: u32) -> Vec<u8> {
    let frame = ipv4_header_frame([192, 0, 2, 1], [192, 0, 2, 2]);
    let mut bytes = empty_capture();
    for record in 0..records {
        bytes.extend_from_slice(&record.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&34_u32.to_le_bytes());
        bytes.extend_from_slice(&34_u32.to_le_bytes());
        bytes.extend_from_slice(&frame);
    }
    bytes
}

fn create_bundle(root: &Path, records: u32) -> Result<(std::path::PathBuf, Value), Box<dyn Error>> {
    create_bundle_from_capture(root, &capture(records))
}

fn create_bundle_from_capture(
    root: &Path,
    bytes: &[u8],
) -> Result<(std::path::PathBuf, Value), Box<dyn Error>> {
    let source = root.join("input.pcap");
    let bundle = root.join("bundle");
    fs::write(&source, bytes)?;
    let output = run(
        &[
            "stream",
            path_arg(&source)?,
            "--directory",
            path_arg(&bundle)?,
            "--page-records",
            "2",
            "--context-records",
            "1",
        ],
        b"",
    )?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    let manifest = serde_json::from_slice(&fs::read(bundle.join("manifest.json"))?)?;
    Ok((bundle, manifest))
}

fn run_query(path: &Path) -> Result<std::process::Output, Box<dyn Error>> {
    run(
        &[
            "query",
            path_arg(path)?,
            "--filter",
            "kind=packet",
            "--format",
            "json",
        ],
        b"",
    )
}

#[cfg(unix)]
fn run_query_with_timeout(path: &Path) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "query"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            if output.status != status {
                return Err("workbench query exit status changed while collecting output".into());
            }
            return Ok(output);
        }
        if started.elapsed() >= Duration::from_secs(3) {
            child.kill()?;
            let _ = child.wait()?;
            return Err("workbench query blocked while opening a bundle document".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn write_manifest(bundle: &Path, manifest: &Value) -> Result<(), Box<dyn Error>> {
    fs::write(bundle.join("manifest.json"), serde_json::to_vec(manifest)?)?;
    Ok(())
}

fn set_field(value: &mut Value, name: &str, replacement: Value) -> Result<(), Box<dyn Error>> {
    value
        .as_object_mut()
        .ok_or("expected a JSON object")?
        .insert(name.to_owned(), replacement);
    Ok(())
}

fn first_page_mut(manifest: &mut Value) -> Result<&mut Value, Box<dyn Error>> {
    manifest
        .get_mut("pages")
        .and_then(Value::as_array_mut)
        .and_then(|pages| pages.first_mut())
        .ok_or_else(|| "manifest has no first page".into())
}

#[test]
fn bundle_visiting_page_windows_context() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 5)?;
    let output = run_query(&bundle)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/inventory/pages"), Some(&json!(3)));
    assert_eq!(report.get("matched_nodes"), Some(&json!(5)));
    assert_eq!(
        report.pointer("/inventory/collection_complete"),
        Some(&json!(true))
    );
    assert_eq!(
        report.pointer("/inventory/source_ids/0"),
        Some(&json!(format!("sha256:{}", sha256(&capture(5))))),
    );
    Ok(())
}

#[test]
fn single_case_validation_path() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 1)?;
    let page = bundle.join("pages/000001.json");
    let output = run_query(&page)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/inventory/pages"), Some(&json!(1)));
    assert_eq!(
        report.pointer("/inventory/collection_complete"),
        Some(&json!(true))
    );
    Ok(())
}

#[test]
fn bundle_visiting_length_captured_packets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut bytes = empty_capture();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    let (bundle, _) = create_bundle_from_capture(directory.path(), &bytes)?;
    let output = run(
        &[
            "query",
            path_arg(&bundle)?,
            "--filter",
            "kind=packet",
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("matched_nodes"), Some(&json!(1)));
    Ok(())
}

#[test]
fn bundle_visiting_accepts_empty_capture() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 0)?;
    let output = run_query(&bundle)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/inventory/pages"), Some(&json!(0)));
    assert_eq!(report.get("matched_nodes"), Some(&json!(0)));
    Ok(())
}

#[test]
fn bundle_visiting_page_hash_mismatch() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 3)?;
    set_field(
        first_page_mut(&mut manifest)?,
        "sha256",
        json!("00".repeat(32)),
    )?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_noncanonical_page_paths() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 3)?;
    set_field(
        first_page_mut(&mut manifest)?,
        "path",
        json!("../outside.json"),
    )?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_rejects_missing_pages() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 3)?;
    fs::remove_file(bundle.join("pages/000002.json"))?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bundle_visiting_symlinked_page_documents() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 1)?;
    let page = bundle.join("pages/000001.json");
    let target = directory.path().join("external-page.json");
    fs::rename(&page, &target)?;
    symlink(&target, &page)?;

    let output = run_query_with_timeout(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bundle_visiting_documents_without_blocking() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, _) = create_bundle(directory.path(), 1)?;
    let manifest = bundle.join("manifest.json");
    fs::remove_file(&manifest)?;
    let status = Command::new("mkfifo").arg(&manifest).status()?;
    if !status.success() {
        return Err("mkfifo could not create the FIFO test document".into());
    }

    let output = run_query_with_timeout(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_primary_gaps() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 5)?;
    let page = manifest
        .get_mut("pages")
        .and_then(Value::as_array_mut)
        .and_then(|pages| pages.get_mut(1))
        .ok_or("manifest has no second page")?;
    set_field(page, "first_record", json!(4))?;
    set_field(page, "last_record", json!(4))?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_summary_window_gaps() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 3)?;
    let page_path = bundle.join("pages/000001.json");
    let mut page: Value = serde_json::from_slice(&fs::read(&page_path)?)?;
    let summary = page
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .find(|node| node.get("kind") == Some(&json!("capture_summary")))
        })
        .ok_or("page has no capture summary")?;
    let record_window = summary
        .get_mut("details")
        .and_then(|details| details.get_mut("record_window"))
        .ok_or("capture summary has no record window")?;
    set_field(record_window, "first", json!(2))?;
    let document = serde_json::to_vec(&page)?;
    fs::write(page_path, &document)?;
    set_field(
        first_page_mut(&mut manifest)?,
        "sha256",
        json!(sha256(&document)),
    )?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_inaccurate_raw_completeness() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 3)?;
    set_field(&mut manifest, "raw_collection_complete", json!(false))?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_page_completeness_mismatch() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 3)?;
    set_field(
        first_page_mut(&mut manifest)?,
        "collection_complete",
        json!(false),
    )?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn bundle_visiting_incomplete_packet_prefix() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 1)?;
    let source_id = manifest
        .pointer("/source/id")
        .and_then(Value::as_str)
        .ok_or("manifest source identity is missing")?;
    let source_label = manifest
        .pointer("/source/label")
        .and_then(Value::as_str)
        .ok_or("manifest source label is missing")?;
    let source_length = manifest
        .pointer("/source/length")
        .and_then(Value::as_u64)
        .ok_or("manifest source length is missing")?;
    let digest = source_id.strip_prefix("sha256:").ok_or("bad source ID")?;
    let mut case = Case::new();
    case.add_source(source_label, "capture", source_length, digest, None)?;
    case.add_node(
        "capture_summary",
        None,
        Vec::new(),
        json!({
            "frames_seen": 1,
            "retained_frames": 1,
            "record_window": {"first": 1, "last": 1}
        }),
    )?;
    case.mark_incomplete("Packet evidence was omitted after a retention limit")?;
    let document = case.to_json()?;
    fs::write(bundle.join("pages/000001.json"), &document)?;
    set_field(
        first_page_mut(&mut manifest)?,
        "sha256",
        json!(sha256(&document)),
    )?;
    set_field(first_page_mut(&mut manifest)?, "packet_nodes", json!(0))?;
    set_field(
        first_page_mut(&mut manifest)?,
        "collection_complete",
        json!(false),
    )?;
    set_field(&mut manifest, "raw_collection_complete", json!(false))?;
    set_field(&mut manifest, "analysis_complete", json!(false))?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/inventory/collection_complete"),
        Some(&json!(false))
    );
    assert_eq!(report.get("matched_nodes"), Some(&json!(0)));
    Ok(())
}

#[test]
fn bundle_visiting_unknown_manifest_fields() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let (bundle, mut manifest) = create_bundle(directory.path(), 1)?;
    set_field(&mut manifest, "unrecognized", json!(true))?;
    write_manifest(&bundle, &manifest)?;
    let output = run_query(&bundle)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}
