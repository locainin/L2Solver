use super::support::{capture_with_truncated_record, ipv4_capture, path_arg, run};
use l2_workbench::{evidence::Case, sha256};
use serde_json::Value;
use std::{error::Error, fs};

#[test]
fn streaming_bundle_global_source_ranges() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.pcap");
    let destination = directory.path().join("bundle");
    let bytes = ipv4_capture(5);
    fs::write(&input, &bytes)?;
    let output = run(
        &[
            "stream",
            path_arg(&input)?,
            "--directory",
            path_arg(&destination)?,
            "--page-records",
            "2",
            "--context-records",
            "1",
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
    let manifest: Value = serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert_eq!(
        manifest.pointer("/source/id"),
        Some(&Value::String(format!("sha256:{}", sha256(&bytes))))
    );
    assert_eq!(manifest.pointer("/source/frames"), Some(&Value::from(5)));
    assert_eq!(
        manifest.get("raw_collection_complete"),
        Some(&Value::Bool(true))
    );
    let pages = manifest
        .get("pages")
        .and_then(Value::as_array)
        .ok_or("missing pages")?;
    assert_eq!(pages.len(), 3);
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt.get("pages"), Some(&Value::from(3)));
    assert_eq!(
        receipt.pointer("/acquisition_quality/status"),
        Some(&Value::from("unverified"))
    );
    assert_eq!(
        receipt.pointer("/acquisition_quality/authority"),
        Some(&Value::from("absent"))
    );
    assert!(output.stdout.len() < 1024);
    assert_eq!(
        pages
            .get(1)
            .and_then(|page| page.get("context_first_record")),
        Some(&Value::from(2))
    );
    let second = Case::from_json(&fs::read(destination.join("pages/000002.json"))?)?;
    let packets: Vec<_> = second
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .collect();
    assert_eq!(packets.len(), 3);
    assert_eq!(
        packets
            .first()
            .and_then(|node| node.ranges.first())
            .and_then(|range| range.packet),
        Some(2)
    );
    Ok(())
}

#[test]
fn stream_defaults_to_directory_summary() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.pcap");
    let destination = directory.path().join("bundle");
    fs::write(&input, ipv4_capture(5))?;

    let output = run(
        &[
            "stream",
            path_arg(&input)?,
            "--directory",
            path_arg(&destination)?,
            "--page-records",
            "2",
            "--context-records",
            "1",
        ],
        b"",
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains(&format!(
        "Created stream directory: {}",
        destination.display()
    )));
    assert!(text.contains("Pages: 3; raw records retained: complete; analysis: complete"));
    assert!(text.contains("acquisition: unverified (authority=absent)"));
    assert!(destination.join("manifest.json").is_file());
    Ok(())
}

#[test]
fn streaming_failure_no_partial_publish() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("broken.pcap");
    let destination = directory.path().join("bundle");
    let mut bytes = ipv4_capture(3);
    bytes.pop();
    fs::write(&input, bytes)?;
    let output = run(
        &[
            "stream",
            path_arg(&input)?,
            "--directory",
            path_arg(&destination)?,
        ],
        b"",
    )?;
    assert!(!output.status.success());
    assert!(!destination.exists());
    fs::write(&input, ipv4_capture(1))?;
    fs::create_dir(&destination)?;
    fs::write(destination.join("marker"), b"keep")?;
    let output = run(
        &[
            "stream",
            path_arg(&input)?,
            "--directory",
            path_arg(&destination)?,
        ],
        b"",
    )?;
    assert!(!output.status.success());
    assert_eq!(fs::read(destination.join("marker"))?, b"keep");
    Ok(())
}

#[test]
fn malformed_stream_names_input() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("truncated-record.pcap");
    let destination = directory.path().join("bundle");
    fs::write(&input, capture_with_truncated_record())?;

    let output = run(
        &[
            "stream",
            path_arg(&input)?,
            "--directory",
            path_arg(&destination)?,
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    let path = input.display().to_string();
    assert!(stderr.contains(&path), "{stderr}");
    assert_eq!(stderr.matches(&path).count(), 1, "{stderr}");
    assert!(!destination.exists());
    Ok(())
}
