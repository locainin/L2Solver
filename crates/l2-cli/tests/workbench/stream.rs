use super::support::{
    capture_with_truncated_record, empty_capture, ipv4_header_frame, path_arg, run,
};
use l2_workbench::{evidence::Case, sha256};
use serde_json::Value;
use std::{error::Error, fs};

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

#[test]
fn streaming_bundle_global_source_ranges() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.pcap");
    let destination = directory.path().join("bundle");
    let bytes = capture(5);
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
    fs::write(&input, capture(5))?;

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
    assert!(text.contains("Pages: 3; raw collection: complete; analysis: complete"));
    assert!(destination.join("manifest.json").is_file());
    Ok(())
}

#[test]
fn streaming_failure_no_partial_publish() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("broken.pcap");
    let destination = directory.path().join("bundle");
    let mut bytes = capture(3);
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
    fs::write(&input, capture(1))?;
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
