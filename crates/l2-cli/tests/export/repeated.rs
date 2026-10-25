use super::*;

fn extraction_command(root: &Path, capture: &Path, destination: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
    command
        .arg("extract")
        .arg(capture)
        .arg("-o")
        .arg(destination)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_STATE_HOME", root.join("state"));
    command
}

#[test]
fn identical_extraction_reuses_the_published_result() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    let destination = root.join("result");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    let first = extraction_command(root, &capture, &destination).output()?;
    assert!(matches!(first.status.code(), Some(0 | 3)));
    let before = fs::read(destination.join("manifest.json"))?;
    let second = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(second.status.code(), first.status.code());
    assert!(String::from_utf8_lossy(&second.stdout).contains("Reused"));
    assert_eq!(fs::read(destination.join("manifest.json"))?, before);
    Ok(())
}

#[test]
fn unrelated_destination_is_rejected_before_reading_a_capture() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let destination = root.join("result");
    fs::create_dir(&destination)?;
    fs::write(destination.join("keep.txt"), b"user data")?;
    let capture = root.join("invalid.pcap");
    fs::write(&capture, b"not a capture")?;
    let result = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(result.status.code(), Some(1));
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("destination") || error.contains("output"),
        "{error}"
    );
    assert!(!root.join("cache").exists());
    assert_eq!(fs::read(destination.join("keep.txt"))?, b"user data");
    Ok(())
}

#[test]
fn matching_partial_extraction_returns_the_recorded_partial_status() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcapng");
    let destination = root.join("result");
    fs::write(
        &capture,
        capture_with_packet_block_drops(&capture_with_http_body(BODY)?, 7)?,
    )?;
    let first = extraction_command(root, &capture, &destination).output()?;
    assert_eq!(first.status.code(), Some(3));
    let original_manifest = fs::read(destination.join("manifest.json"))?;

    let reused = extraction_command(root, &capture, &destination).output()?;

    assert_eq!(reused.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&reused.stdout).contains("Reused"));
    assert_eq!(
        fs::read(destination.join("manifest.json"))?,
        original_manifest
    );
    Ok(())
}

#[test]
fn deeper_profile_reuses_the_index_and_keeps_progress_as_json() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let capture = root.join("capture.pcap");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    let normal = extraction_command(root, &capture, &root.join("normal")).output()?;
    assert!(matches!(normal.status.code(), Some(0 | 3)));

    let deep = extraction_command(root, &capture, &root.join("deep"))
        .args(["--profile", "deep", "--progress", "json"])
        .output()?;

    assert!(matches!(deep.status.code(), Some(0 | 3)));
    let mut index_reused = false;
    for line in String::from_utf8(deep.stderr)?.lines() {
        let event: serde_json::Value = serde_json::from_str(line)?;
        index_reused |= event
            .get("phases")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|phases| {
                phases.iter().any(|phase| {
                    phase.get("phase").and_then(serde_json::Value::as_str) == Some("ingestion")
                        && phase.get("state").and_then(serde_json::Value::as_str) == Some("skipped")
                })
            });
    }
    assert!(index_reused, "deep run did not report a reused index");
    Ok(())
}
