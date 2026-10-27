use super::*;

#[test]
fn unavailable_cache_preserves_recovered_artifact_bytes_and_completion()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("capture.pcap");
    let cache_home = temporary.path().join("unavailable-cache");
    let state_home = temporary.path().join("state");
    fs::write(&capture, capture_with_http_body(BODY)?)?;
    fs::write(&cache_home, b"not a directory")?;
    fs::create_dir(&state_home)?;

    let baseline_directory = temporary.path().join("baseline");
    let fallback_directory = temporary.path().join("fallback");
    let run = |destination: &Path, flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("extract")
            .arg(&capture)
            .arg("--output")
            .arg(destination)
            .args(["--progress", "never"])
            .args(flags)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("XDG_STATE_HOME", &state_home)
            .output()
    };
    let baseline = run(&baseline_directory, &["--no-cache"])?;
    let fallback = run(&fallback_directory, &[])?;
    assert!(
        matches!(baseline.status.code(), Some(0 | 3)),
        "baseline failed: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    assert_eq!(
        fallback.status.code(),
        baseline.status.code(),
        "fallback changed the completion status: {}",
        String::from_utf8_lossy(&fallback.stderr)
    );
    let read_artifacts = |directory: &Path| -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let mut contents = artifact_paths(directory)?
            .iter()
            .map(fs::read)
            .collect::<Result<Vec<_>, _>>()?;
        contents.sort();
        Ok(contents)
    };
    let baseline_bytes = read_artifacts(&baseline_directory)?;
    assert_eq!(baseline_bytes, vec![BODY.to_vec()]);
    assert_eq!(read_artifacts(&fallback_directory)?, baseline_bytes);
    assert!(String::from_utf8(fallback.stderr)?.contains("cache unavailable x1"));
    Ok(())
}
