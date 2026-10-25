use super::support::{capture_with_truncated_record, empty_capture, path_arg, run};
use serde_json::Value;
use std::{error::Error, fs};

#[test]
fn indexed_capture_reopened_verified_exported() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("input.pcap");
    let directory = temporary.path().join("index");
    fs::write(&input, empty_capture())?;
    let result = run(
        &[
            "index",
            path_arg(&input)?,
            "--directory",
            path_arg(&directory)?,
            "--format",
            "json",
        ],
        b"",
    )?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(receipt.pointer("/inventory/packets"), Some(&Value::from(0)));
    assert!(directory.join("index.sqlite").is_file());
    let result = run(&["indexed", path_arg(&directory)?, "verify"], b"")?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = run(&["indexed", path_arg(&directory)?, "flows"], b"")?;
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    Ok(())
}

#[test]
fn index_defaults_to_directory_summary() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("input.pcap");
    let directory = temporary.path().join("index");
    fs::write(&input, empty_capture())?;

    let result = run(
        &[
            "index",
            path_arg(&input)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = String::from_utf8(result.stdout)?;
    assert!(text.contains(&format!("Created index directory: {}", directory.display())));
    assert!(text.contains("Sources: 1; packets: 0; flows: 0"));
    assert!(directory.join("index.sqlite").is_file());
    Ok(())
}

#[test]
fn failed_index_never_replaces_directory() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("broken.pcap");
    let directory = temporary.path().join("index");
    fs::write(&input, b"broken")?;
    let result = run(
        &[
            "index",
            path_arg(&input)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;
    assert!(!result.status.success());
    assert!(!directory.exists());
    fs::create_dir(&directory)?;
    fs::write(directory.join("keep"), b"original")?;
    fs::write(&input, empty_capture())?;
    let result = run(
        &[
            "index",
            path_arg(&input)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;
    assert!(!result.status.success());
    assert_eq!(fs::read(directory.join("keep"))?, b"original");
    assert!(!directory.join("index.sqlite").exists());
    Ok(())
}

#[test]
fn later_malformed_names_input() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let valid = temporary.path().join("valid.pcap");
    let malformed = temporary.path().join("truncated-record.pcap");
    let directory = temporary.path().join("index");
    fs::write(&valid, empty_capture())?;
    fs::write(&malformed, capture_with_truncated_record())?;

    let output = run(
        &[
            "index",
            path_arg(&valid)?,
            path_arg(&malformed)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    let malformed_path = malformed.display().to_string();
    assert!(stderr.contains(&malformed_path), "{stderr}");
    assert_eq!(stderr.matches(&malformed_path).count(), 1, "{stderr}");
    assert!(!stderr.contains(&valid.display().to_string()), "{stderr}");
    assert!(!directory.exists());
    Ok(())
}

#[test]
fn duplicate_content_error_without_publishing() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("input.pcap");
    let directory = temporary.path().join("index");
    fs::write(&input, empty_capture())?;

    let result = run(
        &[
            "index",
            path_arg(&input)?,
            path_arg(&input)?,
            "--directory",
            path_arg(&directory)?,
        ],
        b"",
    )?;

    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let diagnostic = String::from_utf8(result.stderr)?;
    assert!(diagnostic.contains("duplicate capture source content"));
    assert!(!diagnostic.contains("UNIQUE constraint"));
    assert!(!directory.exists());
    Ok(())
}
