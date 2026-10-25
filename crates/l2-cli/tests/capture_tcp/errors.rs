use super::support::{capture, frame, report, run, run_bytes};
use serde_json::json;
use std::error::Error;

#[test]
fn gaps_incomplete_explicit_text_description() -> Result<(), Box<dyn Error>> {
    let frames = [frame(10, 0x10, b"ab", vec![], 0)?];
    let output = run(&frames, &["--packet", "1", "--length", "4"])?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("2 without a retained value"));
    assert!(text.contains("connection generation"));
    Ok(())
}

#[test]
fn malformed_tail_never_partial() -> Result<(), Box<dyn Error>> {
    let mut bytes = capture(&[frame(10, 0x10, b"ab", vec![], 0)?])?;
    bytes.extend_from_slice(&[0, 0, 0]);
    let output = run_bytes(
        &bytes,
        &[
            "--packet",
            "1",
            "--last-packet",
            "1",
            "--length",
            "2",
            "--format",
            "json",
        ],
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn invalid_ranges_window_usage_errors() -> Result<(), Box<dyn Error>> {
    for args in [
        vec!["--packet", "0", "--length", "1"],
        vec!["--packet", "1", "--length", "0"],
        vec!["--packet", "1", "--length", "65536"],
        vec!["--packet", "2", "--last-packet", "1", "--length", "1"],
        vec!["--packet", "1", "--sequence", "4294967296", "--length", "1"],
        vec!["--packet", "1", "--format", "html", "--length", "1"],
    ] {
        let output = run_bytes(&[], &args)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn missing_anchor_packet_input_error() -> Result<(), Box<dyn Error>> {
    let frames = [frame(10, 0x10, b"ab", vec![], 0)?];
    for args in [
        vec!["--packet", "2", "--length", "1"],
        vec!["--packet", "1", "--last-packet", "2", "--length", "1"],
    ] {
        let output = run(&frames, &args)?;
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn empty_anchor_requires_explicit_sequence() -> Result<(), Box<dyn Error>> {
    let frames = [
        frame(10, 0x02, b"", vec![], 0)?,
        frame(11, 0x10, b"a", vec![], 0)?,
    ];
    let rejected = run(&frames, &["--packet", "1", "--length", "1"])?;
    assert_eq!(rejected.status.code(), Some(1));
    let output = run(
        &frames,
        &[
            "--packet",
            "1",
            "--sequence",
            "11",
            "--length",
            "1",
            "--format",
            "json",
        ],
    )?;
    assert!(output.status.success());
    let value = report(&output)?;
    assert_eq!(
        value.pointer("/range/observations/0/flags"),
        Some(&json!(2))
    );
    Ok(())
}
