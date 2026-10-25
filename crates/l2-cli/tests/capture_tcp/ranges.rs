use super::support::{bytes, frame, report, run};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;

#[test]
fn out_payload_frame_locations_hashes() -> Result<(), Box<dyn Error>> {
    let frames = [
        frame(100, 0x10, b"ab", vec![], 0)?,
        frame(104, 0x10, b"ef", vec![], 0)?,
        frame(102, 0x10, b"cd", vec![], 0)?,
    ];
    let output = run(
        &frames,
        &["--packet", "1", "--length", "6", "--format", "json"],
    )?;
    assert!(output.status.success());
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(true)));
    assert_eq!(bytes(&value, "/range/spans/0/bytes")?, b"abcdef");
    assert_eq!(
        value.pointer("/range/observations/2/payload_frame_offset"),
        Some(&json!(62))
    );
    assert_eq!(
        value.pointer("/range/observations/2/range_offset"),
        Some(&json!(2))
    );
    let digest = format!(
        "{:x}",
        Sha256::digest(frames.first().ok_or("missing frame")?.bytes())
    );
    assert_eq!(
        value.pointer("/sources/0/captured_sha256"),
        Some(&json!(digest))
    );
    assert_eq!(value.pointer("/capture_packets"), Some(&json!(3)));
    Ok(())
}

#[test]
fn text_report_locations_omit_hashes() -> Result<(), Box<dyn Error>> {
    let output = run(
        &[frame(100, 0x10, b"ab", vec![], 0)?],
        &["--packet", "1", "--length", "2"],
    )?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("Source packet 1"));
    assert!(!text.contains("sha256="));
    Ok(())
}

#[test]
fn conflicting_overlaps_remain_source_observations() -> Result<(), Box<dyn Error>> {
    let output = run(
        &[
            frame(10, 0x10, b"abcd", vec![], 0)?,
            frame(11, 0x10, b"XY", vec![], 0)?,
        ],
        &["--packet", "1", "--length", "4", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/range/conflicting_bytes"), Some(&json!(2)));
    assert_eq!(
        value.pointer("/range/spans/1/status"),
        Some(&json!("conflict"))
    );
    assert!(value.pointer("/range/spans/1/bytes").is_none());
    assert_eq!(bytes(&value, "/range/observations/1/bytes")?, b"XY");
    Ok(())
}

#[test]
fn explicit_sequence_wrap_clips_prefix() -> Result<(), Box<dyn Error>> {
    let start = (u32::MAX - 1).to_string();
    let output = run(
        &[
            frame(u32::MAX - 2, 0x10, b"zab", vec![], 0)?,
            frame(0, 0x10, b"cde", vec![], 0)?,
        ],
        &[
            "--packet",
            "1",
            "--sequence",
            &start,
            "--length",
            "5",
            "--format",
            "json",
        ],
    )?;
    assert!(output.status.success());
    let value = report(&output)?;
    assert_eq!(bytes(&value, "/range/spans/0/bytes")?, b"abcde");
    assert_eq!(
        value.pointer("/range/observations/0/payload_frame_offset"),
        Some(&json!(63))
    );
    Ok(())
}

#[test]
fn syn_adjusts_without_creating_payload() -> Result<(), Box<dyn Error>> {
    let output = run(
        &[frame(99, 0x02, b"abc", vec![], 0)?],
        &["--packet", "1", "--length", "3", "--format", "json"],
    )?;
    assert!(output.status.success());
    let value = report(&output)?;
    assert_eq!(value.pointer("/range/start_sequence"), Some(&json!(100)));
    assert_eq!(bytes(&value, "/range/spans/0/bytes")?, b"abc");
    Ok(())
}

#[test]
fn packet_window_earlier_later_reuse() -> Result<(), Box<dyn Error>> {
    let frames = [
        frame(10, 0x10, b"ZZ", vec![], 0)?,
        frame(10, 0x10, b"ab", vec![], 0)?,
        frame(10, 0x10, b"XY", vec![], 0)?,
    ];
    let output = run(
        &frames,
        &[
            "--packet",
            "2",
            "--last-packet",
            "2",
            "--length",
            "2",
            "--format",
            "json",
        ],
    )?;
    assert!(output.status.success());
    let value = report(&output)?;
    assert_eq!(bytes(&value, "/range/spans/0/bytes")?, b"ab");
    assert_eq!(value.pointer("/first_packet"), Some(&json!(2)));
    assert_eq!(value.pointer("/last_packet"), Some(&json!(2)));
    assert_eq!(value.pointer("/capture_packets"), Some(&json!(3)));
    Ok(())
}
