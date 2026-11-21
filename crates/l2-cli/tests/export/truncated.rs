#[path = "../../../../tests/fixtures/truncated_tcp.rs"]
mod fixture;

use std::{error::Error, fs};

#[test]
fn truncated_conflict_not_exported_complete() -> Result<(), Box<dyn Error>> {
    let payload = b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
    let mut conflict = payload.to_vec();
    let body = conflict.len() - 3;
    *conflict.get_mut(body).ok_or("missing body")? = b'x';
    let frames = [
        fixture::tcp(100, 2, b"", 0)?,
        fixture::tcp(101, 0x18, payload, 0)?,
        fixture::tcp(101, 0x18, &conflict, 8)?,
        fixture::tcp(101 + u32::try_from(payload.len())?, 0x11, b"", 0)?,
    ];
    let captured: Vec<_> = frames.iter().map(|frame| frame.bytes().to_vec()).collect();
    let mut bytes = super::capture_from_frames(&captured)?;
    let original_offset = 24
        + 16
        + captured.first().ok_or("missing first frame")?.len()
        + 16
        + captured.get(1).ok_or("missing second frame")?.len()
        + 12;
    bytes
        .get_mut(original_offset..original_offset + 4)
        .ok_or("missing original length")?
        .copy_from_slice(
            &frames
                .get(2)
                .ok_or("missing truncated frame")?
                .metadata()
                .original_len()
                .to_le_bytes(),
        );
    let temporary = tempfile::tempdir()?;
    let input = temporary.path().join("capture.pcap");
    let destination = temporary.path().join("output");
    fs::write(&input, bytes)?;
    let output = super::export(&input, Some(&destination))?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("manifest.json"))?)?;
    assert!(
        !manifest
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing artifacts")?
            .iter()
            .any(|artifact| {
                artifact
                    .get("provenance")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|origins| {
                        origins.iter().any(|origin| {
                            origin.get("category").and_then(serde_json::Value::as_str)
                                == Some("native_http_body")
                        })
                    })
            })
    );
    assert!(
        fs::read_to_string(destination.join("summary.txt"))?
            .contains("Supported transport records: 4")
    );
    Ok(())
}
