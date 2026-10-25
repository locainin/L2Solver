use std::{
    error::Error,
    io::{BufWriter, Write},
    process::Command,
};
use tempfile::NamedTempFile;

#[test]
fn survey_former_event_limit_file() -> Result<(), Box<dyn Error>> {
    const FRAME_COUNT: u32 = 1_004_097;
    const FRAME: [u8; 14] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x88, 0xb5,
    ];
    let frame_length = u32::try_from(FRAME.len())?;

    let mut capture = NamedTempFile::new()?;
    {
        let mut writer = BufWriter::new(capture.as_file_mut());
        // Select little-endian classic PCAP with Ethernet frames
        writer.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1,
            0, 0, 0,
        ])?;
        // Reuse one zero-time record so the test stresses iteration, not fixture storage
        let mut record = [0; 16];
        record[8..12].copy_from_slice(&frame_length.to_le_bytes());
        record[12..16].copy_from_slice(&frame_length.to_le_bytes());
        for _ in 0..FRAME_COUNT {
            writer.write_all(&record)?;
            writer.write_all(&FRAME)?;
        }
        writer.flush()?;
    }
    let capture = capture.into_temp_path();

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["survey", "--format", "json"])
        .arg(&capture)
        .output()?;
    assert!(
        output.status.success(),
        "survey failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    assert_eq!(
        report.pointer("/quality/frames"),
        Some(&serde_json::json!(FRAME_COUNT))
    );
    assert_eq!(
        report.pointer("/interfaces/0/frames"),
        Some(&serde_json::json!(FRAME_COUNT))
    );
    Ok(())
}
