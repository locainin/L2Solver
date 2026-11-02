#[path = "../../../tests/fixtures/capture_paths.rs"]
mod capture_paths;
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

use std::process::Command;

#[test]
fn preserves_json_frame_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("json")
        .arg(fixtures.path("lldp.pcap"))
        .output()?;
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value.get("sequence"), Some(&serde_json::json!(1)));
    assert_eq!(value.get("status"), Some(&serde_json::json!("parsed")));
    assert_eq!(value.get("captured_len"), Some(&serde_json::json!(41)));
    assert_eq!(value.get("interface"), Some(&serde_json::json!(0)));
    assert_eq!(
        value.pointer("/timestamp/ticks"),
        Some(&serde_json::json!(1_000_000))
    );
    assert_eq!(
        value.pointer("/timestamp/exponent"),
        Some(&serde_json::json!(6))
    );
    let raw = value
        .get("raw_bytes")
        .ok_or("missing raw evidence")?
        .as_array()
        .ok_or("raw evidence is not array")?;
    let expected = crate::captures::LLDP
        .get(40..)
        .ok_or("fixture missing payload")?;
    assert_eq!(
        raw,
        &expected
            .iter()
            .map(|byte| serde_json::json!(byte))
            .collect::<Vec<_>>()
    );
    assert!(!output.stdout.contains(&0x1b));
    Ok(())
}

#[test]
fn reports_malformed_frame_status() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = crate::capture_paths::CapturePaths::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("json")
        .arg(fixtures.path("short.pcap"))
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value.get("status"), Some(&serde_json::json!("malformed")));
    assert_eq!(value.get("raw_bytes"), Some(&serde_json::json!([0])));
    assert!(
        value
            .get("diagnostic")
            .is_some_and(serde_json::Value::is_string)
    );
    Ok(())
}

#[test]
fn reports_unsupported_frame_status() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = crate::captures::LINUX_STP.to_vec();
    *capture
        .get_mut(24 + 16 + 19)
        .ok_or("missing STP version byte")? = 3;
    let directory = std::env::temp_dir().join(format!(
        "l2solver-json-unsupported-stp-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let path = directory.join("unsupported-stp.pcap");
    std::fs::write(&path, capture)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("json")
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value.get("status"), Some(&serde_json::json!("unsupported")));

    std::fs::remove_dir_all(directory)?;
    Ok(())
}
