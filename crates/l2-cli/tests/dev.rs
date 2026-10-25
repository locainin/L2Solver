use std::{error::Error, process::Command};

#[test]
fn limits_distinguish_budgets_streaming_ceiling() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["dev", "limits"])
        .output()?;

    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    let default = l2_pcap::CaptureLimits::default();
    let streaming = l2_pcap::CaptureLimits::STREAMING;
    assert!(text.contains(&format!(
        "capture.default.max_input_bytes={}",
        default.max_input_bytes()
    )));
    assert!(text.contains(&format!(
        "capture.default.max_records={}",
        default.max_records()
    )));
    assert!(text.contains(&format!(
        "capture.streaming.max_input_bytes={}",
        streaming.max_input_bytes()
    )));
    assert!(text.contains(&format!(
        "capture.streaming.max_records={}",
        streaming.max_records()
    )));
    assert!(!text.lines().any(|line| {
        matches!(
            line.split_once('='),
            Some(("capture.max_input_bytes" | "capture.max_records", _))
        )
    }));
    Ok(())
}
