use std::process::{Command, Stdio};

#[test]
fn reports_no_stp_without_verdict() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["observe", "../../tests/pcaps/lldp.pcap"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("Capture: ../../tests/pcaps/lldp.pcap"));
    assert!(text.contains("frames=1 stp=0"));
    assert!(text.contains("timestamp_regressions=0 missing_timestamps=0"));
    assert!(text.contains("STP observation: complete"));
    assert!(!text.contains("PASS"));
    Ok(())
}

#[test]
fn matches_tshark_stp_fields() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["observe", "../../tests/pcaps/linux-stp.pcap"])
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("36:09:f1:ae:e3:29 (priority=32768 extension=0)"));
    assert!(text.contains("frames=1 stp=1"));
    assert!(text.contains("event=1 time=0ns"));
    Ok(())
}

#[test]
fn reports_replay_time_regressions() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_bytes!("../../../tests/pcaps/linux-stp.pcap");
    let header = source.get(..24).ok_or("missing PCAP header")?;
    let record = source.get(24..).ok_or("missing PCAP record")?;
    let directory =
        std::env::temp_dir().join(format!("l2solver-replay-time-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    for (name, second, expected_status, expected_text) in [
        ("expiry.pcap", 21_u32, 0, "observation expired"),
        ("regression.pcap", 0_u32, 3, "timestamp_regressions=1"),
        ("truncated.pcap", 2_u32, 3, "truncated=3"),
    ] {
        let mut capture = header.to_vec();
        for seconds in [1_u32, second, second + 1] {
            // Keep kernel frame bytes intact and alter only record timestamps
            let record_start = capture.len();
            capture.extend_from_slice(&seconds.to_le_bytes());
            capture.extend_from_slice(&0_u32.to_le_bytes());
            capture.extend_from_slice(record.get(8..).ok_or("missing record lengths")?);
            if name == "truncated.pcap" {
                capture
                    .get_mut(record_start + 12..record_start + 16)
                    .ok_or("missing original length")?
                    .copy_from_slice(&100_u32.to_le_bytes());
            }
        }
        let path = directory.join(name);
        std::fs::write(&path, capture)?;
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg("observe")
            .arg(path)
            .output()?;
        assert_eq!(output.status.code(), Some(expected_status));
        let text = String::from_utf8(output.stdout)?;
        assert!(text.contains(expected_text));
        assert!(text.contains("event=1 time=0ns"));
        if name == "expiry.pcap" {
            assert!(text.contains("event=3 time=21000000000ns"));
        }
    }
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn malformed_capture_returns_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["observe", "../../tests/pcaps/short.pcap"])
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("malformed Ethernet"));
    assert!(text.contains("STP observation: incomplete"));
    Ok(())
}

#[test]
fn malformed_iteration_names_input() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("truncated-record.pcap");
    let mut capture = include_bytes!("../../../tests/pcaps/lldp.pcap")
        .get(..24)
        .ok_or("missing capture header")?
        .to_vec();
    for value in [0_u32, 0, 14, 14] {
        capture.extend_from_slice(&value.to_le_bytes());
    }
    capture.push(0);
    std::fs::write(&path, capture)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "observe"])
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    let path = path.display().to_string();
    assert!(stderr.contains(&path), "{stderr}");
    assert_eq!(stderr.matches(&path).count(), 1, "{stderr}");
    Ok(())
}

#[test]
fn counts_semantic_invalidity_as_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = include_bytes!("../../../tests/pcaps/lldp.pcap")
        .get(..24)
        .ok_or("missing capture header")?
        .to_vec();
    // End-only LLDP parses mechanically but lacks all mandatory fields
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x88, 0xcc, 0, 0]);
    for value in [1_u32, 0, 16, 16] {
        capture.extend_from_slice(&value.to_le_bytes());
    }
    capture.extend_from_slice(&frame);
    let directory = std::env::temp_dir().join(format!(
        "l2solver-invalid-observation-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory)?;
    let path = directory.join("invalid.pcap");
    std::fs::write(&path, capture)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("observe")
        .arg(path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stdout)?
            .contains("frames=1 stp=0 malformed=0 invalid=1 unsupported_stp=0 truncated=0")
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[test]
fn counts_unsupported_stp_as_incomplete() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = include_bytes!("../../../tests/pcaps/linux-stp.pcap").to_vec();
    *capture.get_mut(59).ok_or("missing STP version byte")? = 3;
    let directory =
        std::env::temp_dir().join(format!("l2solver-unsupported-stp-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("unsupported.pcap");
    std::fs::write(&path, capture)?;

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("observe")
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("unsupported STP protocol version 3"));
    assert!(text.contains("unsupported_stp=1"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn closed_pipe_keeps_incomplete_status() -> Result<(), Box<dyn std::error::Error>> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["observe", "../../tests/pcaps/short.pcap"])
        .stdout(Stdio::piped())
        .spawn()?;
    drop(process.stdout.take().ok_or("missing stdout")?);

    assert_eq!(process.wait()?.code(), Some(3));
    Ok(())
}

fn block(kind: u32, body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let length = u32::try_from(body.len() + 12)?;
    let mut bytes = kind.to_le_bytes().to_vec();
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&length.to_le_bytes());
    Ok(bytes)
}

#[test]
fn reports_missing_simple_packet_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = pcapng_prefix(None)?;
    let frame = include_bytes!("../../../tests/pcaps/linux-stp.pcap")
        .get(40..)
        .ok_or("missing frame")?;
    let mut packet = u32::try_from(frame.len())?.to_le_bytes().to_vec();
    packet.extend_from_slice(frame);
    packet.resize(packet.len().next_multiple_of(4), 0);
    capture.extend(block(3, &packet)?);
    let directory =
        std::env::temp_dir().join(format!("l2solver-missing-time-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("simple.pcapng");
    std::fs::write(&path, capture)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("observe")
        .arg(path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("missing_timestamps=1"));
    assert!(text.contains("time=0ns"));
    assert!(text.contains("frames=1 stp=1"));
    assert!(text.contains("event=1 time=0ns"));
    std::fs::remove_dir_all(directory)?;
    Ok(())
}

fn pcapng_prefix(resolution: Option<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut capture = block(
        0x0a0d_0d0a,
        &[
            0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    )?;
    let mut interface = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
    if let Some(resolution) = resolution {
        interface.extend_from_slice(&[9, 0, 1, 0, resolution, 0, 0, 0, 0, 0, 0, 0]);
    }
    capture.extend(block(1, &interface)?);
    Ok(capture)
}

#[test]
fn preserves_unsupported_timestamp_span() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = pcapng_prefix(Some(0))?;
    let frame = include_bytes!("../../../tests/pcaps/linux-stp.pcap")
        .get(40..)
        .ok_or("missing frame")?;
    for ticks in [0_u64, u64::MAX] {
        let mut packet = 0_u32.to_le_bytes().to_vec();
        packet.extend_from_slice(&u32::try_from(ticks >> 32)?.to_le_bytes());
        packet.extend_from_slice(&u32::try_from(ticks & 0xffff_ffff)?.to_le_bytes());
        packet.extend_from_slice(&u32::try_from(frame.len())?.to_le_bytes());
        packet.extend_from_slice(&u32::try_from(frame.len())?.to_le_bytes());
        packet.extend_from_slice(frame);
        packet.resize(packet.len().next_multiple_of(4), 0);
        capture.extend(block(6, &packet)?);
    }
    let directory = std::env::temp_dir().join(format!("l2solver-range-{}", std::process::id()));
    std::fs::create_dir(&directory)?;
    let path = directory.join("range.pcapng");
    std::fs::write(&path, capture)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("observe")
        .arg(&path)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("exceeds the observation clock range"));
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("json")
        .arg(&path)
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(records.len(), 2);
    assert_eq!(
        records
            .get(1)
            .and_then(|value| value.pointer("/timestamp/ticks")),
        Some(&serde_json::json!(u64::MAX))
    );
    std::fs::remove_dir_all(directory)?;
    Ok(())
}
