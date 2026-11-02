#![cfg(feature = "live")]

use std::{error::Error, fs, path::Path, process::Command};

#[test]
fn sorts_interfaces_and_rejects_unknown() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("interfaces")
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("NAME\tTYPE\tMODE\tPHY\tMONITOR\tINJECTION")
    );
    let rows: Vec<_> = lines.collect();
    assert!(rows.iter().any(|row| row.starts_with("lo\t")));
    assert!(rows.windows(2).all(|pair| {
        match pair {
            [left, right] => left
                .split_once('\t')
                .zip(right.split_once('\t'))
                .is_some_and(|((left_name, _), (right_name, _))| left_name < right_name),
            _ => false,
        }
    }));
    for row in rows {
        assert_eq!(row.split('\t').count(), 6);
    }
    let missing = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["listen", "l2solver-interface-that-does-not-exist", "1"])
        .output()?;
    assert!(!missing.status.success());
    assert!(String::from_utf8(missing.stderr)?.contains("unknown capture interface"));
    let missing_wifi = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["wifi-listen", "l2solver-interface-that-does-not-exist", "1"])
        .output()?;
    assert!(!missing_wifi.status.success());
    assert!(String::from_utf8(missing_wifi.stderr)?.contains("unknown capture interface"));
    let missing_survey = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "survey",
            "live",
            "l2solver-interface-that-does-not-exist",
            "1",
        ])
        .output()?;
    assert!(!missing_survey.status.success());
    let missing_record = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "record",
            "l2solver-interface-that-does-not-exist",
            "1",
            "evidence.pcapng",
        ])
        .output()?;
    assert!(!missing_record.status.success());
    assert!(String::from_utf8(missing_record.stderr)?.contains("unknown capture interface"));
    Ok(())
}

#[test]
fn observes_stp_from_live_bridge() -> Result<(), Box<dyn Error>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let directory =
        std::env::temp_dir().join(format!("l2solver-namespace-test-{}", std::process::id()));
    fs::create_dir(&directory)?;
    let output = Command::new("bash")
        .arg(root.join("tests/lab/namespace.sh"))
        .arg(env!("CARGO_BIN_EXE_l2solver"))
        .arg(&directory)
        .output()?;
    let success = output.status.success();
    if !success {
        return Err(format!(
            "isolated lab failed; logs retained at {}: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let observation = fs::read_to_string(directory.join("namespace-stp-observation.txt"))?;
    assert!(observation.contains("STP"));
    let survey: serde_json::Value = serde_json::from_str(&fs::read_to_string(
        directory.join("namespace-survey.json"),
    )?)?;
    let quality = survey
        .get("quality")
        .ok_or("assessment has no quality data")?;
    assert_eq!(quality.get("frames"), Some(&serde_json::json!(2)));
    assert_eq!(quality.get("malformed"), Some(&serde_json::json!(0)));
    assert_eq!(quality.get("invalid"), Some(&serde_json::json!(0)));
    assert_eq!(quality.get("truncated"), Some(&serde_json::json!(0)));
    assert_eq!(quality.get("dropped"), Some(&serde_json::json!(0)));
    assert_eq!(quality.get("incomplete"), Some(&serde_json::json!(true)));
    let wifi_status = fs::read_to_string(directory.join("namespace-wifi-status.txt"))?;
    assert!(wifi_status.contains("wireless assessment requires IEEE 802.11 or radiotap"));
    let recording_path = directory.join("namespace-record.pcapng");
    assert!(recording_path.is_file());
    verify_saved_recording(&recording_path)?;
    verify_recording_json_replay(&recording_path)?;
    fs::remove_dir_all(directory)?;
    Ok(())
}

fn verify_saved_recording(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut capture = l2_pcap::CaptureSource::new(fs::File::open(path)?)?;
    let mut packets = 0_u64;
    while let Some(frame) = capture.next_packet()? {
        assert!(!frame.bytes().is_empty());
        let identity = frame
            .metadata()
            .linux_interface()
            .ok_or("recorded interface identity is missing")?;
        assert!(identity.namespace_device() > 0);
        assert!(identity.namespace_inode() > 0);
        assert!(identity.interface_device() > 0);
        assert!(identity.interface_inode() > 0);
        assert!(identity.ifindex() > 0);
        packets = packets.checked_add(1).ok_or("packet count overflow")?;
    }
    assert_eq!(packets, 2);
    assert_eq!(capture.collection_summary().incomplete_sections, 1);
    Ok(())
}

fn verify_recording_json_replay(path: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("json")
        .arg(path)
        .output()?;
    assert_eq!(output.status.code(), Some(3));
    let rendered = String::from_utf8(output.stdout)?;
    let mut packets = 0_u64;
    let mut incomplete_sections = None;
    for line in rendered.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        if value.get("record_type").and_then(serde_json::Value::as_str) == Some("source_collection")
        {
            incomplete_sections = value
                .pointer("/source_collection/incomplete_sections")
                .and_then(serde_json::Value::as_u64);
        } else {
            let bytes = value
                .get("raw_bytes")
                .and_then(serde_json::Value::as_array)
                .ok_or("replay omitted raw packet bytes")?;
            assert!(!bytes.is_empty());
            packets = packets.checked_add(1).ok_or("packet count overflow")?;
        }
    }
    assert_eq!(packets, 2);
    assert_eq!(incomplete_sections, Some(1));
    Ok(())
}

#[test]
fn internal_lab_cannot_pid_isolation() -> Result<(), Box<dyn Error>> {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/lab/namespace.sh");
    let output = Command::new("bash")
        .env("L2SOLVER_LAB_INNER", "1")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_l2solver"))
        .arg(std::env::temp_dir())
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("requires the private PID namespace"));
    Ok(())
}
