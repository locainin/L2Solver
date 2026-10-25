use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
};
use l2_cli::arguments::{Command, OutputFormat, parse};
use l2_pcap::{
    InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgWriter, TimestampResolution, TimestampSource,
};
use std::{
    error::Error,
    ffi::OsString,
    io::Write,
    process::{Command as ProcessCommand, Stdio},
};

fn argument_list(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn classic_capture(packets: &[&[u8]]) -> Vec<u8> {
    let mut capture = Vec::new();
    capture.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    capture.extend_from_slice(&2_u16.to_le_bytes());
    capture.extend_from_slice(&4_u16.to_le_bytes());
    capture.extend_from_slice(&0_i32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    for (index, packet) in packets.iter().enumerate() {
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&u32::try_from(index).unwrap_or(u32::MAX).to_le_bytes());
        capture.extend_from_slice(
            &u32::try_from(packet.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        capture.extend_from_slice(
            &u32::try_from(packet.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        capture.extend_from_slice(packet);
    }
    capture
}

fn classic_capture_with_original_lengths(
    packets: &[&[u8]],
    original_lengths: &[u32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if packets.len() != original_lengths.len() {
        return Err("one original length is required for each packet".into());
    }

    let mut capture = classic_capture(packets);
    let mut header_offset = 24_usize;
    for (packet, original_length) in packets.iter().zip(original_lengths) {
        let original_length_offset = header_offset
            .checked_add(12)
            .ok_or("original length offset overflow")?;
        let field = capture
            .get_mut(original_length_offset..original_length_offset + 4)
            .ok_or("record original length field is missing")?;
        field.copy_from_slice(&original_length.to_le_bytes());
        header_offset = header_offset
            .checked_add(16)
            .and_then(|offset| offset.checked_add(packet.len()))
            .ok_or("next record header offset overflow")?;
    }
    Ok(capture)
}

fn multi_interface_capture() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    for (index, link_type, bytes) in [
        (0_u32, LinkType::Ethernet, vec![0xaa]),
        (1_u32, LinkType::Ieee80211, vec![0xbb, 0xcc]),
    ] {
        let interface = InterfaceId { section: 0, index };
        let config = InterfaceConfig::new_with_link_type(
            link_type,
            64,
            TimestampResolution::MICROSECOND,
            0,
            FcsStatus::Unknown,
        )?;
        writer.add_interface(interface, config)?;
        let original_length = u32::try_from(bytes.len())?;
        let timestamp = CaptureTimestamp::new(
            1,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::Unknown,
        );
        let metadata = CaptureMetadata::new(
            interface,
            original_length,
            None,
            Some(timestamp),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
        .with_link_type(link_type);
        writer.write_frame(&CapturedFrame::new(bytes, metadata)?)?;
    }
    writer.finish()?;
    Ok(writer.into_inner())
}

struct CaptureFile {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl CaptureFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for CaptureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn capture_file(name: &str, bytes: &[u8]) -> Result<CaptureFile, Box<dyn Error>> {
    let directory = std::env::temp_dir().join(format!(
        "l2solver-capture-compare-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("input.pcap");
    std::fs::write(&path, bytes)?;
    Ok(CaptureFile { directory, path })
}

fn assert_parse_rejected(arguments: &[&str]) {
    assert!(
        parse(&argument_list(arguments)).is_err(),
        "accepted {arguments:?}"
    );
}

fn json_value<'report>(
    report: &'report serde_json::Value,
    path: &str,
) -> Result<&'report serde_json::Value, Box<dyn Error>> {
    report
        .pointer(path)
        .ok_or_else(|| format!("missing JSON field {path}").into())
}

fn json_number(report: &serde_json::Value, path: &str) -> Result<u64, Box<dyn Error>> {
    json_value(report, path)?
        .as_u64()
        .ok_or_else(|| format!("JSON field {path} is not an unsigned integer").into())
}

fn json_text<'report>(
    report: &'report serde_json::Value,
    path: &str,
) -> Result<&'report str, Box<dyn Error>> {
    json_value(report, path)?
        .as_str()
        .ok_or_else(|| format!("JSON field {path} is not text").into())
}

#[test]
fn parser_accepts_ranges_json_format() -> Result<(), Box<dyn Error>> {
    let Command::CaptureCompare(options) = parse(&argument_list(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "1",
        "--right-packet",
        "2",
        "--left-offset",
        "12",
        "--right-offset",
        "9",
        "--length",
        "4",
        "--xor-key",
        "0102ff",
        "--format",
        "json",
    ]))?
    else {
        return Err("capture compare command was not selected".into());
    };
    assert_eq!(options.left_packet, 1);
    assert_eq!(options.right_packet, 2);
    assert_eq!(options.left_offset, 12);
    assert_eq!(options.right_offset, 9);
    assert_eq!(options.length, Some(4));
    assert_eq!(options.xor_key, Some(vec![1, 2, 255]));
    assert_eq!(options.format, OutputFormat::Json);
    Ok(())
}

#[test]
fn parser_packet_indices_outside_ceiling() {
    assert_parse_rejected(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "0",
        "--right-packet",
        "1",
    ]);
    assert_parse_rejected(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "1",
        "--right-packet",
        "1000001",
    ]);
}

#[test]
fn parser_offsets_byte_range_limits() {
    assert_parse_rejected(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "1",
        "--right-packet",
        "1",
        "--left-offset",
        "65536",
    ]);
    for length in ["0", "65536"] {
        assert_parse_rejected(&[
            "capture",
            "compare",
            "-",
            "--left-packet",
            "1",
            "--right-packet",
            "1",
            "--length",
            length,
        ]);
    }
}

#[test]
fn parser_unsupported_odd_xor_keys() {
    assert_parse_rejected(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "1",
        "--right-packet",
        "1",
        "--format",
        "html",
    ]);
    for key in ["é", "0"] {
        assert_parse_rejected(&[
            "capture",
            "compare",
            "-",
            "--left-packet",
            "1",
            "--right-packet",
            "1",
            "--xor-key",
            key,
        ]);
    }
}

#[test]
fn parser_xor_over_byte_limit() {
    let overlong_key = "00".repeat(257);
    assert_parse_rejected(&[
        "capture",
        "compare",
        "-",
        "--left-packet",
        "1",
        "--right-packet",
        "1",
        "--xor-key",
        &overlong_key,
    ]);
}

#[test]
fn malformed_raw_json_provenance() -> Result<(), Box<dyn Error>> {
    let path = capture_file(
        "raw-packets-json",
        &classic_capture(&[&[0xaa, 0xbb], &[0xbb, 0xaa, 0xbc]]),
    )?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--right-offset",
            "1",
            "--format",
            "json",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_number(&report, "/left/packet_index")?, 1);
    assert_eq!(json_number(&report, "/left/interface/section")?, 0);
    assert_eq!(json_number(&report, "/left/interface/index")?, 0);
    assert_eq!(json_number(&report, "/left/link_type/raw")?, 1);
    assert_eq!(json_number(&report, "/left/captured_frame_offset")?, 0);
    assert_eq!(json_number(&report, "/left/selected_length")?, 2);
    assert_eq!(json_number(&report, "/right/captured_frame_offset")?, 1);
    assert_eq!(json_number(&report, "/right/selected_length")?, 2);
    for side in ["left", "right"] {
        assert_eq!(
            json_value(&report, &format!("/{side}/truncated"))?.as_bool(),
            Some(false)
        );
    }
    assert_eq!(json_number(&report, "/comparison/differing_bytes")?, 1);
    assert_eq!(json_number(&report, "/comparison/right_tail_length")?, 0);
    assert_eq!(json_number(&report, "/comparison/spans/0/offset")?, 1);
    assert_eq!(
        json_text(&report, "/left/captured_sha256")?,
        "d798d1fac6bd4bb1c11f50312760351013379a0ab6f0a8c0af8a506b96b2525a"
    );
    assert_eq!(
        json_text(&report, "/right/captured_sha256")?,
        "c17ef45d463350e992bb466062d229a41899e28366be7a01105b4bd8c08a3481"
    );
    assert!(report.get("supplied_xor_key_hex").is_none());
    assert!(json_text(&report, "/interpretation")?.contains("does not infer"));
    Ok(())
}

#[test]
fn malformed_raw_text_provenance() -> Result<(), Box<dyn Error>> {
    let path = capture_file(
        "raw-packets-text",
        &classic_capture(&[&[0xaa, 0xbb], &[0xbb, 0xaa, 0xbc]]),
    )?;
    let text = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--right-offset",
            "1",
        ])
        .output()?;
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let text = String::from_utf8(text.stdout)?;
    assert!(text.contains("Unequal span: left byte 1 / right byte 2, length 1"));
    assert!(!text.contains("sha256="));
    assert!(!text.contains("Supplied XOR key (hex):"));
    assert!(text.contains("does not infer encryption, concealment, or intent"));
    Ok(())
}

#[test]
fn truncated_source_frames_json_text() -> Result<(), Box<dyn Error>> {
    let capture =
        classic_capture_with_original_lengths(&[&[0xaa, 0xbb], &[0xaa, 0xbc]], &[20, 20])?;
    let path = capture_file("truncated-frames", &capture)?;
    let json = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--format",
            "json",
        ])
        .output()?;

    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)?;
    assert_eq!(json_number(&report, "/left/captured_length")?, 2);
    assert_eq!(json_number(&report, "/left/original_length")?, 20);
    assert_eq!(
        json_value(&report, "/left/truncated")?.as_bool(),
        Some(true)
    );
    assert_eq!(json_number(&report, "/right/captured_length")?, 2);
    assert_eq!(json_number(&report, "/right/original_length")?, 20);
    assert_eq!(
        json_value(&report, "/right/truncated")?.as_bool(),
        Some(true)
    );
    assert_eq!(json_number(&report, "/comparison/compared_length")?, 2);

    let text = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args(["--left-packet", "1", "--right-packet", "2"])
        .output()?;
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let text = String::from_utf8(text.stdout)?;
    assert!(text.contains("captured=2 original=20"));
    assert!(text.contains("truncated=true"));
    Ok(())
}

#[test]
fn per_packet_pcapng_interfaces_types() -> Result<(), Box<dyn Error>> {
    let path = capture_file("interface-metadata", &multi_interface_capture()?)?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--format",
            "json",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_number(&report, "/left/interface/index")?, 0);
    assert_eq!(json_number(&report, "/left/link_type/raw")?, 1);
    assert_eq!(json_number(&report, "/right/interface/index")?, 1);
    assert_eq!(json_number(&report, "/right/link_type/raw")?, 105);
    Ok(())
}

#[test]
fn clean_eof_emitting_comparison() -> Result<(), Box<dyn Error>> {
    let mut capture = classic_capture(&[&[1, 2], &[1, 3]]);
    capture.extend_from_slice(&[0, 0, 0]);
    let path = capture_file("bad-tail", &capture)?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args(["--left-packet", "1", "--right-packet", "2"])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("record header"));
    Ok(())
}

#[test]
fn missing_selected_packets_scanning() -> Result<(), Box<dyn Error>> {
    let path = capture_file("missing-packet", &classic_capture(&[&[1, 2]]))?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args(["--left-packet", "1", "--right-packet", "2"])
        .output()?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("packet 2"));
    Ok(())
}

#[test]
fn selected_ranges_tails_xor_status() -> Result<(), Box<dyn Error>> {
    let path = capture_file("tails", &classic_capture(&[&[1, 2, 3, 4], &[1, 2]]))?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--xor-key",
            "00",
            "--format",
            "json",
        ])
        .output()?;

    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_number(&report, "/comparison/left_tail_length")?, 2);
    assert_eq!(json_number(&report, "/comparison/right_tail_length")?, 0);
    assert_eq!(json_number(&report, "/left/selected_length")?, 4);
    assert_eq!(json_number(&report, "/right/selected_length")?, 2);
    assert_eq!(
        json_text(&report, "/comparison/xor_verification/status")?,
        "not_comparable"
    );
    Ok(())
}

#[test]
fn supplied_repeating_relation_without_interpreting() -> Result<(), Box<dyn Error>> {
    let path = capture_file(
        "xor-match",
        &classic_capture(&[&[0x10, 0x20, 0x30, 0x40], &[0x11, 0x22, 0x31, 0x42]]),
    )?;
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--xor-key",
            "0102",
            "--format",
            "json",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        json_text(&report, "/comparison/xor_verification/status")?,
        "verified"
    );
    assert_eq!(json_text(&report, "/supplied_xor_key_hex")?, "0102");
    assert!(json_text(&report, "/interpretation")?.contains("does not infer encryption"));

    let text = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "compare"])
        .arg(path.path())
        .args([
            "--left-packet",
            "1",
            "--right-packet",
            "2",
            "--xor-key",
            "0102",
        ])
        .output()?;
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(String::from_utf8(text.stdout)?.contains("Supplied XOR key (hex): 0102"));
    Ok(())
}

#[test]
fn stdin_closed_stdout_command_successful() -> Result<(), Box<dyn Error>> {
    let capture = classic_capture(&[&[1, 2, 3], &[1, 2, 4]]);
    let mut child = ProcessCommand::new(env!("CARGO_BIN_EXE_l2solver"))
        .args([
            "capture",
            "compare",
            "-",
            "--left-packet",
            "1",
            "--right-packet",
            "2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("stdin pipe unavailable")?;
    let stdout = child.stdout.take().ok_or("stdout pipe unavailable")?;
    drop(stdout);
    stdin.write_all(&capture)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
