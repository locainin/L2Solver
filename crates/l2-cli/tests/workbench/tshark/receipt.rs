use super::super::{TsharkOptions, decode_packets, prepare_capture, run};
use super::{assert_error_contains, json_field};
use l2_workbench::{sha256, tshark::TsharkReport};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
};

#[path = "invocations.rs"]
mod invocations;

fn options(capture: &Path, executable: &Path) -> TsharkOptions {
    TsharkOptions {
        capture: capture.to_owned(),
        executable: executable.to_owned(),
        tls_keylog: None,
        output: None,
        timeout_seconds: 30,
        max_input_mib: 1,
        max_metadata_mib: 1,
        max_output_mib: 16,
        max_diagnostics_mib: 1,
    }
}

fn fixture(
    directory: &Path,
    frames: &[u8],
    packets: &Value,
) -> Result<TsharkOptions, Box<dyn Error>> {
    let executable = directory.join("tshark-fixture");
    // Close and sync the fixture before another test thread can ask the kernel to execute it
    let mut fixture = File::create(&executable)?;
    fixture.write_all(include_bytes!("fake_tshark.sh"))?;
    fixture.sync_all()?;
    drop(fixture);
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    fs::write(directory.join("frames.txt"), frames)?;
    fs::write(directory.join("packets.json"), serde_json::to_vec(packets)?)?;
    let capture = directory.join("capture.pcap");
    fs::write(&capture, b"source fixture")?;
    Ok(options(&capture, &executable))
}

fn packets(count: u64) -> Value {
    Value::Array(
        (1..=count)
            .map(|number| json!({"_source":{"layers":{"frame":{"frame.number":number}}}}))
            .collect(),
    )
}

fn produce(options: &TsharkOptions) -> Result<Value, Box<dyn Error>> {
    let mut output = Vec::new();
    run(options, &mut output)?;
    Ok(serde_json::from_slice(&output)?)
}

#[test]
fn complete_source_lossless_recorded_receipt() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n2\n", &packets(2))?;

    let report = produce(&options)?;

    assert_eq!(json_field(&report, "schema_version")?, 2);
    assert_eq!(
        json_field(&report, "source_packet_count")?,
        &json!({"count":2,"output_sha256":sha256(b"1\n2\n")})
    );
    let tool = json_field(&report, "tool")?;
    let invocations = json_field(tool, "invocations")?
        .as_array()
        .ok_or("tool invocations must be an array")?;
    let count = invocations
        .iter()
        .find(|invocation| invocation.get("phase") == Some(&json!("packet_count")))
        .ok_or("packet count invocation missing")?;
    assert_eq!(
        json_field(count, "argv")?,
        &json!([
            "-n",
            "-C",
            "l2solver-offline",
            "--disable-all-protocols",
            "-r",
            "<source-snapshot>",
            "-T",
            "fields",
            "-e",
            "frame.number"
        ])
    );
    let decode = invocations
        .iter()
        .find(|invocation| invocation.get("phase") == Some(&json!("decode")))
        .ok_or("decode invocation missing")?;
    assert!(
        json_field(decode, "argv")?
            .as_array()
            .ok_or("decode arguments must be an array")?
            .contains(&json!("--no-duplicate-keys"))
    );
    assert!(
        json_field(tool, "diagnostics")?
            .as_array()
            .ok_or("tool diagnostics must be an array")?
            .iter()
            .any(|diagnostic| {
                diagnostic.get("phase") == Some(&json!("packet_count"))
                    && diagnostic.get("sha256")
                        == Some(&json!(sha256(b"packet count diagnostic\n")))
            })
    );
    serde_json::from_value::<TsharkReport>(report)?.validate()?;
    Ok(())
}

#[test]
fn missing_extra_decoded_packets_written() -> Result<(), Box<dyn Error>> {
    for decoded_count in [0, 1, 3] {
        let directory = tempfile::tempdir()?;
        let options = fixture(directory.path(), b"1\n2\n", &packets(decoded_count))?;
        let mut output = Vec::new();

        assert_error_contains(run(&options, &mut output), "packet count")?;

        assert_eq!(output.len(), 0);
    }
    Ok(())
}

#[test]
fn empty_traversal_decoded_packet_array() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"", &packets(0))?;

    let report = produce(&options)?;

    assert_eq!(
        json_field(json_field(&report, "source_packet_count")?, "count")?,
        0
    );
    serde_json::from_value::<TsharkReport>(report)?.validate()?;
    Ok(())
}

#[test]
fn malformed_truncated_cannot_source_completeness() -> Result<(), Box<dyn Error>> {
    for frames in [
        b"\n".as_slice(),
        b"1\n\n",
        b"1\n1\n",
        b"1\n3\n",
        b"0\n",
        b"01\n",
        b"+1\n",
        b"1\t2\n",
        b"1 \n",
        b"18446744073709551616\n",
        b"1",
        b"1\n2",
        b"\xff\n",
    ] {
        let directory = tempfile::tempdir()?;
        let options = fixture(directory.path(), frames, &packets(1))?;
        let mut output = Vec::new();

        assert!(run(&options, &mut output).is_err(), "accepted {frames:?}");

        assert_eq!(output.len(), 0);
    }
    Ok(())
}

#[test]
fn empty_explicit_rejected_tool_inspection() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut options = fixture(directory.path(), b"1\n", &packets(1))?;
    let keylog = directory.path().join("empty-keys.log");
    fs::write(&keylog, b"")?;
    options.tls_keylog = Some(keylog);

    assert_error_contains(prepare_capture(&options), "key log must be nonempty")?;
    Ok(())
}

#[test]
fn prepared_profile_private_empty_directory() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &packets(1))?;

    let prepared = prepare_capture(&options)?;

    let extcap = prepared
        .environment
        .iter()
        .find_map(|(name, value)| (name == "WIRESHARK_EXTCAP_DIR").then_some(value))
        .ok_or("private extcap directory environment is missing")?;
    let extcap_path = Path::new(extcap);
    assert!(extcap_path.is_dir());
    assert_eq!(extcap_path.parent(), prepared.source.path.parent());
    assert!(fs::read_dir(extcap_path)?.next().is_none());
    let report = produce(&options)?;
    assert!(
        report
            .pointer("/tool/profile/process_environment")
            .and_then(Value::as_str)
            .ok_or("profile environment receipt missing")?
            .contains("private_empty_extcap_directory")
    );
    Ok(())
}

#[test]
fn consumer_decoded_frame_numbers_consecutive() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n2\n", &packets(2))?;
    let report = produce(&options)?;
    for count in [0, 1] {
        let mut incomplete = report.clone();
        json_field(&incomplete, "packets")?;
        incomplete
            .get_mut("packets")
            .and_then(Value::as_array_mut)
            .ok_or("packet array missing")?
            .truncate(count);

        let parsed: TsharkReport = serde_json::from_value(incomplete)?;

        assert_error_contains(parsed.validate(), "packet count")?;
    }
    Ok(())
}

#[test]
fn consumer_requires_source_bound_invocation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &packets(1))?;
    let report = produce(&options)?;
    for (pointer, replacement) in [
        ("/source_packet_count/output_sha256", json!("invalid")),
        (
            "/tool/invocations/3/argv/5",
            json!("different-capture.pcap"),
        ),
        ("/tool/invocations/3/phase", json!("unrecorded_count")),
    ] {
        let mut invalid = report.clone();
        *invalid
            .pointer_mut(pointer)
            .ok_or("receipt field missing")? = replacement;

        let parsed: TsharkReport = serde_json::from_value(invalid)?;

        assert!(parsed.validate().is_err(), "accepted change to {pointer}");
    }
    let mut missing = report;
    missing
        .as_object_mut()
        .ok_or("report must be an object")?
        .remove("source_packet_count");
    assert!(serde_json::from_value::<TsharkReport>(missing).is_err());
    Ok(())
}

#[test]
fn legacy_without_precise_regeneration_error() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &packets(1))?;
    let mut report = produce(&options)?;
    *report
        .get_mut("schema_version")
        .ok_or("schema version missing")? = json!(1);
    report
        .as_object_mut()
        .ok_or("report must be an object")?
        .remove("source_packet_count");

    assert_error_contains(
        serde_json::from_value::<TsharkReport>(report),
        "schema version 1 lacks source packet-count evidence; regenerate",
    )?;
    Ok(())
}

#[test]
fn merged_duplicate_values_reassembly_markers() -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec(&json!([{"_source":{"layers":{
        "frame":{"frame.number":"1"},
        "ip":[
            {"ip.addr":["192.0.2.1","192.0.2.2"]},
            {"ip.addr":["198.51.100.1","198.51.100.2"],
             "ip.fragments":[{"ip.reassembled.in":"2"}]}
        ],
        "udp":{"udp.port":["12345","54321"]}
    }}}]))?;

    let packets = decode_packets(&bytes)?;

    let packet = packets.first().ok_or("decoded packet missing")?;
    assert_eq!(
        packet.fields.pointer("/ip/0/ip.addr/0"),
        Some(&json!("192.0.2.1"))
    );
    assert_eq!(
        packet.fields.pointer("/ip/1/ip.addr/1"),
        Some(&json!("198.51.100.2"))
    );
    assert!(packet.reassembled_fields.contains("ip.reassembled.in"));
    Ok(())
}

#[test]
fn installed_tshark_layers_udp_ports() -> Result<(), Box<dyn Error>> {
    if Command::new("tshark").arg("--version").output().is_err() {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("encapsulated-udp.pcap");
    fs::write(&capture, encapsulated_udp_capture())?;

    let report = produce(&options(&capture, Path::new("tshark")))?;

    let fields = report
        .pointer("/packets/0/fields")
        .ok_or("decoded fields missing")?;
    assert_eq!(
        fields.pointer("/ip/0/ip.addr"),
        Some(&json!(["192.0.2.1", "192.0.2.2"]))
    );
    assert_eq!(
        fields.pointer("/ip/1/ip.addr"),
        Some(&json!(["198.51.100.1", "198.51.100.2"]))
    );
    assert_eq!(
        fields.pointer("/udp/udp.port"),
        Some(&json!(["12345", "54321"]))
    );
    serde_json::from_value::<TsharkReport>(report)?.validate()?;
    Ok(())
}

fn encapsulated_udp_capture() -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    // The Ethernet frame carries two IP layers and one eight-byte UDP payload
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[
        0x45, 0, 0, 56, 0, 1, 0, 0, 64, 4, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    frame.extend_from_slice(&[
        0x45, 0, 0, 36, 0, 2, 0, 0, 64, 17, 0, 0, 198, 51, 100, 1, 198, 51, 100, 2,
    ]);
    frame.extend_from_slice(&[0x30, 0x39, 0xd4, 0x31, 0, 16, 0, 0]);
    frame.extend_from_slice(b"abcdefgh");
    // Timestamp and length fields describe exactly one complete captured frame
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&70_u32.to_le_bytes());
    capture.extend_from_slice(&70_u32.to_le_bytes());
    capture.extend_from_slice(&frame);
    capture
}
