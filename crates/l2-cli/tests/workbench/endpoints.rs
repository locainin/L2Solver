use super::support::{path_arg, run};
use l2_pcap::{
    CaptureSource, CollectionGoal, CollectionReport, CollectionStopReason, FcsStatus,
    InterfaceConfig, PcapNgWriter, TimestampResolution,
};
use serde_json::Value;
use std::{error::Error, fs, io::Cursor};

#[test]
fn native_usn_fields_source_identity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("journal.bin");
    let bytes = usn_v2_record("alpha.bin")?;
    fs::write(&file, &bytes)?;

    let output = run(&["endpoint", path_arg(&file)?, "--format", "usn"], &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        json_u64(&report, "/source_length"),
        Some(u64::try_from(bytes.len())?)
    );
    assert_eq!(
        json_text(&report, "/records/0/file_name"),
        Some("alpha.bin")
    );
    assert!(json_text(&report, "/source_sha256").is_some_and(|value| value.starts_with("sha256:")));
    assert_eq!(json_bool(&report, "/complete"), Some(true));
    Ok(())
}

#[test]
fn exported_event_emits_original_ranges() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("events.xml");
    fs::write(
        &file,
        b"<Events><Event><System><EventID>2</EventID></System></Event></Events>",
    )?;

    let output = run(
        &["endpoint", path_arg(&file)?, "--format", "event-xml"],
        &[],
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_text(&report, "/events/0/event_id"), Some("2"));
    assert_eq!(json_u64(&report, "/events/0/source_range/offset"), Some(8));
    assert_eq!(
        json_text(&report, "/events/0/source_range/source"),
        json_text(&report, "/source_sha256")
    );
    Ok(())
}

#[test]
fn unsupported_native_incomplete_successful_import() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("future-usn.bin");
    let mut bytes = vec![0_u8; 8];
    bytes
        .get_mut(..4)
        .ok_or("record length range missing")?
        .copy_from_slice(&8_u32.to_le_bytes());
    bytes
        .get_mut(4..6)
        .ok_or("version range missing")?
        .copy_from_slice(&4_u16.to_le_bytes());
    fs::write(&file, bytes)?;

    let output = run(&["endpoint", path_arg(&file)?, "--format", "usn"], &[])?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_bool(&report, "/complete"), Some(false));
    assert_eq!(json_u64(&report, "/unsupported/0/major_version"), Some(4));
    Ok(())
}

#[test]
fn unknown_endpoint_rejected_usage_error() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("source.bin");
    fs::write(&file, b"not parsed")?;

    let output = run(
        &["endpoint", path_arg(&file)?, "--format", "json-events"],
        &[],
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout.len(), 0);
    Ok(())
}

#[test]
fn input_rejected_non_trace_formats() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source.usn");
    let capture = directory.path().join("capture.pcap");
    fs::write(&source, usn_v2_record("sample")?)?;
    fs::write(&capture, [])?;

    let output = run(
        &[
            "endpoint",
            path_arg(&source)?,
            "--format",
            "usn",
            "--capture",
            path_arg(&capture)?,
        ],
        &[],
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 0);
    assert!(String::from_utf8_lossy(&output.stderr).contains("only with --format strace"));
    Ok(())
}

#[test]
fn mft_import_lines_complete_summary() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("$MFT");
    let mut source = minimal_mft_record(1)?;
    source.extend_from_slice(&minimal_mft_record(2)?);
    fs::write(&file, source)?;

    let output = run(&["endpoint", path_arg(&file)?, "--format", "mft"], &[])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8(output.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(lines.len(), 3);
    let first = lines.first().ok_or("first MFT output line missing")?;
    let second = lines.get(1).ok_or("second MFT output line missing")?;
    let summary = lines.get(2).ok_or("MFT summary line missing")?;
    assert_eq!(json_text(first, "/record_type"), Some("record"));
    assert_eq!(json_u64(first, "/record/record_number"), Some(1));
    assert_eq!(json_u64(second, "/record/record_number"), Some(2));
    assert_eq!(json_text(summary, "/record_type"), Some("summary"));
    assert_eq!(json_u64(summary, "/report/records_seen"), Some(2));
    assert_eq!(json_u64(summary, "/report/streamed_records"), Some(2));
    assert_eq!(
        json_text(first, "/record/source_range/source"),
        json_text(summary, "/report/source_sha256")
    );
    assert_eq!(json_u64(second, "/record/source_range/offset"), Some(1024));
    assert_eq!(
        summary
            .pointer("/report/records")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn strace_import_hash_qualified_offsets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let trace = directory.path().join("owned.trace");
    let capture = directory.path().join("owned.pcap");
    fs::write(
        &trace,
        b"412 sendto(5<UDP:[192.0.2.10:40000->198.51.100.20:53]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5, 0, NULL, 0) = 5\n",
    )?;
    fs::write(&capture, udp_capture(b"HELLO")?)?;

    let output = run(
        &[
            "endpoint",
            path_arg(&trace)?,
            "--format",
            "strace",
            "--capture",
            path_arg(&capture)?,
        ],
        &[],
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        json_text(&report, "/correlations/0/status"),
        Some("exact_unique_match")
    );
    assert_eq!(
        json_u64(&report, "/correlations/0/candidate_count"),
        Some(1)
    );
    assert_eq!(
        json_u64(&report, "/correlations/0/captured_ranges/0/packet"),
        Some(1)
    );
    assert_eq!(
        json_u64(&report, "/correlations/0/captured_ranges/0/offset"),
        Some(82)
    );
    assert_eq!(
        json_text(&report, "/correlations/0/captured_ranges/0/source"),
        json_text(&report, "/capture/source_sha256")
    );
    Ok(())
}

#[test]
fn incomplete_declaration_blocks_exact_unique() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let trace = directory.path().join("owned.trace");
    let capture = directory.path().join("incomplete.pcapng");
    fs::write(
        &trace,
        b"412 sendto(5<UDP:[192.0.2.10:40000->198.51.100.20:53]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5, 0, NULL, 0) = 5\n",
    )?;
    fs::write(&capture, udp_capture_with_incomplete_report(b"HELLO")?)?;

    let output = run(
        &[
            "endpoint",
            path_arg(&trace)?,
            "--format",
            "strace",
            "--capture",
            path_arg(&capture)?,
        ],
        &[],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json_bool(&report, "/capture/complete"), Some(false));
    assert_eq!(
        json_u64(&report, "/capture/collection_summary/incomplete_sections"),
        Some(1)
    );
    assert_eq!(
        json_text(&report, "/correlations/0/status"),
        Some("capture_incomplete")
    );
    assert_eq!(
        json_u64(&report, "/correlations/0/candidate_count"),
        Some(1)
    );
    Ok(())
}

#[test]
fn trace_incomplete_when_frame_truncated() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let trace = directory.path().join("owned.trace");
    let capture = directory.path().join("truncated.pcap");
    fs::write(
        &trace,
        b"412 sendto(5<UDP:[192.0.2.10:40000->198.51.100.20:53]>, \"\\x48\\x45\\x4c\\x4c\\x4f\", 5, 0, NULL, 0) = 5\n",
    )?;
    fs::write(&capture, udp_capture_with_truncation(b"HELLO")?)?;

    let output = run(
        &[
            "endpoint",
            path_arg(&trace)?,
            "--format",
            "strace",
            "--capture",
            path_arg(&capture)?,
        ],
        &[],
    )?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        json_text(&report, "/correlations/0/status"),
        Some("capture_incomplete")
    );
    assert_eq!(json_u64(&report, "/capture/truncated_frames"), Some(1));
    assert_eq!(json_bool(&report, "/capture/complete"), Some(false));
    Ok(())
}

fn usn_v2_record(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let length = 60_usize
        .checked_add(encoded.len())
        .ok_or("record length overflow")?;
    let mut record = vec![0_u8; length];
    put_u32(&mut record, 0, u32::try_from(length)?)?;
    put_u16(&mut record, 4, 2)?;
    put_u64(&mut record, 8, 17)?;
    put_u64(&mut record, 16, 8)?;
    put_u64(&mut record, 24, 9)?;
    put_u64(&mut record, 32, 100)?;
    put_u32(&mut record, 40, 0x8000)?;
    put_u32(&mut record, 52, 0x20)?;
    put_u16(&mut record, 56, u16::try_from(encoded.len())?)?;
    put_u16(&mut record, 58, 60)?;
    record
        .get_mut(60..)
        .ok_or("name range missing")?
        .copy_from_slice(&encoded);
    Ok(record)
}

fn json_text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn json_u64(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(Value::as_u64)
}

fn json_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(Value::as_bool)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Box<dyn Error>> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or("16-bit field range missing")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Box<dyn Error>> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or("32-bit field range missing")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), Box<dyn Error>> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or("64-bit field range missing")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn minimal_mft_record(number: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut record = vec![0_u8; 1024];
    record
        .get_mut(..4)
        .ok_or("FILE signature range missing")?
        .copy_from_slice(b"FILE");
    put_u16(&mut record, 4, 48)?;
    put_u16(&mut record, 6, 3)?;
    put_u16(&mut record, 16, 1)?;
    put_u16(&mut record, 20, 56)?;
    put_u32(&mut record, 24, 64)?;
    put_u32(&mut record, 28, 1024)?;
    put_u32(&mut record, 44, number)?;
    put_u16(&mut record, 48, 0xaaaa)?;
    put_u16(&mut record, 50, 0x1111)?;
    put_u16(&mut record, 52, 0x2222)?;
    put_u32(&mut record, 56, u32::MAX)?;
    put_u16(&mut record, 510, 0xaaaa)?;
    put_u16(&mut record, 1022, 0xaaaa)?;
    Ok(record)
}

fn udp_capture(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    udp_capture_with_original_length(payload, None)
}

fn udp_capture_with_truncation(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let original_length = u32::try_from(14 + 20 + 8 + payload.len())?
        .checked_add(1)
        .ok_or("original frame length overflow")?;
    udp_capture_with_original_length(payload, Some(original_length))
}

fn udp_capture_with_original_length(
    payload: &[u8],
    original_length: Option<u32>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let udp_length = u16::try_from(
        8_usize
            .checked_add(payload.len())
            .ok_or("UDP length overflow")?,
    )?;
    let ip_length = u16::try_from(20 + usize::from(udp_length))?;
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&ip_length.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 17, 0, 0]);
    frame.extend_from_slice(&[192, 0, 2, 10]);
    frame.extend_from_slice(&[198, 51, 100, 20]);
    frame.extend_from_slice(&40_000_u16.to_be_bytes());
    frame.extend_from_slice(&53_u16.to_be_bytes());
    frame.extend_from_slice(&udp_length.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(payload);
    let frame_length = u32::try_from(frame.len())?;
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&frame_length.to_le_bytes());
    capture.extend_from_slice(&original_length.unwrap_or(frame_length).to_le_bytes());
    capture.extend_from_slice(&frame);
    Ok(capture)
}

fn udp_capture_with_incomplete_report(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut classic = CaptureSource::new(Cursor::new(udp_capture(payload)?))?;
    let frame = classic.next_packet()?.ok_or("UDP fixture frame missing")?;
    let interface = frame.metadata().interface();
    let config = InterfaceConfig::new(
        65_535,
        TimestampResolution::decimal(6)?,
        0,
        FcsStatus::Unknown,
    )?;
    let report = CollectionReport::new(
        CollectionStopReason::Unavailable,
        CollectionGoal::Packets,
        1,
        0,
        0,
        false,
    );
    let mut writer = PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, report)?;
    writer.add_interface(interface, config)?;
    writer.write_frame(&frame)?;
    writer.finish()?;
    Ok(writer.into_inner())
}
