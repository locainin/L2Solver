use serde_json::Value;
#[path = "json_payloads/dns.rs"]
mod dns;
use std::{
    error::Error,
    num::TryFromIntError,
    process::{Command, ExitStatus},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_CAPTURE_ID: AtomicU64 = AtomicU64::new(0);

struct CaptureFile {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl CaptureFile {
    fn create(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let id = NEXT_CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "l2solver-json-payloads-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let path = directory.join("input.pcap");
        std::fs::write(&path, bytes)?;
        Ok(Self { directory, path })
    }
}

impl Drop for CaptureFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct CapturedRecord {
    bytes: Vec<u8>,
    original_length: u32,
}

fn classic_capture(records: &[CapturedRecord]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut capture = Vec::new();
    capture.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    capture.extend_from_slice(&2_u16.to_le_bytes());
    capture.extend_from_slice(&4_u16.to_le_bytes());
    capture.extend_from_slice(&0_i32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());

    for record in records {
        // Capture and original lengths differ only for the truncation fixture
        let captured_length = u32::try_from(record.bytes.len())?;
        capture.extend_from_slice(&1_u32.to_le_bytes());
        capture.extend_from_slice(&0_u32.to_le_bytes());
        capture.extend_from_slice(&captured_length.to_le_bytes());
        capture.extend_from_slice(&record.original_length.to_le_bytes());
        capture.extend_from_slice(&record.bytes);
    }
    Ok(capture)
}

fn full_record(bytes: Vec<u8>) -> Result<CapturedRecord, Box<dyn Error>> {
    Ok(CapturedRecord {
        original_length: u32::try_from(bytes.len())?,
        bytes,
    })
}

fn dump(records: &[CapturedRecord]) -> Result<(ExitStatus, Vec<Value>), Box<dyn Error>> {
    let capture = classic_capture(records)?;
    let file = CaptureFile::create(&capture)?;
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["capture", "dump"])
        .arg(&file.path)
        .args(["--format", "ndjson"])
        .output()?;

    let stdout = String::from_utf8(output.stdout)?;
    let parsed = stdout
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok((output.status, parsed))
}

fn ethernet(ethertype: u16, payload: &[u8], vlan: bool) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
    if vlan {
        // Keep the inner EtherType after a real four-byte VLAN tag
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        frame.extend_from_slice(&0x6123_u16.to_be_bytes());
    }
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv4(
    protocol: u8,
    body: &[u8],
    options: &[u8],
    fragment: u16,
) -> Result<Vec<u8>, TryFromIntError> {
    // IPv4 IHL counts 32-bit words, including all option bytes
    assert_eq!(options.len() % 4, 0);
    let header_length = 20 + options.len();
    let total_length = header_length + body.len();
    let header_words = u8::try_from(header_length / 4)?;
    let total_length = u16::try_from(total_length)?;
    let mut packet = vec![0x40 | header_words, 0];
    packet.extend_from_slice(&total_length.to_be_bytes());
    packet.extend_from_slice(&0x1234_u16.to_be_bytes());
    packet.extend_from_slice(&fragment.to_be_bytes());
    packet.extend_from_slice(&[64, protocol, 0, 0]);
    packet.extend_from_slice(&[192, 0, 2, 17, 198, 51, 100, 29]);
    packet.extend_from_slice(options);
    packet.extend_from_slice(body);
    Ok(packet)
}

fn ipv6(protocol: u8, body: &[u8]) -> Result<Vec<u8>, TryFromIntError> {
    let mut packet = vec![0x60, 0, 0, 0];
    // The declared payload length covers extension headers and transport bytes
    packet.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
    packet.extend_from_slice(&[protocol, 64]);
    packet.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17]);
    packet.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x29]);
    packet.extend_from_slice(body);
    Ok(packet)
}

fn udp(
    source: u16,
    destination: u16,
    payload: &[u8],
    declared_length: Option<u16>,
) -> Result<Vec<u8>, TryFromIntError> {
    let length = match declared_length {
        Some(length) => length,
        None => u16::try_from(8 + payload.len())?,
    };
    let mut header = Vec::with_capacity(8 + payload.len());
    header.extend_from_slice(&source.to_be_bytes());
    header.extend_from_slice(&destination.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(payload);
    Ok(header)
}

fn tcp(
    source: u16,
    destination: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, TryFromIntError> {
    // TCP data offset also counts 32-bit words
    assert_eq!(options.len() % 4, 0);
    let header_length = 20 + options.len();
    let mut header = Vec::with_capacity(header_length + payload.len());
    header.extend_from_slice(&source.to_be_bytes());
    header.extend_from_slice(&destination.to_be_bytes());
    header.extend_from_slice(&sequence.to_be_bytes());
    header.extend_from_slice(&acknowledgement.to_be_bytes());
    header.push(u8::try_from(header_length / 4)? << 4);
    header.push(flags);
    header.extend_from_slice(&32_768_u16.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(&0_u16.to_be_bytes());
    header.extend_from_slice(options);
    header.extend_from_slice(payload);
    Ok(header)
}

fn bytes_at(record: &Value, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    record
        .pointer(path)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing byte array {path}"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| format!("invalid byte in {path}").into())
        })
        .collect()
}

fn range(record: &Value, path: &str) -> Result<(usize, usize), Box<dyn Error>> {
    let value = record
        .pointer(path)
        .ok_or_else(|| format!("missing range {path}"))?;
    let offset = value
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("invalid offset in {path}"))?;
    let length = value
        .get("length")
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("invalid length in {path}"))?;
    Ok((offset, length))
}

fn assert_payload_matches_raw(
    record: &Value,
    payload_path: &str,
    expected_frame: &[u8],
    expected_payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let raw = bytes_at(record, "/raw_bytes")?;
    // Check the output range against the untouched captured frame
    assert_eq!(raw, expected_frame, "raw capture bytes changed");
    let (offset, length) = range(record, payload_path)?;
    assert_eq!(length, expected_payload.len());
    let end = offset
        .checked_add(length)
        .ok_or("reported payload range overflow")?;
    assert_eq!(raw.get(offset..end), Some(expected_payload));
    Ok(())
}

#[test]
fn ipv4_tcp_range_header_facts() -> Result<(), Box<dyn Error>> {
    let payload = [0xde, 0xad, 0xbe, 0xef, 0x10];
    let tcp = tcp(
        30_001,
        30_002,
        0x0102_0304,
        0x0506_0708,
        0x12,
        &[1, 1, 1, 1],
        &payload,
    )?;
    let ip = ipv4(6, &tcp, &[1, 1, 1, 1], 0)?;
    let frame = ethernet(0x0800, &ip, true);
    let (status, records) = dump(&[full_record(frame.clone())?])?;
    assert!(status.success());
    assert_eq!(records.len(), 1);
    let record = records.first().ok_or("missing NDJSON record")?;

    assert_eq!(record.get("status"), Some(&serde_json::json!("parsed")));
    assert_eq!(
        record.pointer("/ip/source"),
        Some(&serde_json::json!({"family": "ipv4", "octets": [192, 0, 2, 17]}))
    );
    assert_eq!(
        record.pointer("/ip/destination"),
        Some(&serde_json::json!({"family": "ipv4", "octets": [198, 51, 100, 29]}))
    );
    assert_eq!(record.pointer("/ip/protocol"), Some(&serde_json::json!(6)));
    assert_eq!(
        record.pointer("/ip/fragmented"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(
        record.pointer("/ip/declared_len"),
        Some(&serde_json::json!(ip.len()))
    );
    assert_eq!(
        record.pointer("/ip/transport/ports"),
        Some(&serde_json::json!([30_001, 30_002]))
    );
    assert_eq!(
        record.pointer("/ip/transport/header"),
        Some(&serde_json::json!({
            "kind": "tcp",
            "sequence": 0x0102_0304_u32,
            "acknowledgement": 0x0506_0708_u32,
            "flags": 0x12,
        }))
    );
    assert_eq!(record.pointer("/ip/transport/trailing"), Some(&Value::Null));
    assert_payload_matches_raw(record, "/ip/transport/payload", &frame, &payload)?;
    Ok(())
}

#[test]
fn ipv6_udp_internal_trailing_ranges() -> Result<(), Box<dyn Error>> {
    let payload = [0x41, 0x42, 0x43, 0x44];
    let ip_trailing = [0xfa, 0xfb, 0xfc];
    let mut udp_segment = udp(31_337, 40_001, &payload, None)?;
    // These bytes remain inside the IP declaration but exceed the UDP length
    udp_segment.extend_from_slice(&ip_trailing);
    let mut extension_and_udp = vec![17, 0, 0, 0, 0, 0, 0, 0];
    extension_and_udp.extend_from_slice(&udp_segment);
    let ip = ipv6(0, &extension_and_udp)?;
    let frame = ethernet(0x86dd, &ip, true);
    let (status, records) = dump(&[full_record(frame.clone())?])?;
    assert!(status.success());
    let record = records.first().ok_or("missing NDJSON record")?;

    assert_eq!(record.get("status"), Some(&serde_json::json!("parsed")));
    assert_eq!(
        record.pointer("/ip/source"),
        Some(
            &serde_json::json!({"family": "ipv6", "octets": [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23]})
        )
    );
    assert_eq!(
        record.pointer("/ip/destination"),
        Some(
            &serde_json::json!({"family": "ipv6", "octets": [32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 41]})
        )
    );
    assert_eq!(record.pointer("/ip/protocol"), Some(&serde_json::json!(17)));
    assert_eq!(
        record.pointer("/ip/fragmented"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(
        record.pointer("/ip/declared_len"),
        Some(&serde_json::json!(ip.len()))
    );
    assert_eq!(
        record.pointer("/ip/transport/ports"),
        Some(&serde_json::json!([31_337, 40_001]))
    );
    assert_eq!(
        record.pointer("/ip/transport/header"),
        Some(&serde_json::json!({"kind": "udp"}))
    );
    let payload_range = range(record, "/ip/transport/payload")?;
    let trailing_range = range(record, "/ip/transport/trailing")?;
    assert_eq!(trailing_range.0, payload_range.0 + payload_range.1);
    assert_eq!(trailing_range.1, ip_trailing.len());
    assert_payload_matches_raw(record, "/ip/transport/payload", &frame, &payload)?;
    let raw = bytes_at(record, "/raw_bytes")?;
    assert_eq!(
        raw.get(trailing_range.0..trailing_range.0 + trailing_range.1),
        Some(ip_trailing.as_slice())
    );
    Ok(())
}

#[test]
fn udp_has_no_trailing_range() -> Result<(), Box<dyn Error>> {
    let payload = [0x71, 0x72, 0x73];
    let udp_segment = udp(31_337, 40_001, &payload, None)?;
    let ip = ipv4(17, &udp_segment, &[], 0)?;
    let frame = ethernet(0x0800, &ip, false);
    let (status, records) = dump(&[full_record(frame.clone())?])?;
    assert!(status.success());
    let record = records.first().ok_or("missing NDJSON record")?;

    assert_eq!(record.get("status"), Some(&serde_json::json!("parsed")));
    assert_eq!(record.pointer("/ip/transport/trailing"), Some(&Value::Null));
    assert_payload_matches_raw(record, "/ip/transport/payload", &frame, &payload)?;
    Ok(())
}

#[test]
fn fragments_and_truncation_hide_payload() -> Result<(), Box<dyn Error>> {
    let payload = [0xaa, 0xbb, 0xcc];
    let udp_segment = udp(10_000, 10_001, &payload, None)?;
    let fragmented_ip = ipv4(17, &udp_segment, &[], 0x2000)?;
    let fragmented_frame = ethernet(0x0800, &fragmented_ip, false);
    let mut fragment_header = vec![17, 0, 0, 9, 0, 0, 0, 1];
    fragment_header.extend_from_slice(&udp_segment);
    let fragmented_ipv6 = ipv6(44, &fragment_header)?;
    let fragmented_ipv6_frame = ethernet(0x86dd, &fragmented_ipv6, true);
    let full_tcp = tcp(10_000, 10_001, 1, 0, 0x02, &[], &payload)?;
    let truncated_ip = ipv4(6, &full_tcp, &[], 0)?;
    let full_frame = ethernet(0x0800, &truncated_ip, false);
    let captured_length = 14 + 20 + 12;
    let truncated_frame = full_frame
        .get(..captured_length)
        .ok_or("truncation boundary exceeds frame")?
        .to_vec();
    let truncated_record = CapturedRecord {
        bytes: truncated_frame.clone(),
        original_length: u32::try_from(full_frame.len())?,
    };

    let (status, records) = dump(&[
        full_record(fragmented_frame.clone())?,
        full_record(fragmented_ipv6_frame.clone())?,
        truncated_record,
    ])?;
    assert_eq!(status.code(), Some(3));
    assert_eq!(records.len(), 3);

    let fragment = records.first().ok_or("missing fragment record")?;
    assert_eq!(
        fragment.pointer("/ip/fragmented"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(fragment.get("status"), Some(&serde_json::json!("parsed")));
    assert_transport_payload_absent(fragment);
    assert_eq!(bytes_at(fragment, "/raw_bytes")?, fragmented_frame);

    let ipv6_fragment = records.get(1).ok_or("missing IPv6 fragment record")?;
    assert_eq!(
        ipv6_fragment.pointer("/ip/fragmented"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        ipv6_fragment.get("status"),
        Some(&serde_json::json!("parsed"))
    );
    assert_transport_payload_absent(ipv6_fragment);
    assert_eq!(
        bytes_at(ipv6_fragment, "/raw_bytes")?,
        fragmented_ipv6_frame
    );

    let truncated = records.get(2).ok_or("missing truncated record")?;
    assert_eq!(truncated.get("truncated"), Some(&serde_json::json!(true)));
    assert_eq!(truncated.get("ip"), Some(&Value::Null));
    assert_transport_payload_absent(truncated);
    assert_eq!(bytes_at(truncated, "/raw_bytes")?, truncated_frame);
    Ok(())
}

#[test]
fn malformed_transport_fact_no() -> Result<(), Box<dyn Error>> {
    let malformed_udp = udp(1_234, 5_678, &[0xde, 0xad], Some(4))?;
    let udp_ip = ipv4(17, &malformed_udp, &[], 0)?;
    let udp_frame = ethernet(0x0800, &udp_ip, false);

    let mut malformed_tcp = tcp(1_234, 5_678, 1, 2, 0x10, &[], &[])?;
    *malformed_tcp.get_mut(12).ok_or("short TCP fixture")? = 0x40; // The declared TCP header is shorter than its fixed header
    let tcp_ip = ipv4(6, &malformed_tcp, &[], 0)?;
    let tcp_frame = ethernet(0x0800, &tcp_ip, false);

    let (status, records) = dump(&[
        full_record(udp_frame.clone())?,
        full_record(tcp_frame.clone())?,
    ])?;
    assert!(status.success());
    assert_eq!(records.len(), 2);
    let udp_record = records.first().ok_or("missing UDP record")?;
    let tcp_record = records.get(1).ok_or("missing TCP record")?;
    for (record, protocol, ip_length) in [
        (udp_record, 17, udp_ip.len()),
        (tcp_record, 6, tcp_ip.len()),
    ] {
        assert!(record.get("ip").is_some_and(Value::is_object));
        assert_eq!(record.get("status"), Some(&serde_json::json!("parsed")));
        assert_eq!(
            record.pointer("/ip/source"),
            Some(&serde_json::json!({"family": "ipv4", "octets": [192, 0, 2, 17]}))
        );
        assert_eq!(
            record.pointer("/ip/destination"),
            Some(&serde_json::json!({"family": "ipv4", "octets": [198, 51, 100, 29]}))
        );
        assert_eq!(
            record.pointer("/ip/protocol"),
            Some(&serde_json::json!(protocol))
        );
        assert_eq!(
            record.pointer("/ip/declared_len"),
            Some(&serde_json::json!(ip_length))
        );
        assert_transport_payload_absent(record);
    }
    assert_eq!(
        bytes_at(records.first().ok_or("missing UDP record")?, "/raw_bytes")?,
        udp_frame
    );
    assert_eq!(
        bytes_at(records.get(1).ok_or("missing TCP record")?, "/raw_bytes")?,
        tcp_frame
    );
    Ok(())
}

#[test]
fn malformed_ip_no_transport_facts() -> Result<(), Box<dyn Error>> {
    let mut malformed_ip = vec![0x44, 0];
    malformed_ip.extend_from_slice(&20_u16.to_be_bytes());
    malformed_ip.extend_from_slice(&[0; 16]);
    let malformed_frame = ethernet(0x0800, &malformed_ip, false);
    let unknown_frame = ethernet(0x88b5, &[0x01, 0x02, 0x03, 0x04], true);

    let (status, records) = dump(&[
        full_record(malformed_frame.clone())?,
        full_record(unknown_frame.clone())?,
    ])?;
    assert_eq!(status.code(), Some(3));
    assert_eq!(records.len(), 2);
    let malformed = records.first().ok_or("missing malformed IP record")?;
    assert_eq!(malformed.get("ip"), Some(&Value::Null));
    assert_eq!(
        malformed.get("status"),
        Some(&serde_json::json!("unsupported"))
    );
    assert!(malformed.get("diagnostic").is_some_and(Value::is_string));
    assert_transport_payload_absent(malformed);
    assert_eq!(bytes_at(malformed, "/raw_bytes")?, malformed_frame);

    let unknown = records.get(1).ok_or("missing unknown EtherType record")?;
    assert_eq!(unknown.get("ip"), Some(&Value::Null));
    assert_eq!(
        unknown.get("status"),
        Some(&serde_json::json!("unsupported"))
    );
    assert_eq!(unknown.get("diagnostic"), Some(&Value::Null));
    assert_transport_payload_absent(unknown);
    assert_eq!(bytes_at(unknown, "/raw_bytes")?, unknown_frame);
    Ok(())
}

fn assert_transport_payload_absent(record: &Value) {
    if record.pointer("/ip").is_some_and(Value::is_object) {
        assert_eq!(
            record.pointer("/ip/transport"),
            Some(&Value::Null),
            "transport facts exposed without a complete, unfragmented transport header: {record}"
        );
    }
    assert!(
        record
            .pointer("/ip/transport/payload")
            .is_none_or(Value::is_null),
        "transport payload range exposed without a complete transport header: {record}"
    );
}
