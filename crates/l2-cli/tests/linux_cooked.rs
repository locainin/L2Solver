use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampSource,
};
use l2_pcap::{InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgWriter, TimestampResolution};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::Write,
    process::{Command, Output, Stdio},
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn classic_cooked_dns_reports_header_metadata_and_exact_payload_location() -> TestResult {
    let dns = dns_query();
    for (link_type, version, header_len, ifindex) in
        [(113, "v1", 16, None), (276, "v2", 20, Some(7))]
    {
        let bytes = cooked(link_type, 7, &ipv4(17, &udp(&dns)?)?);
        let capture = classic(link_type, &[(&bytes, u32::try_from(bytes.len())?)])?;
        let output = run(&["capture", "dump", "-", "--format", "ndjson"], &capture)?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(record.pointer("/status"), Some(&json!("parsed")));
        assert_eq!(record.pointer("/cooked/version"), Some(&json!(version)));
        assert_eq!(record.pointer("/cooked/packet_type"), Some(&json!("host")));
        assert_eq!(record.pointer("/cooked/hardware_type"), Some(&json!(1)));
        assert_eq!(record.pointer("/cooked/protocol"), Some(&json!(0x0800)));
        assert_eq!(record.pointer("/cooked/address_length"), Some(&json!(6)));
        assert_eq!(
            record.pointer("/cooked/address"),
            Some(&json!([2, 3, 4, 5, 6, 7]))
        );
        assert_eq!(
            record.pointer("/cooked/interface_index"),
            Some(&json!(ifindex))
        );
        assert_eq!(
            record.pointer("/ip/transport/dns/status"),
            Some(&json!("decoded"))
        );
        assert_eq!(
            record.pointer("/ip/transport/dns/message/id"),
            Some(&json!(0x1234))
        );
        assert_eq!(
            record.pointer("/ip/transport/payload/offset"),
            Some(&json!(header_len + 20 + 8))
        );
        assert_eq!(
            record.pointer("/ip/transport/payload/length"),
            Some(&json!(dns.len()))
        );
        assert_eq!(record.pointer("/raw_bytes"), Some(&json!(&bytes)));
        assert_eq!(bytes.get(header_len + 20 + 8..), Some(dns.as_slice()));

        assert_cooked_inspection(&capture, ifindex)?;
    }
    Ok(())
}

fn assert_cooked_inspection(capture: &[u8], ifindex: Option<u32>) -> TestResult {
    let text = run(&["capture", "inspect", "-"], capture)?;
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout)?;
    assert!(text.contains("Linux cooked"), "{text}");
    assert!(text.contains("hardware_type=1"), "{text}");
    assert!(text.contains("protocol=0x0800"), "{text}");
    assert!(text.contains("address=02:03:04:05:06:07"), "{text}");
    assert!(text.contains("IP 192.0.2.1 -> 198.51.100.2"), "{text}");
    assert!(!text.contains("tags="), "{text}");
    assert_eq!(text.contains("ifindex=7"), ifindex.is_some(), "{text}");
    Ok(())
}

#[test]
fn cooked_tcp_range_keeps_fixed_header_offsets() -> TestResult {
    for (link_type, header_len) in [(113, 16), (276, 20)] {
        let first = cooked(link_type, 7, &ipv4(6, &tcp(10, b"ab"))?);
        let second = cooked(link_type, 7, &ipv4(6, &tcp(12, b"cd"))?);
        let capture = classic(
            link_type,
            &[
                (&first, u32::try_from(first.len())?),
                (&second, u32::try_from(second.len())?),
            ],
        )?;
        let output = run(
            &[
                "capture",
                "tcp-range",
                "-",
                "--packet",
                "1",
                "--length",
                "4",
                "--format",
                "json",
            ],
            &capture,
        )?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result.pointer("/complete"), Some(&json!(true)));
        assert_eq!(result.pointer("/matching_packets"), Some(&json!(2)));
        assert_eq!(
            result.pointer("/range/spans/0/bytes"),
            Some(&json!(b"abcd"))
        );
        assert_eq!(
            result.pointer("/range/observations/0/payload_frame_offset"),
            Some(&json!(header_len + 40))
        );
        assert_eq!(
            result.pointer("/range/observations/1/payload_frame_offset"),
            Some(&json!(header_len + 40))
        );
        if link_type == 276 {
            assert_eq!(
                result.pointer("/flow/scope/cooked_ifindex"),
                Some(&json!(7))
            );
        } else {
            assert!(result.pointer("/flow/scope/cooked_ifindex").is_none());
        }
        let text = run(
            &[
                "capture",
                "tcp-range",
                "-",
                "--packet",
                "1",
                "--length",
                "4",
            ],
            &capture,
        )?;
        assert!(text.status.success());
        let text = String::from_utf8(text.stdout)?;
        assert!(text.contains("VLAN membership unavailable"), "{text}");
        assert!(
            text.contains("SLL1 may combine multiple interfaces"),
            "{text}"
        );
    }
    Ok(())
}

#[test]
fn cooked_ipv6_tcp_payload_offsets_follow_each_link_header() -> TestResult {
    for (link_type, header_len, protocol_offset) in [(113, 16, 14), (276, 20, 0)] {
        let mut frame = cooked(link_type, 7, &ipv6(6, &tcp(10, b"v6"))?);
        frame
            .get_mut(protocol_offset..protocol_offset + 2)
            .ok_or("missing cooked protocol")?
            .copy_from_slice(&0x86dd_u16.to_be_bytes());
        let capture = classic(link_type, &[(&frame, u32::try_from(frame.len())?)])?;
        let output = run(
            &[
                "capture",
                "tcp-range",
                "-",
                "--packet",
                "1",
                "--length",
                "2",
                "--format",
                "json",
            ],
            &capture,
        )?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result.pointer("/range/spans/0/bytes"), Some(&json!(b"v6")));
        assert_eq!(
            result.pointer("/range/observations/0/payload_frame_offset"),
            Some(&json!(header_len + 40 + 20))
        );
        let dump = run(&["capture", "dump", "-", "--format", "ndjson"], &capture)?;
        assert!(dump.status.success());
        let record: Value = serde_json::from_slice(&dump.stdout)?;
        assert_eq!(
            record.pointer("/ip/transport/payload/offset"),
            Some(&json!(header_len + 60))
        );
    }
    Ok(())
}

#[test]
fn pcapng_cooked_scope_excludes_other_ifindices_and_interfaces() -> TestResult {
    let first = cooked(276, 7, &ipv4(6, &tcp(10, b"ab"))?);
    let other_index = cooked(276, 8, &ipv4(6, &tcp(12, b"XY"))?);
    let other_index_header = other_index.get(..20).ok_or("missing SLL2 header")?;
    let second = cooked(276, 7, &ipv4(6, &tcp(12, b"cd"))?);
    let other_interface = cooked(113, 0, &ipv4(6, &tcp(12, b"ZZ"))?);
    let other_capture_interface = cooked(276, 7, &ipv4(6, &tcp(12, b"XX"))?);
    let capture = pcapng(&[
        (0, 276, &first, first.len()),
        (0, 276, &other_index, other_index.len()),
        (0, 276, other_index_header, other_index.len()),
        (1, 113, &other_interface, other_interface.len()),
        (
            2,
            276,
            &other_capture_interface,
            other_capture_interface.len(),
        ),
        (0, 276, &second, second.len()),
    ])?;
    let output = run(
        &[
            "capture",
            "tcp-range",
            "-",
            "--packet",
            "1",
            "--length",
            "4",
            "--format",
            "json",
        ],
        &capture,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result.pointer("/matching_packets"), Some(&json!(2)));
    assert_eq!(result.pointer("/unresolved_packets"), Some(&json!(0)));
    assert_eq!(
        result.pointer("/range/spans/0/bytes"),
        Some(&json!(b"abcd"))
    );
    assert_eq!(result.pointer("/flow/scope/interface"), Some(&json!(0)));
    assert_eq!(
        result.pointer("/flow/scope/cooked_ifindex"),
        Some(&json!(7))
    );
    Ok(())
}

#[test]
fn cooked_truncation_and_malformed_header_keep_range_incomplete() -> TestResult {
    let first = cooked(276, 7, &ipv4(6, &tcp(10, b"ab"))?);
    let truncated = cooked(276, 7, &ipv4(6, &tcp(12, b"cd"))?);
    let truncated_bytes = truncated.get(..40).ok_or("missing truncated IP header")?;
    let malformed = [0_u8; 8];
    let capture = pcapng(&[
        (0, 276, &first, first.len()),
        (0, 276, truncated_bytes, truncated.len()),
        (0, 276, &malformed, malformed.len()),
    ])?;
    let output = run(
        &[
            "capture",
            "tcp-range",
            "-",
            "--packet",
            "1",
            "--length",
            "2",
            "--format",
            "json",
        ],
        &capture,
    )?;
    assert_eq!(output.status.code(), Some(3));
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result.pointer("/complete"), Some(&json!(false)));
    assert_eq!(result.pointer("/unresolved_packets"), Some(&json!(2)));
    assert_eq!(
        result.pointer("/unresolved_sources/0/reason"),
        Some(&json!("truncated_capture"))
    );
    assert_eq!(
        result.pointer("/unresolved_sources/1/reason"),
        Some(&json!("cooked_layout"))
    );
    let dump = run(&["capture", "dump", "-", "--format", "ndjson"], &capture)?;
    assert_eq!(dump.status.code(), Some(3));
    let records: Vec<Value> = String::from_utf8(dump.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        records.get(1).and_then(|v| v.pointer("/truncated")),
        Some(&json!(true))
    );
    assert_eq!(
        records.get(1).and_then(|v| v.pointer("/ip")),
        Some(&Value::Null)
    );
    Ok(())
}

#[test]
fn cooked_unknown_protocol_in_selected_scope_remains_unresolved() -> TestResult {
    let first = cooked(276, 7, &ipv4(6, &tcp(10, b"ab"))?);
    let mut vlan = cooked(276, 7, &ipv4(6, &tcp(12, b"cd"))?);
    vlan.get_mut(..2)
        .ok_or("missing SLL2 protocol")?
        .copy_from_slice(&0x8100_u16.to_be_bytes());
    let capture = classic(
        276,
        &[
            (&first, u32::try_from(first.len())?),
            (&vlan, u32::try_from(vlan.len())?),
        ],
    )?;
    let output = run(
        &[
            "capture",
            "tcp-range",
            "-",
            "--packet",
            "1",
            "--length",
            "2",
            "--format",
            "json",
        ],
        &capture,
    )?;
    assert_eq!(output.status.code(), Some(3));
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result.pointer("/complete"), Some(&json!(false)));
    assert_eq!(result.pointer("/unresolved_packets"), Some(&json!(1)));
    assert_eq!(
        result.pointer("/unresolved_sources/0/reason"),
        Some(&json!("unsupported_protocol"))
    );
    Ok(())
}

#[test]
fn malformed_cooked_and_unsupported_link_types_remain_distinct() -> TestResult {
    let malformed = [0_u8; 8];
    let unknown = [0_u8; 32];
    let mut bad_reserved = cooked(276, 7, &[]);
    *bad_reserved.get_mut(3).ok_or("missing reserved byte")? = 1;
    let capture = pcapng(&[
        (0, 113, &malformed, malformed.len()),
        (1, 999, &unknown, unknown.len()),
        (2, 276, &bad_reserved, bad_reserved.len()),
    ])?;
    let output = run(&["capture", "dump", "-", "--format", "ndjson"], &capture)?;
    assert_eq!(output.status.code(), Some(3));
    let records: Vec<Value> = String::from_utf8(output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        records.first().and_then(|v| v.pointer("/status")),
        Some(&json!("malformed"))
    );
    assert_eq!(
        records.get(1).and_then(|v| v.pointer("/status")),
        Some(&json!("unsupported"))
    );
    assert_eq!(
        records.get(1).and_then(|v| v.pointer("/link_type_raw")),
        Some(&json!(999))
    );
    assert!(
        records
            .get(1)
            .and_then(|v| v.pointer("/diagnostic"))
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("unsupported link type"))
    );
    assert_eq!(
        records.get(2).and_then(|v| v.pointer("/status")),
        Some(&json!("malformed"))
    );
    Ok(())
}

#[test]
fn cooked_address_length_and_packet_type_preserve_header_claims() -> TestResult {
    let mut frame = cooked(113, 0, &ipv4(6, &tcp(10, b"a"))?);
    frame
        .get_mut(..2)
        .ok_or("missing packet type")?
        .copy_from_slice(&4_u16.to_be_bytes());
    frame
        .get_mut(4..6)
        .ok_or("missing address length")?
        .copy_from_slice(&12_u16.to_be_bytes());
    let capture = classic(113, &[(&frame, u32::try_from(frame.len())?)])?;
    let output = run(&["capture", "dump", "-", "--format", "ndjson"], &capture)?;
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        result.pointer("/cooked/packet_type"),
        Some(&json!("outgoing"))
    );
    assert_eq!(result.pointer("/cooked/address_length"), Some(&json!(12)));
    assert_eq!(
        result.pointer("/cooked/address"),
        Some(&json!([2, 3, 4, 5, 6, 7, 0, 0]))
    );
    Ok(())
}

#[test]
fn observation_distinguishes_unsupported_cooked_protocol_from_link_type() -> TestResult {
    let mut frame = cooked(276, 7, &[]);
    frame
        .get_mut(..2)
        .ok_or("missing SLL2 protocol")?
        .copy_from_slice(&0x8100_u16.to_be_bytes());
    let capture = classic(276, &[(&frame, u32::try_from(frame.len())?)])?;
    let output = run(&["capture", "observe", "-"], &capture)?;
    assert_eq!(output.status.code(), Some(3));
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains("unsupported Linux cooked protocol"), "{text}");
    assert!(text.contains("unsupported_link=0"), "{text}");
    assert!(text.contains("unsupported_protocol=1"), "{text}");
    Ok(())
}

fn cooked(link_type: u16, ifindex: u32, ip: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    if link_type == 113 {
        // SLL1 stores the packet type and hardware address before the protocol
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&6_u16.to_be_bytes());
        bytes.extend_from_slice(&[2, 3, 4, 5, 6, 7, 0, 0]);
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
    } else {
        // SLL2 carries a separate host interface index in its fixed header
        bytes.extend_from_slice(&0x0800_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&ifindex.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 6, 2, 3, 4, 5, 6, 7, 0, 0]);
    }
    bytes.extend_from_slice(ip);
    bytes
}

fn ipv4(protocol: u8, payload: &[u8]) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(&u16::try_from(20 + payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&[
        0, 0, 0, 0, 64, protocol, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
    ]);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn ipv6(protocol: u8, payload: &[u8]) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0x60, 0, 0, 0];
    bytes.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&[protocol, 64]);
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn tcp(sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x9c, 0x40, 0x9c, 0x41];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x10, 0x20, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

fn udp(payload: &[u8]) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0xa4, 0x10, 0, 53];
    bytes.extend_from_slice(&u16::try_from(8 + payload.len())?.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn dns_query() -> Vec<u8> {
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm',
        b'p', b'l', b'e', 0, 0, 1, 0, 1,
    ]
}

fn classic(link_type: u16, records: &[(&[u8], u32)]) -> TestResult<Vec<u8>> {
    // One classic PCAP header applies to every following record
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1];
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&4_u16.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&u32::from(link_type).to_le_bytes());
    for (record, original_len) in records {
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&u32::try_from(record.len())?.to_le_bytes());
        bytes.extend_from_slice(&original_len.to_le_bytes());
        bytes.extend_from_slice(record);
    }
    Ok(bytes)
}

fn pcapng(records: &[(u32, u16, &[u8], usize)]) -> TestResult<Vec<u8>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let mut interfaces = Vec::new();
    // Each capture interface gets an independent link type declaration
    for &(index, raw_type, _, _) in records {
        if !interfaces.contains(&index) {
            let link_type = LinkType::from_raw(raw_type);
            writer.add_interface(
                InterfaceId { section: 0, index },
                InterfaceConfig::new_with_link_type(
                    link_type,
                    65_535,
                    TimestampResolution::MICROSECOND,
                    0,
                    FcsStatus::Unknown,
                )?,
            )?;
            interfaces.push(index);
        }
    }
    for &(index, raw_type, bytes, original_len) in records {
        let interface = InterfaceId { section: 0, index };
        let metadata = CaptureMetadata::new(
            interface,
            u32::try_from(original_len)?,
            None,
            Some(CaptureTimestamp::new(
                0,
                TimestampResolution::MICROSECOND,
                0,
                TimestampSource::Unknown,
            )),
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
        .with_link_type(LinkType::from_raw(raw_type));
        writer.write_frame(&CapturedFrame::new(bytes.to_vec(), metadata)?)?;
    }
    writer.finish()?;
    Ok(writer.into_inner())
}

fn run(args: &[&str], capture: &[u8]) -> TestResult<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("missing stdin")?;
    stdin.write_all(capture)?;
    drop(stdin);
    Ok(child.wait_with_output()?)
}
