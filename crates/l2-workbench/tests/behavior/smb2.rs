use l2_workbench::{
    behavior::{BehaviorConfig, BehaviorKind, analyze_case},
    evidence::Case,
    sha256,
};
use std::error::Error;

#[test]
fn smb2_file_times_field_ranges() -> Result<(), Box<dyn Error>> {
    let message = smb2_file_basic_set()?;
    let mut case = Case::new();
    let source = case.add_source(
        "generic-stream.bin",
        "stream",
        u64::try_from(message.len())?,
        &sha256(&message),
        None,
    )?;
    let run = add_tcp_run(&mut case, &message, &source)?;
    let report = analyze_case(&case, &BehaviorConfig::default())?;
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::Smb2FileBasicInfoSetRequest)
        .ok_or("SMB2 SET_INFO candidate missing")?;

    assert_eq!(finding.node_ids, [run]);
    assert_eq!(
        finding.details.get("file_id"),
        Some(&serde_json::json!("000102030405060708090a0b0c0d0e0f"))
    );
    assert_eq!(
        finding.details.get("operation_result"),
        Some(&serde_json::json!("unresolved"))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/0/raw_ticks"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/0/meaning"),
        Some(&serde_json::json!("no_change"))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/1/raw_ticks"),
        Some(&serde_json::json!(111))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/1/meaning"),
        Some(&serde_json::json!("literal_time_request"))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/3/raw_ticks"),
        Some(&serde_json::json!(u64::MAX))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/3/meaning"),
        Some(&serde_json::json!("disable_future_updates"))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/1/stream_range/offset"),
        Some(&serde_json::json!(108))
    );
    assert_eq!(
        finding.details.pointer("/timestamps/1/stream_range/length"),
        Some(&serde_json::json!(8))
    );
    assert_eq!(
        finding.source_ranges.first().map(|range| range.packet),
        Some(Some(1))
    );
    Ok(())
}

#[test]
fn smb2_parser_inconsistent_netbios_frames() -> Result<(), Box<dyn Error>> {
    let mut truncated = smb2_file_basic_set()?;
    truncated.pop();
    let mut malformed = smb2_file_basic_set()?;
    let length_byte = malformed.get_mut(3).ok_or("NetBIOS header is incomplete")?;
    *length_byte = length_byte.wrapping_add(1);

    for bytes in [truncated, malformed] {
        let mut case = Case::new();
        let source = case.add_source(
            "generic-stream.bin",
            "stream",
            u64::try_from(bytes.len())?,
            &sha256(&bytes),
            None,
        )?;
        let run = add_tcp_run(&mut case, &bytes, &source)?;
        let report = analyze_case(&case, &BehaviorConfig::default())?;
        assert!(report.findings.iter().all(|finding| {
            finding.kind != BehaviorKind::Smb2FileBasicInfoSetRequest || finding.node_ids != [run]
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.kind == BehaviorKind::Smb2UnparsedRange
                && finding.status == l2_workbench::evidence::EvidenceStatus::Unresolved
                && finding.node_ids == [run]
        }));
    }
    Ok(())
}

#[test]
fn smb2_parser_frame_valid_message() -> Result<(), Box<dyn Error>> {
    let mut bytes = smb2_file_basic_set()?;
    let frame_offset = bytes.len();
    bytes.extend_from_slice(&[0x7f, 0x55]);
    let mut case = Case::new();
    let source = case.add_source(
        "generic-stream.bin",
        "stream",
        u64::try_from(bytes.len())?,
        &sha256(&bytes),
        None,
    )?;
    let run = add_tcp_run(&mut case, &bytes, &source)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let unparsed = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::Smb2UnparsedRange)
        .ok_or("trailing partial frame was not reported")?;
    assert_eq!(unparsed.node_ids, [run]);
    assert_eq!(
        unparsed.details.get("stream_range"),
        Some(&serde_json::json!({"offset":frame_offset,"length":2}))
    );
    Ok(())
}

#[test]
fn malformed_file_info_visible_unresolved() -> Result<(), Box<dyn Error>> {
    let mut bytes = smb2_file_basic_set()?;
    write_field(&mut bytes, 72, &39_u32.to_le_bytes())?;
    let mut case = Case::new();
    let source = case.add_source(
        "generic-stream.bin",
        "stream",
        u64::try_from(bytes.len())?,
        &sha256(&bytes),
        None,
    )?;
    let run = add_tcp_run(&mut case, &bytes, &source)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::Smb2UnparsedRange
            && finding.status == l2_workbench::evidence::EvidenceStatus::Unresolved
            && finding.node_ids == [run]
    }));
    assert!(report.findings.iter().all(|finding| {
        finding.kind != BehaviorKind::Smb2FileBasicInfoSetRequest || finding.node_ids != [run]
    }));
    Ok(())
}

#[test]
fn padded_file_actual_stream_offset() -> Result<(), Box<dyn Error>> {
    let mut bytes = smb2_file_basic_set()?;
    bytes.splice(100..100, [0xaa, 0xbb, 0xcc, 0xdd]);
    write_field(&mut bytes, 3, &140_u8.to_be_bytes())?;
    write_field(&mut bytes, 76, &100_u16.to_le_bytes())?;
    let mut case = Case::new();
    let source = case.add_source(
        "generic-stream.bin",
        "stream",
        u64::try_from(bytes.len())?,
        &sha256(&bytes),
        None,
    )?;
    add_tcp_run(&mut case, &bytes, &source)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::Smb2FileBasicInfoSetRequest)
        .ok_or("SMB2 SET_INFO candidate missing")?;
    assert_eq!(
        finding.details.pointer("/timestamps/1/stream_range/offset"),
        Some(&serde_json::json!(112))
    );
    assert_eq!(
        finding
            .details
            .pointer("/timestamps/1/source_ranges/0/offset"),
        Some(&serde_json::json!(112))
    );
    Ok(())
}

#[test]
fn negative_filetime_not_literal_timestamps() -> Result<(), Box<dyn Error>> {
    let mut bytes = smb2_file_basic_set()?;
    write_field(&mut bytes, 116, &(u64::MAX - 2).to_le_bytes())?;
    let mut case = Case::new();
    let source = case.add_source(
        "generic-stream.bin",
        "stream",
        u64::try_from(bytes.len())?,
        &sha256(&bytes),
        None,
    )?;
    add_tcp_run(&mut case, &bytes, &source)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let finding = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::Smb2FileBasicInfoSetRequest)
        .ok_or("SMB2 SET_INFO candidate missing")?;
    assert_eq!(
        finding.details.pointer("/timestamps/2/meaning"),
        Some(&serde_json::json!("invalid_negative_time_request"))
    );
    Ok(())
}

fn smb2_file_basic_set() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut smb = vec![0; 64 + 32 + 40];
    write_field(&mut smb, 0, b"\xfeSMB")?;
    write_field(&mut smb, 4, &64_u16.to_le_bytes())?;
    write_field(&mut smb, 12, &0x0011_u16.to_le_bytes())?;
    write_field(&mut smb, 24, &9_u64.to_le_bytes())?;
    write_field(&mut smb, 64, &33_u16.to_le_bytes())?;
    write_field(&mut smb, 66, &[1])?;
    write_field(&mut smb, 67, &[4])?;
    write_field(&mut smb, 68, &40_u32.to_le_bytes())?;
    write_field(&mut smb, 72, &96_u16.to_le_bytes())?;
    for index in 0..16 {
        let byte = smb
            .get_mut(80 + index)
            .ok_or("file id fixture is too short")?;
        *byte = u8::try_from(index)?;
    }
    let timestamps = [0, 111, 222, u64::MAX];
    let buffer = smb
        .get_mut(96..128)
        .ok_or("timestamp fixture is too short")?;
    for (target, timestamp) in buffer.chunks_exact_mut(8).zip(timestamps) {
        target.copy_from_slice(&timestamp.to_le_bytes());
    }
    let mut frame = vec![0, 0, 0, u8::try_from(smb.len())?];
    frame.extend_from_slice(&smb);
    Ok(frame)
}

fn write_field(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(value.len())
        .ok_or("fixture offset overflow")?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or("fixture field is out of bounds")?;
    target.copy_from_slice(value);
    Ok(())
}

fn add_tcp_run(case: &mut Case, stream: &[u8], source: &str) -> Result<u64, Box<dyn Error>> {
    let stream_blob = case.add_blob(stream)?;
    Ok(case.add_node(
        "tcp_byte_run",
        Some(&stream_blob),
        vec![l2_workbench::evidence::SourceRange {
            source: source.to_owned(),
            packet: Some(1),
            offset: 0,
            length: u64::try_from(stream.len())?,
        }],
        serde_json::json!({
            "offset": 0,
            "length": stream.len(),
            "start_known": true,
            "end_observed": true,
            "generation_ambiguous": false,
        }),
    )?)
}
