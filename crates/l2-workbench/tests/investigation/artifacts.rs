use super::{
    case_support::located_records,
    support::{tcp, tcp_ports},
};
use l2_workbench::{
    evidence::{Case, EvidenceStatus, Node},
    investigation::{BuildInput, build},
    sha256,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn http_elf_source_bound_header() -> Result<(), Box<dyn Error>> {
    let elf = minimal_elf_header()?;
    let result = build_http_body_case(&elf)?;
    let body = node(&result.case, "http_body")?;
    let check = check_for(&result.case, body.id)?;
    let details = node_value(&result.case, check)?;

    assert_eq!(blob_bytes(&result.case, body)?, elf);
    assert_eq!(
        details.get("result"),
        Some(&Value::from("validated_metadata"))
    );
    assert_eq!(details.get("input_node"), Some(&Value::from(body.id)));
    assert_eq!(
        details.get("input_sha256"),
        Some(&Value::from(sha256(&elf)))
    );
    assert_eq!(details.pointer("/report/format"), Some(&Value::from("elf")));
    assert_eq!(
        details.pointer("/report/sha256"),
        Some(&Value::from(sha256(&elf)))
    );
    assert_eq!(
        details.get("input_blob").and_then(Value::as_str),
        body.blob.as_deref()
    );
    assert_eq!(
        details.get("coordinate_base"),
        Some(&Value::from("zero_based_from_byte_0_of_input_blob"))
    );
    assert_eq!(check.ranges, body.ranges);
    assert!(has_edge(
        &result.case,
        body.id,
        check.id,
        "tested_by",
        EvidenceStatus::Observed
    ));
    assert!(!has_relation_from(&result.case, check.id, "mapped_by"));
    Ok(())
}

#[test]
fn malformed_executable_prefixes_rejected_header() -> Result<(), Box<dyn Error>> {
    for (bytes, expected_reason) in [
        (b"MZ".as_slice(), "invalid_range"),
        (b"\x7fELF".as_slice(), "invalid_header"),
    ] {
        let result = build_http_body_case(bytes)?;
        let body = node(&result.case, "http_body")?;
        let check = check_for(&result.case, body.id)?;
        let details = node_value(&result.case, check)?;

        assert_eq!(details.get("result"), Some(&Value::from("rejected_header")));
        assert!(details.get("reason").is_some());
        assert_eq!(details.get("input_node"), Some(&Value::from(body.id)));
        assert_eq!(
            details.get("input_sha256"),
            Some(&Value::from(sha256(bytes)))
        );
        assert_eq!(
            details.pointer("/reason/kind").and_then(Value::as_str),
            Some(expected_reason)
        );
        assert!(result.complete);
    }
    Ok(())
}

#[test]
fn executable_metadata_limit_case_incomplete() -> Result<(), Box<dyn Error>> {
    let mut elf = minimal_elf_header()?;
    write_u16(
        &mut elf,
        60,
        u16::try_from(l2_workbench::artifact::MAX_SECTIONS + 1)?,
    )?;
    let result = build_http_body_case(&elf)?;
    let body = node(&result.case, "http_body")?;
    let check = check_for(&result.case, body.id)?;
    let details = node_value(&result.case, check)?;

    assert!(!result.complete);
    assert_eq!(details.get("result"), Some(&Value::from("rejected_header")));
    assert_eq!(
        details.pointer("/reason/kind"),
        Some(&Value::from("entry_limit"))
    );
    assert_eq!(
        details.pointer("/reason/field"),
        Some(&Value::from("sections"))
    );
    assert!(
        result
            .case
            .limitations()
            .iter()
            .any(|text| text.contains("configured format-parser limit"))
    );
    Ok(())
}

#[test]
fn large_inspector_without_mapping_receipts() -> Result<(), Box<dyn Error>> {
    let elf = elf_with_empty_sections(64)?;
    let result = build_http_body_case(&elf)?;
    let body = node(&result.case, "http_body")?;
    let check = check_for(&result.case, body.id)?;
    let details = node_value(&result.case, check)?;

    assert_eq!(
        check.details.get("representation"),
        Some(&Value::from("json_blob"))
    );
    assert_eq!(
        details
            .pointer("/report/sections")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(64)
    );
    assert_eq!(
        details.get("input_blob").and_then(Value::as_str),
        body.blob.as_deref()
    );
    assert_eq!(check.ranges, body.ranges);
    assert!(!has_relation_from(&result.case, check.id, "mapped_by"));
    Ok(())
}

#[test]
fn arbitrary_http_bytes_not_absence() -> Result<(), Box<dyn Error>> {
    let result = build_http_body_case(b"ordinary application bytes")?;

    assert!(
        result
            .case
            .nodes()
            .iter()
            .all(|candidate| candidate.kind != "artifact_header_checks")
    );
    Ok(())
}

#[test]
fn http_masked_network_source_range() -> Result<(), Box<dyn Error>> {
    let wave = b"RIFF\x11\x22\x33\x44WAVEnetwork-body";
    let result = build_http_body_case(wave)?;
    let body = node(&result.case, "http_body")?;
    let signature = result
        .case
        .nodes()
        .iter()
        .find(|candidate| candidate.kind == "file_signature_match")
        .ok_or("file signature match is missing")?;

    assert_eq!(
        signature.details.get("rule_id"),
        Some(&Value::from("riff-wave"))
    );
    assert_eq!(
        signature.details.pointer("/catalogue/version"),
        Some(&Value::from(2))
    );
    assert_eq!(
        signature.details.pointer("/catalogue/source"),
        Some(&Value::from(
            "https://en.wikipedia.org/wiki/List_of_file_signatures"
        ))
    );
    assert_eq!(
        signature.details.pointer("/range/offset"),
        Some(&Value::from(0))
    );
    assert_eq!(
        signature.details.pointer("/range/length"),
        Some(&Value::from(12))
    );
    assert_eq!(signature.ranges.len(), 1);
    let range = signature
        .ranges
        .first()
        .ok_or("signature range is missing")?;
    assert_eq!(range.length, 12);
    assert_eq!(range.packet, Some(2));
    assert!(has_edge(
        &result.case,
        body.id,
        signature.id,
        "contains_signature",
        EvidenceStatus::Observed
    ));
    let edge = result
        .case
        .edges()
        .iter()
        .find(|edge| edge.from == body.id && edge.to == signature.id)
        .ok_or("signature relationship is missing")?;
    assert!(edge.reason.contains("exact or explicitly masked"));
    assert!(
        result
            .case
            .nodes()
            .iter()
            .all(|candidate| candidate.kind != "artifact_header_checks")
    );
    Ok(())
}

#[test]
fn malformed_executable_separate_parser_rejection() -> Result<(), Box<dyn Error>> {
    let result = build_http_body_case(b"MZ")?;
    let signature = result
        .case
        .nodes()
        .iter()
        .find(|candidate| candidate.kind == "file_signature_match")
        .ok_or("MZ signature observation is missing")?;
    let rejected = result
        .case
        .nodes()
        .iter()
        .find(|candidate| candidate.kind == "artifact_header_checks")
        .ok_or("PE parser rejection is missing")?;

    assert_eq!(
        signature.details.get("rule_id"),
        Some(&Value::from("dos-mz"))
    );
    assert_eq!(
        rejected.details.get("result"),
        Some(&Value::from("rejected_header"))
    );
    Ok(())
}

#[test]
fn ftp_data_reuses_blob_header() -> Result<(), Box<dyn Error>> {
    let elf = minimal_elf_header()?;
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(true, 200, 0x12, b"")?,
        tcp(false, 101, 0x18, b"EPSV\r\n")?,
        tcp(
            true,
            201,
            0x18,
            b"229 Entering Extended Passive Mode (|||10000|)\r\n",
        )?,
        tcp_ports(false, (40_001, 10_000), 500, 2, b"")?,
        tcp(false, 107, 0x18, b"RETR sample.bin\r\n")?,
        tcp_ports(true, (40_001, 10_000), 600, 0x12, b"")?,
        tcp_ports(true, (40_001, 10_000), 601, 0x18, &elf)?,
    ])?;
    let result = build(BuildInput {
        label: "ftp-artifact.pcap",
        length,
        sha256_hex: &sha256(b"generic FTP artifact source"),
        records: &records,
        frames_seen: 8,
    })?;
    let data = node(&result.case, "ftp_data_candidate")?;
    let check = check_for(&result.case, data.id)?;
    let details = node_value(&result.case, check)?;

    assert_eq!(
        data.blob.as_deref(),
        details.get("input_blob").and_then(Value::as_str)
    );
    assert_eq!(
        details.get("result"),
        Some(&Value::from("validated_metadata"))
    );
    assert_eq!(
        details.get("input_sha256"),
        Some(&Value::from(sha256(&elf)))
    );
    assert_eq!(check.ranges, data.ranges);
    assert!(has_edge(
        &result.case,
        data.id,
        check.id,
        "tested_by",
        EvidenceStatus::Observed
    ));
    Ok(())
}

fn build_http_body_case(
    bytes: &[u8],
) -> Result<l2_workbench::investigation::BuildResult, Box<dyn Error>> {
    let mut request = format!(
        "POST /upload HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    )
    .into_bytes();
    request.extend_from_slice(bytes);
    let final_sequence = 101_u32
        .checked_add(u32::try_from(request.len())?)
        .ok_or("HTTP TCP sequence overflow")?;
    let (records, length) = located_records(vec![
        tcp(false, 100, 2, b"")?,
        tcp(false, 101, 0x18, &request)?,
        tcp(false, final_sequence, 0x11, b"")?,
    ])?;
    build(BuildInput {
        label: "http-artifact.pcap",
        length,
        sha256_hex: &sha256(b"generic HTTP artifact source"),
        records: &records,
        frames_seen: 3,
    })
}

fn minimal_elf_header() -> Result<Vec<u8>, Box<dyn Error>> {
    elf_with_empty_sections(0)
}

fn elf_with_empty_sections(count: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let table_length = count.checked_mul(64).ok_or("ELF section table overflow")?;
    let mut bytes = vec![
        0;
        64_usize
            .checked_add(table_length)
            .ok_or("ELF length overflow")?
    ];
    write_at(&mut bytes, 0, b"\x7fELF\x02\x01\x01")?;
    write_u16(&mut bytes, 16, 2)?;
    write_u16(&mut bytes, 18, 62)?;
    write_u32(&mut bytes, 20, 1)?;
    let section_table_offset = if count == 0 { 0 } else { 64 };
    write_at(
        &mut bytes,
        40,
        &u64::try_from(section_table_offset)?.to_le_bytes(),
    )?;
    write_u16(&mut bytes, 52, 64)?;
    write_u16(&mut bytes, 54, 56)?;
    write_u16(&mut bytes, 58, 64)?;
    write_u16(&mut bytes, 60, u16::try_from(count)?)?;
    Ok(bytes)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Box<dyn Error>> {
    write_at(bytes, offset, &value.to_le_bytes())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Box<dyn Error>> {
    write_at(bytes, offset, &value.to_le_bytes())
}

fn write_at(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = offset
        .checked_add(value.len())
        .ok_or("fixture range overflow")?;
    bytes
        .get_mut(offset..end)
        .ok_or("fixture write out of range")?
        .copy_from_slice(value);
    Ok(())
}

fn node<'a>(case: &'a Case, kind: &str) -> Result<&'a Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|candidate| candidate.kind == kind)
        .ok_or_else(|| format!("missing {kind} node").into())
}

fn check_for(case: &Case, input_node: u64) -> Result<&Node, Box<dyn Error>> {
    let check_id = case
        .edges()
        .iter()
        .find(|edge| edge.from == input_node && edge.relation == "tested_by")
        .map(|edge| edge.to)
        .ok_or_else(|| format!("missing artifact check edge from node {input_node}"))?;
    case.nodes()
        .iter()
        .find(|candidate| candidate.id == check_id && candidate.kind == "artifact_header_checks")
        .ok_or_else(|| format!("missing artifact header check for node {input_node}").into())
}

fn node_value(case: &Case, node: &Node) -> Result<Value, Box<dyn Error>> {
    if node.details.get("representation") != Some(&Value::from("json_blob")) {
        return Ok(node.details.clone());
    }
    let id = node.blob.as_deref().ok_or("JSON fact node has no blob")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == id)
        .ok_or("JSON fact blob is absent")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn blob_bytes<'a>(case: &'a Case, node: &Node) -> Result<&'a [u8], Box<dyn Error>> {
    let id = node.blob.as_deref().ok_or("byte node has no blob")?;
    case.blobs()
        .iter()
        .find(|blob| blob.id == id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or_else(|| "missing byte blob".into())
}

fn has_edge(case: &Case, from: u64, to: u64, relation: &str, status: EvidenceStatus) -> bool {
    case.edges().iter().any(|edge| {
        edge.from == from && edge.to == to && edge.relation == relation && edge.status == status
    })
}

fn has_relation_from(case: &Case, from: u64, relation: &str) -> bool {
    case.edges()
        .iter()
        .any(|edge| edge.from == from && edge.relation == relation)
}
