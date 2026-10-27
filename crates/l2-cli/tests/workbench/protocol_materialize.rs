use super::support::run;
use l2_workbench::evidence::{ByteMapping, Case, EvidenceStatus, SourceRange, clip_byte_mappings};
use serde_json::json;
use std::{error::Error, process::Command};

#[test]
fn help_shows_framing_rule_syntax() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench", "materialize-frames", "--help"])
        .output()?;

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for flag in [
        "--delimiter-byte",
        "--fixed-size",
        "--length-prefix",
        "--rule-json",
        "--discovery-report",
    ] {
        assert!(help.contains(flag), "missing {flag} from help:\n{help}");
    }
    Ok(())
}

#[test]
fn discovered_rule_selection_records_report_provenance() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"aabb")?;
    let run_id = tcp_run_id(&input_case)?;
    let report_bytes = serde_json::to_vec(&json!({
        "version":1,
        "case_scope":"current_case",
        "source_id":"fixture-source",
        "cohort":{"scope":"fixture"},
        "bootstrap":{"hypotheses":[{"kind":"fixed_size","bytes":2}]}
    }))?;
    let mut input_case = input_case;
    let report_id = input_case.add_bytes_node(
        "recovery_framing_discovery_report",
        &report_bytes,
        Vec::new(),
        json!({"report_schema_version":1}),
    )?;
    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--fixed-size",
            "2",
            "--discovery-report",
            &report_id.to_string(),
        ],
        &input_case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let materialized_case = Case::from_json(&output.stdout)?;
    let basis = json!({"kind":"caller_and_discovered","report_node":report_id});
    let receipt = materialized_case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_framing_receipt")
        .ok_or("framing receipt is missing")?;
    assert_eq!(receipt.details.get("selection_basis"), Some(&basis));
    assert!(materialized_case.edges().iter().any(|edge| {
        edge.from == report_id
            && edge.to == receipt.id
            && edge.relation == "framing_rule_selected_from"
    }));
    assert!(materialized_case.validate().is_ok());
    Ok(())
}

#[test]
fn discovery_report_must_contain_rule_selected_by_cli() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"aabb")?;
    let run_id = tcp_run_id(&input_case)?;
    let report_bytes = serde_json::to_vec(&json!({
        "version":1,
        "case_scope":"current_case",
        "source_id":"fixture-source",
        "cohort":{"scope":"fixture"},
        "bootstrap":{"hypotheses":[{"kind":"fixed_size","bytes":1}]}
    }))?;
    let mut input_case = input_case;
    let report_id = input_case.add_bytes_node(
        "recovery_framing_discovery_report",
        &report_bytes,
        Vec::new(),
        json!({"report_schema_version":1}),
    )?;
    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--fixed-size",
            "2",
            "--discovery-report",
            &report_id.to_string(),
        ],
        &input_case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn fixed_size_frames_expand_zip() -> Result<(), Box<dyn Error>> {
    let archive = empty_zip();
    let mut stream = archive.clone();
    stream.extend_from_slice(&archive);
    let input_case = tcp_run_case(&stream)?;
    let run_id = tcp_run_id(&input_case)?;
    let frame_size = archive.len().to_string();

    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--fixed-size",
            &frame_size,
        ],
        &input_case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let materialized_case = Case::from_json(&output.stdout)?;
    let protocol_frames = materialized_case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .collect::<Vec<_>>();
    assert_eq!(protocol_frames.len(), 2);
    let archive_frame = protocol_frames
        .iter()
        .find(|node| node.details.get("frame_index") == Some(&json!(0)))
        .ok_or("first protocol frame is missing")?;
    let frame_bytes = blob_bytes(&materialized_case, archive_frame)?;
    assert_eq!(frame_bytes, archive.as_slice());

    let mapped =
        l2_workbench::carrier::discovery::mapped_node(&materialized_case, archive_frame.id)?;
    assert_eq!(mapped.bytes, frame_bytes);
    let [first_mapping, second_mapping] = mapped.mappings.as_slice() else {
        return Err("expected two source mappings".into());
    };
    assert_eq!(first_mapping.offset, 0);
    assert_eq!(first_mapping.range.offset, 100);
    assert_eq!(first_mapping.range.length, 14);
    assert_eq!(second_mapping.offset, 14);
    assert_eq!(second_mapping.range.offset, 1_000);
    assert_eq!(second_mapping.range.length, 8);

    assert!(materialized_case.edges().iter().any(|edge| {
        edge.from == run_id
            && edge.to == archive_frame.id
            && edge.relation == "candidate_framed_as"
            && edge.status == EvidenceStatus::Hypothesis
    }));
    assert!(materialized_case.validate().is_ok());

    let expanded_output = run(
        &["expand", "-", "--node", &archive_frame.id.to_string()],
        &materialized_case.to_json()?,
    )?;
    assert!(
        expanded_output.status.success(),
        "{}",
        String::from_utf8_lossy(&expanded_output.stderr)
    );
    let expanded_case = Case::from_json(&expanded_output.stdout)?;
    assert!(
        expanded_case
            .nodes()
            .iter()
            .any(|node| node.kind == "archive_structure")
    );
    Ok(())
}

#[test]
fn delimiter_materializes_complete_frames() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"one\ntwo\n")?;
    let run_id = tcp_run_id(&input_case)?;
    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--delimiter-byte",
            "0x0a",
        ],
        &input_case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let materialized_case = Case::from_json(&output.stdout)?;
    let frames = materialized_case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .collect::<Vec<_>>();
    assert_eq!(frames.len(), 2);
    let [first_frame, second_frame] = frames.as_slice() else {
        return Err("expected two materialized protocol frames".into());
    };
    assert_eq!(blob_bytes(&materialized_case, first_frame)?, b"one\n");
    assert_eq!(blob_bytes(&materialized_case, second_frame)?, b"two\n");
    Ok(())
}

#[test]
fn length_prefix_materializes_complete_frames() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"\x04one\x04two")?;
    let run_id = tcp_run_id(&input_case)?;
    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--length-prefix",
            "0:1:big_endian:whole_message",
        ],
        &input_case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let materialized_case = Case::from_json(&output.stdout)?;
    let frames = materialized_case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .collect::<Vec<_>>();
    let [first_frame, second_frame] = frames.as_slice() else {
        return Err("expected two length-prefixed frames".into());
    };
    assert_eq!(blob_bytes(&materialized_case, first_frame)?, b"\x04one");
    assert_eq!(blob_bytes(&materialized_case, second_frame)?, b"\x04two");
    Ok(())
}

#[test]
fn incomplete_tail_is_materialized() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"first\nunfinished")?;
    let run_id = tcp_run_id(&input_case)?;

    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--rule-json",
            r#"{"kind":"delimiter","byte":10}"#,
        ],
        &input_case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let materialized_case = Case::from_json(&output.stdout)?;
    assert_eq!(
        node_bytes_by_kind(&materialized_case, "custom_protocol_frame")?,
        b"first\n"
    );
    assert_eq!(
        node_bytes_by_kind(&materialized_case, "custom_protocol_framing_tail")?,
        b"unfinished"
    );
    let tail = materialized_case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_framing_tail")
        .ok_or("framing tail is missing")?;
    assert!(materialized_case.edges().iter().any(|edge| {
        edge.to == tail.id
            && edge.relation == "materialized"
            && materialized_case.node(edge.from).is_some_and(|receipt| {
                receipt.details.get("selection_basis") == Some(&json!({"kind":"caller_supplied"}))
            })
    }));
    let input_mappings = l2_workbench::carrier::discovery::mapped_node(&input_case, run_id)?
        .mappings
        .into_iter()
        .map(|mapping| ByteMapping {
            offset: mapping.offset,
            range: mapping.range,
        })
        .collect::<Vec<_>>();
    let tail_node = materialized_case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_framing_tail")
        .ok_or("framing tail is missing")?;
    let tail_mappings =
        l2_workbench::carrier::discovery::mapped_node(&materialized_case, tail_node.id)?
            .mappings
            .into_iter()
            .map(|mapping| ByteMapping {
                offset: mapping.offset,
                range: mapping.range,
            })
            .collect::<Vec<_>>();
    assert_eq!(
        mapping_shapes(&tail_mappings),
        mapping_shapes(&clip_byte_mappings(
            &input_mappings,
            6..b"first\nunfinished".len()
        )?)
    );
    let receipt = materialized_case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_framing_receipt")
        .ok_or("framing receipt is missing")?;
    assert_eq!(
        receipt.details.get("status"),
        Some(&json!("incomplete_tail"))
    );
    assert!(materialized_case.validate().is_ok());
    Ok(())
}

#[test]
fn invalid_rule_yields_tail() -> Result<(), Box<dyn Error>> {
    let input_case = tcp_run_case(b"invalid rule input")?;
    let run_id = tcp_run_id(&input_case)?;

    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--rule-json",
            r#"{"kind":"fixed_size","bytes":0}"#,
        ],
        &input_case.to_json()?,
    )?;

    assert_eq!(output.status.code(), Some(3));
    let materialized_case = Case::from_json(&output.stdout)?;
    assert_eq!(
        node_bytes_by_kind(&materialized_case, "custom_protocol_framing_tail")?,
        b"invalid rule input"
    );
    assert!(
        !materialized_case
            .nodes()
            .iter()
            .any(|node| node.kind == "custom_protocol_frame")
    );
    let receipt = materialized_case
        .nodes()
        .iter()
        .find(|node| node.kind == "custom_protocol_framing_receipt")
        .ok_or("framing receipt is missing")?;
    assert_eq!(
        receipt.details.get("status"),
        Some(&json!("invalid_candidate"))
    );
    assert!(materialized_case.validate().is_ok());
    Ok(())
}

#[test]
fn materializes_beyond_report_preview_count() -> Result<(), Box<dyn Error>> {
    let bytes = b"x\n".repeat(300);
    let input_case = tcp_run_case(&bytes)?;
    let run_id = tcp_run_id(&input_case)?;

    let output = run(
        &[
            "materialize-frames",
            "-",
            "--node",
            &run_id.to_string(),
            "--delimiter-byte",
            "10",
        ],
        &input_case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let materialized_case = Case::from_json(&output.stdout)?;
    assert_eq!(
        materialized_case
            .nodes()
            .iter()
            .filter(|node| node.kind == "custom_protocol_frame")
            .count(),
        300
    );
    Ok(())
}

fn tcp_run_case(bytes: &[u8]) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(2_000 + bytes.len())?,
        &l2_workbench::sha256(b"synthetic capture identity"),
        None,
    )?;
    let split = bytes.len() / 3;
    let mappings = [
        ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.clone(),
                packet: Some(1),
                offset: 100,
                length: u64::try_from(split)?,
            },
        },
        ByteMapping {
            offset: split,
            range: SourceRange {
                source,
                packet: Some(2),
                offset: 1_000,
                length: u64::try_from(bytes.len() - split)?,
            },
        },
    ];
    case.add_mapped_bytes_node("tcp_byte_run", bytes, &mappings, json!({}))?;
    Ok(case)
}

fn tcp_run_id(case: &Case) -> Result<u64, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == "tcp_byte_run")
        .map(|node| node.id)
        .ok_or_else(|| "TCP byte run is missing".into())
}

fn mapping_shapes(mappings: &[ByteMapping]) -> Vec<(usize, SourceRange)> {
    mappings
        .iter()
        .map(|mapping| (mapping.offset, mapping.range.clone()))
        .collect()
}

fn blob_bytes<'a>(
    case: &'a Case,
    node: &l2_workbench::evidence::Node,
) -> Result<&'a [u8], Box<dyn Error>> {
    let blob_id = node.blob.as_deref().ok_or("node blob is missing")?;
    case.blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or_else(|| "node blob is not retained".into())
}

fn node_bytes_by_kind<'a>(case: &'a Case, kind: &str) -> Result<&'a [u8], Box<dyn Error>> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.kind == kind)
        .ok_or_else(|| format!("node kind {kind} is missing"))?;
    blob_bytes(case, node)
}

fn empty_zip() -> Vec<u8> {
    [b"PK\x05\x06".as_slice(), &[0; 18]].concat()
}
