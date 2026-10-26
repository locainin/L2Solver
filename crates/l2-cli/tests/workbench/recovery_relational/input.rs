use super::*;
use crate::workbench::recovery_executor::framing_discovery::{
    collect_plan, range_covered_by_native_messages,
};
use l2_workbench::{
    application::{ParseContext, http::decode_http},
    evidence::{ByteMapping, Edge, EvidenceStatus, SourceRange},
    protocol::ProtocolLimits,
};
use serde_json::json;
use std::error::Error;

#[test]
fn known_start_without_observed_end_remains_eligible_for_exact_artifact_checks()
-> Result<(), Box<dyn Error>> {
    let (case, run, key) = input(true)?;
    let selected = collect_with_native_coverage(&case, &key, &[&run])?;
    assert_eq!(selected.incoming.len(), 1);
    assert!(selected.incomplete_sessions.is_empty());
    assert_eq!(selected.omitted_runs, 0);
    let node = case.node(run.node_id).ok_or("missing input run")?;
    assert_eq!(node.details.get("end_observed"), Some(&json!(false)));
    Ok(())
}

#[test]
fn unknown_start_is_not_treated_as_a_known_counter_reset() -> Result<(), Box<dyn Error>> {
    let (case, run, key) = input(false)?;
    let selected = collect_with_native_coverage(&case, &key, &[&run])?;
    assert!(selected.incoming.is_empty());
    assert!(selected.incomplete_sessions.contains(&run.episode_node_id));
    assert_eq!(selected.omitted_runs, 1);
    Ok(())
}

#[test]
fn multiple_runs_in_one_session_are_not_joined_across_a_gap() -> Result<(), Box<dyn Error>> {
    let (mut case, run, key) = input(true)?;
    let later_node = case.add_bytes_node(
        "tcp_byte_run",
        b"later bytes",
        Vec::new(),
        json!({
            "offset":128,
            "start_known":false,
            "end_observed":true,
        }),
    )?;
    let later = RawRelationalRunInput {
        node_id: later_node,
        stream_offset: 128,
        start_known: false,
        ..run
    };
    let selected = collect_with_native_coverage(&case, &key, &[&run, &later])?;
    assert!(selected.incoming.is_empty());
    assert_eq!(selected.omitted_runs, 2);
    Ok(())
}

#[test]
fn fully_covered_native_http_message_skips_redundant_raw_search() -> Result<(), Box<dyn Error>> {
    let (case, run, key) = native_http_input(b"object bytes", None)?;

    let selected = collect_with_native_coverage(&case, &key, &[&run])?;

    assert!(selected.incoming.is_empty());
    assert!(selected.incomplete_sessions.is_empty());
    assert_eq!(selected.omitted_runs, 0);
    Ok(())
}

#[test]
fn unparsed_http_tail_remains_eligible_for_unknown_wire_search() -> Result<(), Box<dyn Error>> {
    let tail = b"unparsed extension bytes";
    let (case, run, key) = native_http_input(b"object bytes", Some(tail))?;

    let selected = collect_with_native_coverage(&case, &key, &[&run])?;

    assert_eq!(selected.incoming.len(), 1);
    assert!(selected.incomplete_sessions.is_empty());
    assert_eq!(selected.omitted_runs, 0);
    Ok(())
}

#[test]
fn native_message_coverage_does_not_infer_an_unobserved_tcp_end() -> Result<(), Box<dyn Error>> {
    let (case, run, key) = native_http_input(b"object bytes", None)?;

    let selected = collect_with_native_coverage(&case, &key, &[&run])?;
    let node = case.node(run.node_id).ok_or("missing input run")?;

    assert!(selected.incoming.is_empty());
    assert_eq!(node.details.get("end_observed"), Some(&json!(false)));
    Ok(())
}

fn native_http_input(
    body: &[u8],
    unparsed_tail: Option<&[u8]>,
) -> Result<(Case, RawRelationalRunInput, RelationalCohortKey), Box<dyn Error>> {
    let mut bytes = complete_http_message(body);
    if let Some(tail) = unparsed_tail {
        bytes.extend_from_slice(tail);
    }

    native_http_stream_input(&bytes)
}

fn native_http_stream_input(
    bytes: &[u8],
) -> Result<(Case, RawRelationalRunInput, RelationalCohortKey), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source(
        "http.pcap",
        "capture",
        1_000_000,
        &l2_workbench::sha256(bytes),
        None,
    )?;
    let first_packet = 1_u64;
    let (episode_node_id, _direction_node_id, node_id) =
        add_tcp_run_with_end_observed(&mut case, &source, first_packet, bytes, false)?;
    add_native_http_evidence(&mut case, node_id, bytes, false)?;
    let run = RawRelationalRunInput {
        node_id,
        episode_node_id,
        direction_node_id: episode_node_id,
        session_order: 1,
        stream_offset: 0,
        start_known: true,
    };
    let key = RelationalCohortKey {
        source_id: "source".into(),
        scope_json: "{}".into(),
        endpoints_json: "{}".into(),
        direction: Direction::FirstToSecond,
        framing_rule_json: "{}".into(),
        schema_json: "{}".into(),
    };
    Ok((case, run, key))
}

#[test]
fn native_http_frame_coverage_is_range_local() -> Result<(), Box<dyn Error>> {
    let body = b"object bytes";
    let complete_message = complete_http_message(body);
    let (case, run, _) = native_http_input(body, Some(b"unparsed tail"))?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;
    let coverage = plan
        .native_http_coverage_by_run()
        .get(&run.node_id)
        .ok_or("native parser receipts are not indexed")?;
    let message_range = l2_workbench::protocol::ByteRange {
        start: 0,
        end: complete_message.len(),
    };
    let tail_range = l2_workbench::protocol::ByteRange {
        start: complete_message.len(),
        end: complete_message.len() + b"unparsed tail".len(),
    };

    assert!(range_covered_by_native_messages(
        message_range,
        &coverage.message_ranges
    ));
    assert!(!range_covered_by_native_messages(
        tail_range,
        &coverage.message_ranges
    ));
    Ok(())
}

#[test]
fn native_parser_without_complete_messages_does_not_create_coverage() -> Result<(), Box<dyn Error>>
{
    let (case, run, _) = native_http_stream_input(b"bytes outside recognized HTTP framing")?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;

    assert!(
        !plan
            .native_http_coverage_by_run()
            .contains_key(&run.node_id)
    );
    Ok(())
}

fn collect_with_native_coverage(
    case: &Case,
    key: &RelationalCohortKey,
    runs: &[&RawRelationalRunInput],
) -> Result<CollectedRawSamples, RecoveryExecutionError> {
    let plan = collect_plan(case, ProtocolLimits::default())?;
    collect_raw_samples(case, key, runs, plan.native_http_coverage_by_run())
}

fn add_tcp_run_with_end_observed(
    case: &mut Case,
    source: &str,
    first_packet: u64,
    bytes: &[u8],
    end_observed: bool,
) -> Result<(u64, u64, u64), Box<dyn Error>> {
    let endpoints = json!([
        {"address":"192.0.2.1","port":1000},
        {"address":"192.0.2.2","port":2000}
    ]);
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"test","link_type":1},
            "endpoints":endpoints,
            "first_packet":first_packet,
            "generation_ambiguous":false
        }),
    )?;
    let endpoints = endpoints.as_array().ok_or("endpoints are not an array")?;
    let first_endpoint = endpoints.first().ok_or("first endpoint is missing")?;
    let second_endpoint = endpoints.get(1).ok_or("second endpoint is missing")?;
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":first_endpoint,
            "destination":second_endpoint,
            "sequence_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Direction belongs to the episode".to_owned(),
    })?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(first_packet),
                offset: first_packet.checked_mul(10_000).ok_or("offset overflow")?,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({
            "offset":0,
            "length":bytes.len(),
            "start_known":true,
            "end_observed":end_observed,
            "generation_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Run belongs to the direction".to_owned(),
    })?;
    Ok((episode, direction, run))
}

fn add_native_http_evidence(
    case: &mut Case,
    run_node_id: u64,
    bytes: &[u8],
    end_observed: bool,
) -> Result<(), Box<dyn Error>> {
    let report = decode_http(
        bytes,
        ParseContext {
            start_known: true,
            end_observed,
        },
    );
    let checks = case.add_node(
        "application_checks",
        None,
        Vec::new(),
        json!({
            "http": {
                "status":report.status,
                "messages":report.findings.len(),
                "unparsed":report.unparsed,
                "budget_omissions":report.budget_omissions,
            },
            "start_known":true,
            "end_observed":end_observed,
        }),
    )?;
    case.add_edge(Edge {
        from: run_node_id,
        to: checks,
        relation: "tested_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Bounded application parsers inspected these exact bytes".to_owned(),
    })?;
    for message in report.findings {
        let candidate = case.add_node(
            "http_message_candidate",
            None,
            Vec::new(),
            serde_json::to_value(message)?,
        )?;
        case.add_edge(Edge {
            from: run_node_id,
            to: candidate,
            relation: "parsed_as".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Native HTTP framing candidate".to_owned(),
        })?;
    }
    Ok(())
}

fn complete_http_message(body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn input(
    start_known: bool,
) -> Result<(Case, RawRelationalRunInput, RelationalCohortKey), Box<dyn Error>> {
    let mut case = Case::new();
    let episode_node_id = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;
    let node_id = case.add_bytes_node(
        "tcp_byte_run",
        b"captured prefix",
        Vec::new(),
        json!({
            "start_known":start_known,
            "end_observed":false,
        }),
    )?;
    let run = RawRelationalRunInput {
        node_id,
        episode_node_id,
        direction_node_id: episode_node_id,
        session_order: 1,
        stream_offset: 0,
        start_known,
    };
    let key = RelationalCohortKey {
        source_id: "source".into(),
        scope_json: "{}".into(),
        endpoints_json: "{}".into(),
        direction: Direction::FirstToSecond,
        framing_rule_json: "{}".into(),
        schema_json: "{}".into(),
    };
    Ok((case, run, key))
}
