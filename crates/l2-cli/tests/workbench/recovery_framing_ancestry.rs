use super::*;
use l2_workbench::evidence::{ByteMapping, Edge, SourceRange};
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

fn add_tcp_run(
    case: &mut Case,
    episode_statuses: &[EvidenceStatus],
) -> TestResult<(String, u64, u64)> {
    let source_id = case.add_source(
        "ancestry.pcap",
        "capture",
        4096,
        &l2_workbench::sha256(b"ancestry capture"),
        None,
    )?;
    let endpoints = json!([
        {"address":"endpoint-a","port":1000},
        {"address":"endpoint-b","port":2000}
    ]);
    let endpoint_values = endpoints
        .as_array()
        .ok_or("endpoint pair is not an array")?;
    let first_endpoint = endpoint_values.first().ok_or("first endpoint is missing")?;
    let second_endpoint = endpoint_values.get(1).ok_or("second endpoint is missing")?;
    let primary_episode = add_episode(case, &endpoints)?;
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":first_endpoint,
            "destination":second_endpoint,
            "start_known":false,
            "end_observed":false,
            "sequence_ambiguous":false
            ,"coverage":{
                "length":16,
                "observed":8,
                "missing":8,
                "conflicting":0,
                "omitted":0,
                "omitted_observations":0
            }
        }),
    )?;
    for (index, status) in episode_statuses.iter().enumerate() {
        let episode = if index == 0 {
            primary_episode
        } else {
            add_episode(case, &endpoints)?
        };
        case.add_edge(Edge {
            from: episode,
            to: direction,
            relation: "contains".to_owned(),
            status: *status,
            reason: "Synthetic episode ancestry".to_owned(),
        })?;
    }
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        b"one|two|",
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id.clone(),
                packet: Some(1),
                offset: 0,
                length: 8,
            },
        }],
        json!({
            "offset":0,
            "length":8,
            "generation_ambiguous":false,
            "start_known":true,
            "end_observed":true
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic contiguous TCP bytes".to_owned(),
    })?;
    Ok((source_id, primary_episode, run))
}

fn add_episode(case: &mut Case, endpoints: &serde_json::Value) -> TestResult<u64> {
    Ok(case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"eth0","link_type":1},
            "endpoints":endpoints,
            "first_packet":1,
            "generation_ambiguous":false
        }),
    )?)
}

#[test]
fn unique_hypothesized_episode_ancestry_is_usable_and_reported_as_hypothesis() -> TestResult<()> {
    let mut case = Case::new();
    let (source_id, episode_id, _) = add_tcp_run(&mut case, &[EvidenceStatus::Hypothesis])?;

    let plan = collect_plan(&case, ProtocolLimits::default())?;

    let inputs = plan
        .cohorts
        .values()
        .next()
        .ok_or("hypothesized ancestry did not produce a framing cohort")?;
    let input = inputs.first().ok_or("framing cohort omitted its input")?;
    assert_eq!(inputs.len(), 1);
    assert_eq!(input.context.session, episode_id);
    assert_eq!(input.episode_contains_status, EvidenceStatus::Hypothesis);
    assert_eq!(input.direction_contains_status, EvidenceStatus::Observed);
    assert_eq!(
        plan.omissions
            .get(&Some(source_id))
            .map_or(0, |omission| omission.total),
        0
    );
    Ok(())
}

#[test]
fn competing_episode_ancestry_is_omitted_as_ambiguous() -> TestResult<()> {
    let mut case = Case::new();
    let (source_id, _, _) = add_tcp_run(
        &mut case,
        &[EvidenceStatus::Hypothesis, EvidenceStatus::Observed],
    )?;

    let plan = collect_plan(&case, ProtocolLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert_eq!(
        plan.omissions
            .get(&Some(source_id))
            .and_then(|omission| omission.counts.get("ambiguous_context")),
        Some(&1)
    );
    Ok(())
}

#[test]
fn invalid_episode_ancestry_status_is_not_used_as_context() -> TestResult<()> {
    let mut case = Case::new();
    let (source_id, _, _) = add_tcp_run(&mut case, &[EvidenceStatus::ConstraintFailed])?;

    let plan = collect_plan(&case, ProtocolLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert_eq!(
        plan.omissions
            .get(&Some(source_id))
            .and_then(|omission| omission.counts.get("invalid_context")),
        Some(&1)
    );
    Ok(())
}

#[test]
fn missing_episode_ancestry_remains_a_missing_context_omission() -> TestResult<()> {
    let mut case = Case::new();
    let (source_id, _, _) = add_tcp_run(&mut case, &[])?;

    let plan = collect_plan(&case, ProtocolLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert_eq!(
        plan.omissions
            .get(&Some(source_id))
            .and_then(|omission| omission.counts.get("missing_context")),
        Some(&1)
    );
    Ok(())
}

#[test]
fn standard_recovery_flow_keeps_hypothesized_episode_provenance() -> TestResult<()> {
    let mut case = Case::new();
    let (_, episode_id, run_id) = add_tcp_run(&mut case, &[EvidenceStatus::Hypothesis])?;

    super::super::super::recover_case(&mut case)?;

    assert_framing_report_context(&case, run_id)?;
    assert_materialized_context(&case, episode_id, run_id)?;
    assert_record_report_context(&case, run_id)?;
    Ok(())
}

fn report_json(case: &Case, kind: &str) -> TestResult<serde_json::Value> {
    let report = case
        .nodes()
        .iter()
        .find(|node| node.kind == kind)
        .ok_or_else(|| format!("standard recovery omitted {kind}"))?;
    let blob = case
        .blob(
            report
                .blob
                .as_deref()
                .ok_or("recovery report has no blob")?,
        )
        .ok_or("recovery report blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn report_input<'a>(
    report: &'a serde_json::Value,
    list_field: &str,
    id_field: &str,
    id: u64,
) -> TestResult<&'a serde_json::Value> {
    report
        .get(list_field)
        .and_then(serde_json::Value::as_array)
        .and_then(|inputs| {
            inputs
                .iter()
                .find(|input| input.get(id_field) == Some(&json!(id)))
        })
        .ok_or_else(|| format!("report omitted node {id} in {list_field}").into())
}

fn assert_framing_report_context(case: &Case, run_id: u64) -> TestResult<()> {
    let report = report_json(case, "recovery_framing_discovery_report")?;
    let input = report_input(&report, "input_runs", "node_id", run_id)?;
    assert_eq!(
        input
            .pointer("/ancestry/episode_contains_status")
            .and_then(serde_json::Value::as_str),
        Some("hypothesis")
    );
    Ok(())
}

fn assert_materialized_context(case: &Case, episode_id: u64, run_id: u64) -> TestResult<()> {
    let frame = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_frame"
                && node.details.get("input_node") == Some(&json!(run_id))
        })
        .ok_or("standard recovery did not materialize the TCP run")?;
    let direction_id = direction_parent(case, run_id).ok_or("TCP run has no direction parent")?;
    assert!(case.edges().iter().any(|edge| {
        edge.from == run_id
            && edge.to == frame.id
            && edge.relation == "candidate_framed_as"
            && edge.status == EvidenceStatus::Hypothesis
    }));
    assert!(case.edges().iter().any(|edge| {
        edge.from == episode_id
            && edge.to == direction_id
            && edge.relation == "contains"
            && edge.status == EvidenceStatus::Hypothesis
    }));
    Ok(())
}

fn assert_record_report_context(case: &Case, run_id: u64) -> TestResult<()> {
    let (report, frame_node_id) = record_report_frame_for_run(case, run_id)?;
    assert_eq!(report.get("version"), Some(&json!(3)));
    let frame = case
        .nodes()
        .iter()
        .find(|node| node.id == frame_node_id && node.kind == "custom_protocol_frame")
        .ok_or("compact record report frame does not resolve")?;
    let direction_edge = case
        .edges()
        .iter()
        .find(|edge| {
            edge.to == run_id
                && edge.relation == "contains"
                && case
                    .nodes()
                    .iter()
                    .any(|node| node.id == edge.from && node.kind == "tcp_direction")
        })
        .ok_or("TCP run direction ancestry is missing")?;
    assert_eq!(direction_edge.status, EvidenceStatus::Observed);
    let episode_edge = case
        .edges()
        .iter()
        .find(|edge| {
            edge.to == direction_edge.from
                && edge.relation == "contains"
                && case
                    .nodes()
                    .iter()
                    .any(|node| node.id == edge.from && node.kind == "tcp_episode")
        })
        .ok_or("TCP direction episode ancestry is missing")?;
    assert_eq!(episode_edge.status, EvidenceStatus::Hypothesis);
    assert_eq!(frame.details.get("input_node"), Some(&json!(run_id)));
    Ok(())
}

fn record_report_frame_for_run(case: &Case, run_id: u64) -> TestResult<(serde_json::Value, u64)> {
    for report_node in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_record_discovery_report")
    {
        let report_blob_id = report_node
            .blob
            .as_deref()
            .ok_or("record discovery report has no blob")?;
        let report_blob = case
            .blob(report_blob_id)
            .ok_or("record discovery report blob is missing")?;
        let report: serde_json::Value = serde_json::from_slice(&report_blob.bytes)?;
        let frame_node_id = report
            .get("input_frame_refs")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_array)
            .filter_map(|reference| reference.first().and_then(serde_json::Value::as_u64))
            .find(|frame_id| {
                case.node(*frame_id).is_some_and(|node| {
                    node.kind == "custom_protocol_frame"
                        && node.details.get("input_node") == Some(&json!(run_id))
                })
            });
        if let Some(frame_node_id) = frame_node_id {
            return Ok((report, frame_node_id));
        }
    }
    Err(format!("standard recovery omitted a record report referencing TCP run {run_id}").into())
}

fn direction_parent(case: &Case, run_id: u64) -> Option<u64> {
    case.edges()
        .iter()
        .find(|edge| edge.to == run_id && edge.relation == "contains")
        .map(|edge| edge.from)
}
