use super::*;
use l2_workbench::evidence::{ByteMapping, Edge, SourceRange};
use l2_workbench::protocol::{FramingKind, RecordSchemaProposalLimits};
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

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

fn complete_direction_context() -> serde_json::Value {
    json!({
        "source":{"address":"endpoint-a","port":1000},
        "destination":{"address":"endpoint-b","port":2000},
        "start_known":true,
        "end_observed":true,
        "sequence_ambiguous":false,
        "coverage":{"length":4,"observed":4,"missing":0,"conflicting":0,"omitted":0,"omitted_observations":0}
    })
}

fn materialized_run(
    episode_statuses: &[EvidenceStatus],
    direction_contains_status: EvidenceStatus,
    direction_context: serde_json::Value,
) -> TestResult<(Case, u64, u64)> {
    materialized_run_with_endpoints(
        episode_statuses,
        direction_contains_status,
        direction_context,
        &json!([
            {"address":"endpoint-a","port":1000},
            {"address":"endpoint-b","port":2000}
        ]),
    )
}

fn materialized_run_with_endpoints(
    episode_statuses: &[EvidenceStatus],
    direction_contains_status: EvidenceStatus,
    direction_context: serde_json::Value,
    endpoints: &serde_json::Value,
) -> TestResult<(Case, u64, u64)> {
    let mut case = Case::new();
    let source_id = case.add_source(
        "record-ancestry.pcap",
        "capture",
        4096,
        &l2_workbench::sha256(b"record ancestry capture"),
        None,
    )?;
    let primary_episode = add_episode(&mut case, endpoints)?;
    let direction = case.add_node("tcp_direction", None, Vec::new(), direction_context)?;
    for (index, status) in episode_statuses.iter().enumerate() {
        let episode = if index == 0 {
            primary_episode
        } else {
            add_episode(&mut case, endpoints)?
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
        b"abc|",
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id,
                packet: Some(1),
                offset: 0,
                length: 4,
            },
        }],
        json!({
            "offset":0,
            "length":4,
            "generation_ambiguous":false,
            "start_known":true,
            "end_observed":true
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: direction_contains_status,
        reason: "Synthetic contiguous TCP bytes".to_owned(),
    })?;
    let outcome = crate::workbench::framing_materialize::apply(
        &mut case,
        run,
        &FramingKind::Delimiter { byte: b'|' },
    )?;
    let frame = *outcome
        .frame_nodes
        .first()
        .ok_or("materialization did not create a frame")?;
    Ok((case, primary_episode, frame))
}

#[test]
fn record_discovery_accepts_investigation_network_address_endpoints() -> TestResult<()> {
    let endpoints = json!([
        {"address":{"family":"ipv4","octets":[192,0,2,10]},"port":1000},
        {"address":{"family":"ipv4","octets":[192,0,2,20]},"port":2000}
    ]);
    let endpoint_values = endpoints
        .as_array()
        .ok_or("endpoint pair is not an array")?;
    let direction_context = json!({
        "source":endpoint_values.first().ok_or("first endpoint is missing")?,
        "destination":endpoint_values.get(1).ok_or("second endpoint is missing")?,
        "start_known":true,
        "end_observed":true,
        "sequence_ambiguous":false,
        "coverage":{"length":4,"observed":4,"missing":0,"conflicting":0,"omitted":0,"omitted_observations":0}
    });
    let (case, episode_id, _) = materialized_run_with_endpoints(
        &[EvidenceStatus::Hypothesis],
        EvidenceStatus::Observed,
        direction_context,
        &endpoints,
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    let input = plan
        .cohorts
        .values()
        .next()
        .and_then(|inputs| inputs.first())
        .ok_or("investigation-style endpoint context was omitted")?;
    assert_eq!(input.session_node_id, episode_id);
    Ok(())
}

#[test]
fn endpoint_validation_accepts_typed_and_imported_address_forms() {
    assert!(valid_endpoint(&json!({
        "address":{"family":"ipv4","octets":[192,0,2,10]},
        "port":443
    })));
    assert!(valid_endpoint(&json!({
        "address":"192.0.2.10",
        "port":443
    })));
    assert!(!valid_endpoint(&json!({
        "address":{"family":"ipv4","octets":[192,0,2]},
        "port":443
    })));
    assert!(!valid_endpoint(&json!({
        "address":"",
        "port":443
    })));
    assert!(!valid_endpoint(&json!({
        "address":{"family":"ipv4","octets":[192,0,2,10]},
        "port":65536
    })));
}

#[test]
fn record_discovery_keeps_unique_hypothesized_episode_ancestry() -> TestResult<()> {
    let (case, episode_id, frame_id) = materialized_run(
        &[EvidenceStatus::Hypothesis],
        EvidenceStatus::Observed,
        complete_direction_context(),
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    let inputs = plan
        .cohorts
        .values()
        .next()
        .ok_or("hypothesized ancestry did not produce a record cohort")?;
    let input = inputs
        .first()
        .ok_or("record cohort omitted its materialized frame")?;
    assert_eq!(inputs.len(), 1);
    assert_eq!(input.node_id, frame_id);
    assert_eq!(input.session_node_id, episode_id);
    Ok(())
}

#[test]
fn record_discovery_rejects_competing_episode_ancestry() -> TestResult<()> {
    let (case, _, frame_id) = materialized_run(
        &[EvidenceStatus::Hypothesis, EvidenceStatus::Observed],
        EvidenceStatus::Observed,
        complete_direction_context(),
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert!(plan.omissions.values().any(|omissions| {
        omissions.examples.iter().any(|example| {
            example
                .get("frame_node_id")
                .and_then(serde_json::Value::as_u64)
                == Some(frame_id)
                && example.get("reason").and_then(serde_json::Value::as_str)
                    == Some("ambiguous_conversation_context")
        })
    }));
    Ok(())
}

#[test]
fn record_discovery_rejects_invalid_episode_ancestry_status() -> TestResult<()> {
    let (case, _, frame_id) = materialized_run(
        &[EvidenceStatus::ConstraintFailed],
        EvidenceStatus::Observed,
        complete_direction_context(),
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert!(plan.omissions.values().any(|omissions| {
        omissions.examples.iter().any(|example| {
            example
                .get("frame_node_id")
                .and_then(serde_json::Value::as_u64)
                == Some(frame_id)
                && example.get("reason").and_then(serde_json::Value::as_str)
                    == Some("invalid_conversation_context")
        })
    }));
    Ok(())
}

#[test]
fn record_discovery_rejects_missing_episode_ancestry() -> TestResult<()> {
    let (case, _, frame_id) =
        materialized_run(&[], EvidenceStatus::Observed, complete_direction_context())?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert!(plan.omissions.values().any(|omissions| {
        omissions.examples.iter().any(|example| {
            example
                .get("frame_node_id")
                .and_then(serde_json::Value::as_u64)
                == Some(frame_id)
                && example.get("reason").and_then(serde_json::Value::as_str)
                    == Some("missing_conversation_context")
        })
    }));
    Ok(())
}

#[test]
fn record_discovery_rejects_hypothesized_direction_to_run_link() -> TestResult<()> {
    let (case, _, frame_id) = materialized_run(
        &[EvidenceStatus::Observed],
        EvidenceStatus::Hypothesis,
        complete_direction_context(),
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    assert!(plan.cohorts.is_empty());
    assert!(plan.omissions.values().any(|omissions| {
        omissions.examples.iter().any(|example| {
            example
                .get("frame_node_id")
                .and_then(serde_json::Value::as_u64)
                == Some(frame_id)
                && example.get("reason").and_then(serde_json::Value::as_str)
                    == Some("invalid_conversation_context")
        })
    }));
    Ok(())
}

#[test]
fn exact_materialized_frame_remains_eligible_with_partial_direction_context() -> TestResult<()> {
    let partial_direction = json!({
        "source":{"address":"endpoint-a","port":1000},
        "destination":{"address":"endpoint-b","port":2000},
        "start_known":false,
        "end_observed":false,
        "sequence_ambiguous":false,
        "coverage":{"length":8,"observed":4,"missing":4,"conflicting":0,"omitted":0,"omitted_observations":0}
    });
    let (case, _, frame_id) = materialized_run(
        &[EvidenceStatus::Hypothesis],
        EvidenceStatus::Observed,
        partial_direction,
    )?;

    let plan = collect_plan(&case, RecordSchemaProposalLimits::default())?;

    let inputs = plan
        .cohorts
        .values()
        .next()
        .ok_or("partial direction context excluded an exact materialized frame")?;
    let input = inputs
        .first()
        .ok_or("record cohort omitted its materialized frame")?;
    assert_eq!(input.node_id, frame_id);
    Ok(())
}
