use super::collect_plan;
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
    protocol::ProtocolLimits,
};
use serde_json::json;
use std::error::Error;

const RUN_BYTES: &[u8] = b"one|two|";

fn framing_case() -> Result<(Case, String, u64), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source(
        "identity-test.pcap",
        "capture",
        1_000_000,
        &l2_workbench::sha256(b"identity-test capture"),
        None,
    )?;
    let run = add_tcp_run(&mut case, &source, 1, RUN_BYTES)?;
    Ok((case, source, run))
}

fn add_tcp_run(
    case: &mut Case,
    source: &str,
    first_packet: u64,
    bytes: &[u8],
) -> Result<u64, Box<dyn Error>> {
    let endpoints = json!([
        {"address":"endpoint-a","port":1000},
        {"address":"endpoint-b","port":2000}
    ]);
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"identity-test","link_type":1},
            "endpoints":endpoints,
            "first_packet":first_packet,
            "generation_ambiguous":false
        }),
    )?;
    let [first_endpoint, second_endpoint] = endpoints
        .as_array()
        .ok_or("endpoint pair is not an array")?
        .as_slice()
    else {
        return Err("endpoint pair does not contain two endpoints".into());
    };
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
                offset: first_packet * 10_000,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({
            "offset":0,
            "length":bytes.len(),
            "start_known":true,
            "end_observed":true,
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
    Ok(run)
}

#[test]
fn unrelated_appended_nodes_blobs_and_edges_keep_the_plan_current() -> Result<(), Box<dyn Error>> {
    let (mut case, _, _) = framing_case()?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;
    assert!(plan.matches_case(&case));

    case.add_blob(b"unrelated retained bytes")?;
    let unrelated = case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    case.add_edge(Edge {
        from: unrelated,
        to: unrelated,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Unrelated evidence does not affect framing inputs".to_owned(),
    })?;

    assert!(plan.matches_case(&case));
    Ok(())
}

#[test]
fn appended_tcp_run_invalidates_the_plan() -> Result<(), Box<dyn Error>> {
    let (mut case, source, _) = framing_case()?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;

    add_tcp_run(&mut case, &source, 2, b"red|blue|")?;

    assert!(!plan.matches_case(&case));
    Ok(())
}

#[test]
fn appended_contains_edge_for_a_retained_run_invalidates_the_plan() -> Result<(), Box<dyn Error>> {
    let (mut case, _, run) = framing_case()?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;
    let competing_direction = case.add_node("tcp_direction", None, Vec::new(), json!({}))?;

    case.add_edge(Edge {
        from: competing_direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "A second parent changes run ancestry".to_owned(),
    })?;

    assert!(!plan.matches_case(&case));
    Ok(())
}

#[test]
fn appended_contains_edge_for_a_retained_direction_invalidates_the_plan()
-> Result<(), Box<dyn Error>> {
    let (mut case, _, run) = framing_case()?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;
    let direction = case
        .edges()
        .iter()
        .find(|edge| edge.to == run && edge.relation == "contains")
        .map(|edge| edge.from)
        .ok_or("TCP run has no direction parent")?;
    let competing_episode = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;

    case.add_edge(Edge {
        from: competing_episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "A second parent changes direction ancestry".to_owned(),
    })?;

    assert!(!plan.matches_case(&case));
    Ok(())
}

#[test]
fn a_rewound_case_does_not_match_a_plan_from_after_the_rewind() -> Result<(), Box<dyn Error>> {
    let (mut case, _, _) = framing_case()?;
    let mut plan_after_append = None;
    let transaction_result = case.transaction(|case| -> Result<(), Box<dyn Error>> {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
        plan_after_append = Some(collect_plan(case, ProtocolLimits::default())?);
        Err("force the transaction to rewind the appended node".into())
    });

    assert!(transaction_result.is_err());
    let plan_after_append = plan_after_append.ok_or("transaction did not collect a plan")?;
    assert!(!plan_after_append.matches_case(&case));
    Ok(())
}

#[test]
fn a_different_case_with_identical_contents_and_counts_invalidates_the_plan()
-> Result<(), Box<dyn Error>> {
    let (case, _, _) = framing_case()?;
    let plan = collect_plan(&case, ProtocolLimits::default())?;
    let cloned = case.clone();
    let serialized = case.to_json()?;
    let deserialized = Case::from_json(&serialized)?;

    assert_eq!(case.nodes().len(), cloned.nodes().len());
    assert_eq!(case.edges().len(), cloned.edges().len());
    assert_eq!(case.blobs().len(), cloned.blobs().len());
    assert_eq!(case.nodes().len(), deserialized.nodes().len());
    assert_eq!(case.edges().len(), deserialized.edges().len());
    assert_eq!(case.blobs().len(), deserialized.blobs().len());
    assert!(plan.matches_case(&case));
    assert!(!plan.matches_case(&cloned));
    assert!(!plan.matches_case(&deserialized));
    Ok(())
}
