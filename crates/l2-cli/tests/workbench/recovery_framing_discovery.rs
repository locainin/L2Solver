use super::{RecoveryExecutionPolicy, RecoveryPlan, execute};
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, MAX_EDGES, MAX_REASON_BYTES, SourceRange},
    protocol::{
        ByteRunSample, Direction, FramingKind, MessageContext, ProtocolLimits,
        bootstrap_framing_with_execution_plan, bootstrap_framing_with_limits,
    },
    recovery::{RecoveryCandidate, RecoveryCandidateState, RecoveryResult, RecoveryTask},
};
use serde_json::{Value, json};
use std::error::Error;

macro_rules! field {
    ($value:expr, $key:literal) => {
        $value
            .get($key)
            .ok_or_else(|| format!("report is missing field {}", $key))?
    };
}

macro_rules! item {
    ($value:expr, $index:expr) => {
        $value
            .as_array()
            .and_then(|items| items.get($index))
            .ok_or("report is missing an array item")?
    };
}

fn add_unresolved_tcp_runs(case: &mut Case, source: &str) -> Result<(u64, u64), Box<dyn Error>> {
    let orphan = case.add_mapped_bytes_node(
        "tcp_byte_run",
        b"orphan|run|",
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(40),
                offset: 400_000,
                length: 11,
            },
        }],
        json!({"offset":0,"length":11,"generation_ambiguous":false}),
    )?;
    let mixed_source = capture(case, "mixed")?;
    let mixed = case.add_mapped_bytes_node(
        "tcp_byte_run",
        b"mixed|run|",
        &[
            ByteMapping {
                offset: 0,
                range: SourceRange {
                    source: source.to_owned(),
                    packet: Some(50),
                    offset: 500_000,
                    length: 5,
                },
            },
            ByteMapping {
                offset: 5,
                range: SourceRange {
                    source: mixed_source,
                    packet: Some(50),
                    offset: 500_005,
                    length: 5,
                },
            },
        ],
        json!({"offset":0,"length":10,"generation_ambiguous":false}),
    )?;
    Ok((orphan, mixed))
}

fn capture(case: &mut Case, label: &str) -> Result<String, Box<dyn Error>> {
    capture_with_size(case, label, 1_000_000)
}

fn capture_with_size(case: &mut Case, label: &str, size: u64) -> Result<String, Box<dyn Error>> {
    let contents = format!("capture source for {label}");
    Ok(case.add_source(
        &format!("{label}.pcap"),
        "capture",
        size,
        &l2_workbench::sha256(contents.as_bytes()),
        None,
    )?)
}

const IRRELEVANT_EDGE_RELATION: &str = "unrelated_graph_edge";
const IRRELEVANT_EDGE_REASON: &str = "Synthetic edge outside the TCP ancestry";

fn framing_case_with_irrelevant_edges(edge_count: usize) -> Result<(Case, u64), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "edge-work")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
    let unrelated = case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    let reason = format!(
        "{IRRELEVANT_EDGE_REASON}{}",
        "x".repeat(MAX_REASON_BYTES - IRRELEVANT_EDGE_REASON.len())
    );
    for _ in 0..edge_count {
        case.add_edge(Edge {
            from: unrelated,
            to: unrelated,
            relation: IRRELEVANT_EDGE_RELATION.to_owned(),
            status: EvidenceStatus::Observed,
            reason: reason.clone(),
        })?;
    }
    Ok((case, run))
}

fn fill_case_nodes_to_quota(case: &mut Case) -> Result<(), Box<dyn Error>> {
    while case.nodes().len() < l2_workbench::evidence::MAX_NODES {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    }
    Ok(())
}

fn fill_case_edges_to_quota(case: &mut Case) -> Result<(), Box<dyn Error>> {
    let unrelated = case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    while case.edges().len() < MAX_EDGES {
        case.add_edge(Edge {
            from: unrelated,
            to: unrelated,
            relation: IRRELEVANT_EDGE_RELATION.to_owned(),
            status: EvidenceStatus::Observed,
            reason: IRRELEVANT_EDGE_REASON.to_owned(),
        })?;
    }
    Ok(())
}

fn disable_root_expansion(policy: &mut RecoveryExecutionPolicy) {
    policy.resources.max_depth = 0;
    policy.expansion_limits.depth = 0;
}

fn add_tcp_run(
    case: &mut Case,
    source: &str,
    scope_name: &str,
    first_packet: u32,
    direction_index: usize,
    stream_offset: usize,
    bytes: &[u8],
) -> Result<u64, Box<dyn Error>> {
    add_tcp_run_with_state(
        case,
        TcpRunFixture {
            source,
            scope_name,
            first_packet,
            direction_index,
            stream_offset,
            bytes,
            state: TcpRunState::Complete,
        },
    )
}

#[derive(Clone, Copy)]
enum TcpRunState {
    Complete,
    IncompleteBoundaries,
    SequenceAmbiguous,
    GenerationAmbiguous,
}

impl TcpRunState {
    const fn details(self) -> (BoundaryState, bool, bool) {
        match self {
            Self::Complete => (BoundaryState::Complete, false, false),
            Self::IncompleteBoundaries => (BoundaryState::BothUnknown, false, false),
            Self::SequenceAmbiguous => (BoundaryState::Complete, true, false),
            Self::GenerationAmbiguous => (BoundaryState::Complete, false, true),
        }
    }
}

#[derive(Clone, Copy)]
enum BoundaryState {
    Complete,
    StartUnknown,
    EndUnobserved,
    BothUnknown,
}

impl BoundaryState {
    const fn flags(self) -> (bool, bool) {
        match self {
            Self::Complete => (true, true),
            Self::StartUnknown => (false, true),
            Self::EndUnobserved => (true, false),
            Self::BothUnknown => (false, false),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpRunFixture<'a> {
    source: &'a str,
    scope_name: &'a str,
    first_packet: u32,
    direction_index: usize,
    stream_offset: usize,
    bytes: &'a [u8],
    state: TcpRunState,
}

#[derive(Clone, Copy)]
struct TcpDirectionFixture<'a> {
    scope_name: &'a str,
    first_packet: u32,
    direction_index: usize,
    coverage: &'a Value,
    state: TcpRunState,
    parent_status: EvidenceStatus,
}

fn add_tcp_run_with_state(
    case: &mut Case,
    fixture: TcpRunFixture<'_>,
) -> Result<u64, Box<dyn Error>> {
    let TcpRunFixture {
        source,
        scope_name,
        first_packet,
        direction_index,
        stream_offset,
        bytes,
        state,
    } = fixture;
    let (boundaries, _, generation_ambiguous) = state.details();
    let coverage = json!({
        "length":bytes.len(),
        "observed":bytes.len(),
        "missing":0,
        "conflicting":0,
        "omitted":0,
        "omitted_observations":0
    });
    let direction = add_tcp_direction(
        case,
        TcpDirectionFixture {
            scope_name,
            first_packet,
            direction_index,
            coverage: &coverage,
            state,
            parent_status: EvidenceStatus::Observed,
        },
    )?;
    add_tcp_run_to_direction(
        case,
        TcpRunNodeFixture {
            source,
            first_packet,
            direction,
            stream_offset,
            bytes,
            boundaries,
            generation_ambiguous,
            edge_status: EvidenceStatus::Observed,
        },
    )
}

fn add_tcp_direction(
    case: &mut Case,
    fixture: TcpDirectionFixture<'_>,
) -> Result<u64, Box<dyn Error>> {
    let TcpDirectionFixture {
        scope_name,
        first_packet,
        direction_index,
        coverage,
        state,
        parent_status,
    } = fixture;
    let (boundaries, sequence_ambiguous, generation_ambiguous) = state.details();
    let (start_known, end_observed) = boundaries.flags();
    let endpoints = json!([
        {"address":"endpoint-a","port":1000},
        {"address":"endpoint-b","port":2000}
    ]);
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":scope_name,"link_type":1},
            "endpoints":endpoints,
            "first_packet":first_packet,
            "generation_ambiguous":generation_ambiguous
        }),
    )?;
    let [first_endpoint, second_endpoint] = endpoints
        .as_array()
        .ok_or("endpoint pair is not an array")?
        .as_slice()
    else {
        return Err("endpoint pair does not contain two endpoints".into());
    };
    let (source_endpoint, destination_endpoint) = if direction_index == 0 {
        (first_endpoint.clone(), second_endpoint.clone())
    } else {
        (second_endpoint.clone(), first_endpoint.clone())
    };
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":source_endpoint,
            "destination":destination_endpoint,
            "start_sequence":0,
            "start_known":start_known,
            "end_observed":end_observed,
            "sequence_ambiguous":sequence_ambiguous,
            "outside_segments":0,
            "coverage":coverage
        }),
    )?;
    case.add_edge(Edge {
        from: episode,
        to: direction,
        relation: "contains".to_owned(),
        status: parent_status,
        reason: "Synthetic direction belongs to this episode".to_owned(),
    })?;
    Ok(direction)
}

#[derive(Clone, Copy)]
struct TcpRunNodeFixture<'a> {
    source: &'a str,
    first_packet: u32,
    direction: u64,
    stream_offset: usize,
    bytes: &'a [u8],
    boundaries: BoundaryState,
    generation_ambiguous: bool,
    edge_status: EvidenceStatus,
}

fn add_tcp_run_to_direction(
    case: &mut Case,
    fixture: TcpRunNodeFixture<'_>,
) -> Result<u64, Box<dyn Error>> {
    let TcpRunNodeFixture {
        source,
        first_packet,
        direction,
        stream_offset,
        bytes,
        boundaries,
        generation_ambiguous,
        edge_status,
    } = fixture;
    let (start_known, end_observed) = boundaries.flags();
    let source_offset = u64::from(first_packet)
        .checked_mul(10_000)
        .and_then(|offset| offset.checked_add(u64::try_from(stream_offset).ok()?))
        .ok_or("source offset overflow")?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(u64::from(first_packet)),
                offset: source_offset,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({
            "offset":stream_offset,
            "length":bytes.len(),
            "start_known":start_known,
            "end_observed":end_observed,
            "generation_ambiguous":generation_ambiguous
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: edge_status,
        reason: "Synthetic run belongs to this direction".to_owned(),
    })?;
    Ok(run)
}

fn assert_materialized_frames_respect_run_boundaries(
    case: &Case,
    source: &str,
    run_ids: &[u64],
    gap: (u64, u64),
) -> Result<(), Box<dyn Error>> {
    let frames = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .collect::<Vec<_>>();
    assert_ne!(frames.len(), 0);
    for frame in frames {
        let input_node = field!(&frame.details, "input_node")
            .as_u64()
            .ok_or("materialized frame has no input run")?;
        assert!(run_ids.contains(&input_node));
        let parents = case
            .edges()
            .iter()
            .filter(|edge| edge.to == frame.id && edge.relation == "candidate_framed_as")
            .map(|edge| edge.from)
            .collect::<Vec<_>>();
        assert_eq!(parents, vec![input_node]);
        assert_ne!(frame.ranges.len(), 0);
        for mapping in &frame.ranges {
            let range_end = mapping
                .offset
                .checked_add(mapping.length)
                .ok_or("materialized frame source mapping overflows")?;
            assert_eq!(mapping.source, source);
            assert!(range_end <= gap.0 || mapping.offset >= gap.1);
        }
    }
    Ok(())
}

fn decode_report(case: &Case, report_node_id: u64) -> Result<Value, Box<dyn Error>> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == report_node_id)
        .ok_or("framing discovery report node is missing")?;
    let blob_id = node
        .blob
        .as_deref()
        .ok_or("framing discovery report has no retained bytes")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .ok_or("framing discovery report blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn discovery_candidate<'a>(
    outcome: &'a super::RecoveryExecutionOutcome,
    input_ids: &[u64],
) -> Result<&'a RecoveryCandidate, Box<dyn Error>> {
    outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::FramingDiscovery
                && candidate
                    .inputs()
                    .iter()
                    .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
                    .copied()
                    .collect::<Vec<_>>()
                    == input_ids
        })
        .ok_or_else(|| "Case-wide framing discovery candidate is missing".into())
}

fn framing_policy(case: &Case) -> Result<RecoveryExecutionPolicy, Box<dyn Error>> {
    Ok(super::policy::normal_policy(case)?)
}

fn framing_plan() -> RecoveryPlan {
    RecoveryPlan {
        discover_framing: true,
        ..RecoveryPlan::default()
    }
}

fn unresolved_tcp_case() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "unresolved-scan")?;
    add_unresolved_tcp_runs(&mut case, &source)?;
    Ok(case)
}

fn discovery_report_for(
    outcome: &super::RecoveryExecutionOutcome,
    case: &Case,
    input_ids: &[u64],
) -> Result<Value, Box<dyn Error>> {
    let candidate = discovery_candidate(outcome, input_ids)?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = candidate.state()
    else {
        return Err("framing discovery did not retain a hypothesis report".into());
    };
    decode_report(case, *node_id)
}

fn direction_for_run(case: &Case, run: u64) -> Result<u64, Box<dyn Error>> {
    case.edges()
        .iter()
        .find(|edge| {
            edge.to == run && edge.relation == "contains" && edge.status == EvidenceStatus::Observed
        })
        .map(|edge| edge.from)
        .ok_or_else(|| "TCP run has no observed direction parent".into())
}

fn episode_for_run(case: &Case, run: u64) -> Result<u64, Box<dyn Error>> {
    let direction = direction_for_run(case, run)?;
    case.edges()
        .iter()
        .find(|edge| {
            edge.to == direction
                && edge.relation == "contains"
                && edge.status == EvidenceStatus::Observed
        })
        .map(|edge| edge.from)
        .ok_or_else(|| "TCP direction has no observed episode parent".into())
}

fn bounded_report_fixture()
-> Result<(Value, l2_workbench::protocol::FramingBootstrapReport), Box<dyn Error>> {
    let context = l2_workbench::protocol::MessageContext {
        source: "source-identity".to_owned(),
        scope: "scope-a".to_owned(),
        session: 1,
        direction: Direction::FirstToSecond,
    };
    let run = ByteRunSample {
        sample: 1,
        context: Some(context),
        bytes: b"one|two|",
    };
    let bootstrap = bootstrap_framing_with_limits(&[run], ProtocolLimits::default())?;
    let cohort = json!({
        "scope": "scope-a",
        "endpoint_pair": "endpoint-pair-a",
        "direction": "first_to_second"
    });
    let report = json!({
        "version": 1,
        "case_scope": "current_case",
        "source_id": "source-identity",
        "cohort": cohort,
        "protocol_limits": ProtocolLimits::default(),
        "input_runs": [{"node_id":1,"details":"x".repeat(8_192)}],
        "bootstrap": &bootstrap,
        "work_bound_bytes": 33,
    });
    Ok((report, bootstrap))
}

#[test]
fn one_run_framing_discovery_schedules_each_surviving_rule_with_combined_basis()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "single")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;

    let execution_policy = framing_policy(&case)?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::Delimiter { byte: b'|' }],
        ..framing_plan()
    };
    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let candidate = discovery_candidate(&outcome, &[run])?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = candidate.state()
    else {
        return Err("one-run discovery did not retain a hypothesis report".into());
    };
    let report = decode_report(&case, *node_id)?;
    let bootstrap = field!(&report, "bootstrap");
    assert_eq!(field!(&report, "case_scope"), "current_case");
    assert_eq!(field!(bootstrap, "validation_basis"), "discovery_only");
    assert_eq!(field!(bootstrap, "discovery_samples"), &json!([run]));
    assert_eq!(field!(bootstrap, "holdout_samples"), &json!([]));
    assert!(report.get("case_collection_complete").is_none());
    assert!(report.get("reconstruction_complete").is_none());
    assert!(
        field!(bootstrap, "hypotheses")
            .as_array()
            .is_some_and(|hypotheses| hypotheses.contains(&json!({"kind":"delimiter","byte":124})))
    );
    let execution = bootstrap_framing_with_execution_plan(
        &[ByteRunSample {
            sample: run,
            context: Some(MessageContext {
                source,
                scope: serde_json::to_string(&json!({"interface":"scope-a","link_type":1}))?,
                session: episode_for_run(&case, run)?,
                direction: Direction::FirstToSecond,
            }),
            bytes: b"one|two|",
        }],
        ProtocolLimits::default(),
    )?;
    assert_scheduled_survivors(
        &case,
        &outcome,
        run,
        *node_id,
        &execution.execution_plan.surviving_hypotheses,
        &plan.framings,
    )
}

fn assert_scheduled_survivors(
    case: &Case,
    outcome: &super::RecoveryExecutionOutcome,
    input_node: u64,
    report_node: u64,
    surviving_rules: &[FramingKind],
    caller_rules: &[FramingKind],
) -> Result<(), Box<dyn Error>> {
    let materializations = outcome
        .candidates
        .iter()
        .filter(|candidate| {
            matches!(candidate.task(), RecoveryTask::MaterializeFraming(_))
                && candidate
                    .inputs()
                    .iter()
                    .any(|input| input.origin_node_ids() == [input_node])
        })
        .collect::<Vec<_>>();
    let actual_rules = materializations
        .iter()
        .filter_map(|candidate| match candidate.task() {
            RecoveryTask::MaterializeFraming(rule) => Some(serde_json::to_string(rule)),
            _ => None,
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let expected_rules = surviving_rules
        .iter()
        .chain(caller_rules)
        .map(serde_json::to_string)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    assert_eq!(actual_rules, expected_rules);
    for candidate in materializations {
        let RecoveryCandidateState::Finished {
            result:
                RecoveryResult::Derived {
                    evidence_node_id: receipt_id,
                },
            ..
        } = candidate.state()
        else {
            return Err("automatically scheduled framing did not retain a receipt".into());
        };
        let receipt = case
            .nodes()
            .iter()
            .find(|node| node.id == *receipt_id)
            .ok_or("framing receipt node is missing")?;
        let (rule, basis_kind) = match candidate.task() {
            RecoveryTask::MaterializeFraming(rule) => (
                rule,
                if caller_rules.contains(rule) {
                    "caller_and_discovered"
                } else {
                    "discovered"
                },
            ),
            _ => return Err("scheduled framing candidate has an unexpected task".into()),
        };
        assert_eq!(
            field!(&receipt.details, "framing_rule"),
            &serde_json::to_value(rule)?
        );
        assert_eq!(
            field!(&receipt.details, "selection_basis"),
            &json!({"kind":basis_kind,"report_node":report_node})
        );
        assert!(case.edges().iter().any(|edge| {
            edge.from == report_node
                && edge.to == *receipt_id
                && edge.relation == "framing_rule_selected_from"
        }));
        assert!(
            !candidate
                .inputs()
                .iter()
                .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
                .any(|origin| *origin == report_node)
        );
    }
    Ok(())
}

#[test]
fn multiple_sessions_are_held_out_as_complete_groups() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "sessions")?;
    let second_session_first = add_tcp_run(&mut case, &source, "scope-a", 20, 0, 0, b"red|blue|")?;
    let second_session_second = add_tcp_run(&mut case, &source, "scope-a", 20, 1, 0, b"sun|day|")?;
    let first_session_first = add_tcp_run(&mut case, &source, "scope-a", 10, 0, 0, b"one|two|")?;
    let first_session_second = add_tcp_run(&mut case, &source, "scope-a", 10, 1, 0, b"up|down|")?;
    let first_episode = episode_for_run(&case, first_session_first)?;
    let second_episode = episode_for_run(&case, second_session_first)?;
    let expected_input_order = vec![first_session_first, second_session_first];

    let execution_policy = framing_policy(&case)?;
    let forward_total = b"one|two|".len() + b"red|blue|".len();
    assert!(forward_total > b"red|blue|".len());
    assert!(
        execution_policy
            .resources
            .max_total_input_bytes_per_candidate
            >= forward_total
    );
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let candidate = discovery_candidate(&outcome, &expected_input_order)?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = candidate.state()
    else {
        return Err("multi-session discovery did not retain a hypothesis report".into());
    };
    let report = decode_report(&case, *node_id)?;
    let bootstrap = field!(&report, "bootstrap");
    let input_runs = field!(&report, "input_runs");
    assert_eq!(field!(bootstrap, "validation_basis"), "held_out_runs");
    assert_eq!(
        field!(bootstrap, "discovery_samples"),
        &json!([first_session_first])
    );
    assert_eq!(
        field!(bootstrap, "holdout_samples"),
        &json!([second_session_first])
    );
    assert_eq!(
        field!(field!(item!(input_runs, 0), "context"), "session"),
        first_episode
    );
    assert_eq!(
        field!(field!(item!(input_runs, 1), "context"), "session"),
        second_episode
    );
    assert_eq!(
        field!(field!(&report, "cohort"), "direction"),
        "first_to_second"
    );

    let reverse = discovery_candidate(&outcome, &[first_session_second, second_session_second])?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = reverse.state()
    else {
        return Err("reverse-direction discovery did not retain a hypothesis report".into());
    };
    let reverse_report = decode_report(&case, *node_id)?;
    let reverse_bootstrap = field!(&reverse_report, "bootstrap");
    assert_eq!(
        field!(field!(&reverse_report, "cohort"), "direction"),
        "second_to_first"
    );
    assert_eq!(
        field!(reverse_bootstrap, "validation_basis"),
        "held_out_runs"
    );
    assert_eq!(
        field!(reverse_bootstrap, "discovery_samples"),
        &json!([first_session_second])
    );
    assert_eq!(
        field!(reverse_bootstrap, "holdout_samples"),
        &json!([second_session_second])
    );
    Ok(())
}

#[test]
fn duplicate_packet_labels_keep_sessions_separate() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "duplicate-packet-label")?;
    let first = add_tcp_run(&mut case, &source, "scope-a", 10, 0, 0, b"one|two|")?;
    let second = add_tcp_run(&mut case, &source, "scope-a", 10, 0, 100, b"red|blue|")?;
    let first_episode = episode_for_run(&case, first)?;
    let second_episode = episode_for_run(&case, second)?;
    assert_ne!(first_episode, second_episode);

    let execution_policy = framing_policy(&case)?;
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;
    let report = discovery_report_for(&outcome, &case, &[first, second])?;
    let bootstrap = field!(&report, "bootstrap");

    assert_eq!(field!(bootstrap, "validation_basis"), "held_out_runs");
    assert_eq!(field!(bootstrap, "discovery_samples"), &json!([first]));
    assert_eq!(field!(bootstrap, "holdout_samples"), &json!([second]));
    assert_eq!(
        field!(
            field!(item!(field!(&report, "input_runs"), 0), "context"),
            "session"
        ),
        first_episode
    );
    assert_eq!(
        field!(
            field!(item!(field!(&report, "input_runs"), 1), "context"),
            "session"
        ),
        second_episode
    );
    Ok(())
}

#[test]
fn separate_capture_sources_get_separate_discovery_cohorts() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let first_source = capture(&mut case, "first")?;
    let second_source = capture(&mut case, "second")?;
    let first_run = add_tcp_run(&mut case, &first_source, "scope-a", 1, 0, 0, b"one|two|")?;
    let second_run = add_tcp_run(&mut case, &second_source, "scope-a", 1, 0, 0, b"red|blue|")?;

    let execution_policy = framing_policy(&case)?;
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let discovery = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::FramingDiscovery)
        .collect::<Vec<_>>();
    assert_eq!(discovery.len(), 2);
    assert!(discovery.iter().any(|candidate| {
        candidate
            .inputs()
            .iter()
            .any(|input| input.origin_node_ids() == [first_run])
    }));
    assert!(discovery.iter().any(|candidate| {
        candidate
            .inputs()
            .iter()
            .any(|input| input.origin_node_ids() == [second_run])
    }));
    for candidate in discovery {
        let RecoveryCandidateState::Finished {
            result: RecoveryResult::Hypothesis { node_id },
            ..
        } = candidate.state()
        else {
            return Err("separate source discovery did not retain a hypothesis report".into());
        };
        let report = decode_report(&case, *node_id)?;
        assert_eq!(
            field!(&report, "input_runs").as_array().map(Vec::len),
            Some(1)
        );
    }
    Ok(())
}

#[test]
fn report_preserves_hypothesis_episode_ancestry_with_node_ids() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "hypothesis-ancestry")?;
    let coverage = json!({
        "length":8,
        "observed":8,
        "missing":0,
        "conflicting":0,
        "omitted":0,
        "omitted_observations":0
    });
    let direction = add_tcp_direction(
        &mut case,
        TcpDirectionFixture {
            scope_name: "scope-a",
            first_packet: 1,
            direction_index: 0,
            coverage: &coverage,
            state: TcpRunState::Complete,
            parent_status: EvidenceStatus::Hypothesis,
        },
    )?;
    let episode = case
        .nodes()
        .iter()
        .find(|node| node.kind == "tcp_episode")
        .map(|node| node.id)
        .ok_or("episode fixture was not created")?;
    let run = add_tcp_run_to_direction(
        &mut case,
        TcpRunNodeFixture {
            source: &source,
            first_packet: 1,
            direction,
            stream_offset: 0,
            bytes: b"one|two|",
            boundaries: BoundaryState::Complete,
            generation_ambiguous: false,
            edge_status: EvidenceStatus::Observed,
        },
    )?;
    let mut policy = framing_policy(&case)?;
    disable_root_expansion(&mut policy);

    let outcome = execute(&mut case, &framing_plan(), &policy)?;
    let report = discovery_report_for(&outcome, &case, &[run])?;
    let ancestry = field!(item!(field!(&report, "input_runs"), 0), "ancestry");

    assert_eq!(field!(ancestry, "direction_node_id"), direction);
    assert_eq!(field!(ancestry, "direction_contains_status"), "observed");
    assert_eq!(field!(ancestry, "episode_node_id"), episode);
    assert_eq!(field!(ancestry, "episode_contains_status"), "hypothesis");
    Ok(())
}

#[test]
fn unrelated_non_tcp_evidence_does_not_change_cohort_report() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "stable-cohort")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
    let first_policy = framing_policy(&case)?;
    let first_outcome = execute(&mut case, &framing_plan(), &first_policy)?;
    let first_report = discovery_report_for(&first_outcome, &case, &[run])?;

    case.add_bytes_node(
        "unrelated_evidence",
        b"other protocol bytes",
        Vec::new(),
        json!({}),
    )?;
    let second_policy = framing_policy(&case)?;
    let second_outcome = execute(&mut case, &framing_plan(), &second_policy)?;
    let second_report = discovery_report_for(&second_outcome, &case, &[run])?;

    assert_eq!(first_report, second_report);
    Ok(())
}

#[test]
fn new_same_cohort_run_requires_a_fresh_plan_and_updates_the_generation()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "cohort-generation")?;
    let first_run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
    let cached_policy = framing_policy(&case)?;
    let first_outcome = execute(&mut case, &framing_plan(), &cached_policy)?;
    let first_report = discovery_report_for(&first_outcome, &case, &[first_run])?;

    let second_run = add_tcp_run(&mut case, &source, "scope-a", 2, 0, 0, b"red|blue|")?;
    assert!(matches!(
        execute(&mut case, &framing_plan(), &cached_policy),
        Err(super::RecoveryExecutionError::InvalidPolicy(_))
    ));

    let fresh_policy = framing_policy(&case)?;
    let second_outcome = execute(&mut case, &framing_plan(), &fresh_policy)?;
    let second_report = discovery_report_for(&second_outcome, &case, &[first_run, second_run])?;
    assert_ne!(first_report, second_report);
    assert_eq!(
        field!(&second_report, "input_runs")
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        field!(field!(&second_report, "bootstrap"), "validation_basis"),
        "held_out_runs"
    );
    Ok(())
}

#[test]
fn all_omitted_runs_still_charge_case_scan_work_and_report_input_omissions()
-> Result<(), Box<dyn Error>> {
    let mut scan_case = unresolved_tcp_case()?;
    let mut baseline_case = unresolved_tcp_case()?;
    let scan_policy = framing_policy(&scan_case)?;
    let baseline_policy = framing_policy(&baseline_case)?;
    let scan = execute(&mut scan_case, &framing_plan(), &scan_policy)?;
    let baseline = execute(
        &mut baseline_case,
        &RecoveryPlan::default(),
        &baseline_policy,
    )?;

    assert!(!scan.complete);
    assert!(scan.resources.work_charged_bytes > baseline.resources.work_charged_bytes);
    assert!(
        scan.candidates
            .iter()
            .all(|candidate| { candidate.task() != &RecoveryTask::FramingDiscovery })
    );
    assert_eq!(
        scan.omissions
            .iter()
            .filter(|omission| matches!(
                omission,
                super::RecoveryOmission::FramingDiscoveryInputs { .. }
            ))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn case_scan_charges_detail_bytes() -> Result<(), Box<dyn Error>> {
    fn run_with_padding(length: usize) -> Result<usize, Box<dyn Error>> {
        let mut case = Case::new();
        let source = capture(&mut case, "detail-work")?;
        add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
        case.add_node(
            "unrelated_evidence",
            None,
            Vec::new(),
            json!({"padding":"x".repeat(length)}),
        )?;
        let execution_policy = framing_policy(&case)?;
        let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;
        Ok(outcome.resources.work_charged_bytes)
    }

    let small = run_with_padding(8)?;
    let large = run_with_padding(2_048)?;
    assert!(large > small);
    Ok(())
}

#[test]
fn case_scan_charges_irrelevant_edge_work() -> Result<(), Box<dyn Error>> {
    fn run_with_edges(edge_count: usize) -> Result<(usize, Value), Box<dyn Error>> {
        let (mut case, run) = framing_case_with_irrelevant_edges(edge_count)?;
        let execution_policy = framing_policy(&case)?;
        let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;
        let report = discovery_report_for(&outcome, &case, &[run])?;
        Ok((outcome.resources.work_charged_bytes, report))
    }

    let (small_work, small_report) = run_with_edges(0)?;
    let (large_work, large_report) = run_with_edges(128)?;

    assert_eq!(small_report, large_report);
    assert!(large_work > small_work);
    Ok(())
}

#[test]
fn edge_heavy_case_scan_exhaustion_retains_no_report() -> Result<(), Box<dyn Error>> {
    let (mut baseline_case, baseline_run) = framing_case_with_irrelevant_edges(0)?;
    let baseline_policy = framing_policy(&baseline_case)?;
    let baseline = execute(&mut baseline_case, &framing_plan(), &baseline_policy)?;
    let _ = discovery_report_for(&baseline, &baseline_case, &[baseline_run])?;
    let work_limit = baseline.resources.work_charged_bytes / 2;
    let edge_work = IRRELEVANT_EDGE_RELATION
        .len()
        .checked_add(MAX_REASON_BYTES)
        .and_then(|work| work.checked_add(3 * std::mem::size_of::<u64>()))
        .ok_or("edge work calculation overflowed")?;
    let edge_count = work_limit
        .checked_div(edge_work)
        .and_then(|count| count.checked_add(1))
        .ok_or("edge padding count overflowed")?;
    let (mut bounded_case, bounded_run) = framing_case_with_irrelevant_edges(edge_count)?;
    assert_eq!(baseline_run, bounded_run);
    assert!(bounded_case.edges().len() <= MAX_EDGES);

    let mut bounded_policy = framing_policy(&bounded_case)?;
    bounded_policy.resources.max_work_bytes = work_limit;
    let outcome = execute(&mut bounded_case, &framing_plan(), &bounded_policy)?;

    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            limit,
            used: 0,
            requested,
            ..
        } if *limit == work_limit && *requested > work_limit
    )));
    assert!(
        outcome
            .candidates
            .iter()
            .all(|candidate| { candidate.task() != &RecoveryTask::FramingDiscovery })
    );
    assert!(
        bounded_case
            .nodes()
            .iter()
            .all(|node| node.kind != "recovery_framing_discovery_report")
    );
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn report_node_quota_exhaustion_keeps_completed_search_and_rolls_back() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let source = capture(&mut case, "framing-report-node-quota")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
    fill_case_nodes_to_quota(&mut case)?;
    let before = case.try_clone()?;
    let mut policy = framing_policy(&case)?;
    disable_root_expansion(&mut policy);

    let outcome = execute(&mut case, &framing_plan(), &policy)?;

    assert_eq!(
        &case, &before,
        "failed report retention must roll back atomically"
    );
    let candidate = discovery_candidate(&outcome, &[run])?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceNodes,
                limit: l2_workbench::evidence::MAX_NODES,
                used: l2_workbench::evidence::MAX_NODES,
                requested: 1,
            },
            ..
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceNodes,
            limit: l2_workbench::evidence::MAX_NODES,
            used: l2_workbench::evidence::MAX_NODES,
            requested: 1,
            ..
        }
    )));
    assert!(super::discovery_input_coverage_complete(&outcome.omissions));
    assert!(super::search_exhaustive_within_plan(&outcome.omissions));
    assert!(!super::report_details_complete(&outcome.omissions));
    assert!(case.collection_complete());
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn report_edge_quota_exhaustion_keeps_completed_search_and_rolls_back() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let source = capture(&mut case, "framing-report-edge-quota")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"one|two|")?;
    fill_case_edges_to_quota(&mut case)?;
    let before = case.try_clone()?;
    let mut policy = framing_policy(&case)?;
    disable_root_expansion(&mut policy);

    let outcome = execute(&mut case, &framing_plan(), &policy)?;

    assert_eq!(
        &case, &before,
        "failed report retention must roll back atomically"
    );
    let candidate = discovery_candidate(&outcome, &[run])?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
                limit: MAX_EDGES,
                used: MAX_EDGES,
                requested: 1,
            },
            ..
        }
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceEdges,
            limit: MAX_EDGES,
            used: MAX_EDGES,
            requested: 1,
            ..
        }
    )));
    assert!(super::discovery_input_coverage_complete(&outcome.omissions));
    assert!(super::search_exhaustive_within_plan(&outcome.omissions));
    assert!(!super::report_details_complete(&outcome.omissions));
    assert!(case.collection_complete());
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn report_blob_byte_quota_exhaustion_keeps_search_and_omits_only_report_details()
-> Result<(), Box<dyn Error>> {
    let run_bytes = b"one|two|";
    let mut case = Case::with_blob_limit(run_bytes.len())?;
    let source = capture(&mut case, "framing-report-blob-quota")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, run_bytes)?;
    assert_eq!(
        case.blobs()
            .iter()
            .map(|blob| blob.bytes.len())
            .sum::<usize>(),
        run_bytes.len()
    );
    let before_blob_count = case.blobs().len();
    let mut policy = framing_policy(&case)?;
    disable_root_expansion(&mut policy);

    let outcome = execute(&mut case, &framing_plan(), &policy)?;

    let candidate = discovery_candidate(&outcome, &[run])?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::EvidenceBlobBytes,
                limit,
                used,
                requested,
            },
            ..
        } if *limit == run_bytes.len()
            && *used == run_bytes.len()
            && *requested > run_bytes.len()
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::EvidenceBlobBytes,
            limit,
            used,
            requested,
            ..
        } if *limit == run_bytes.len()
            && *used == run_bytes.len()
            && *requested > run_bytes.len()
    )));
    assert!(
        case.nodes()
            .iter()
            .all(|node| node.kind != "recovery_framing_discovery_report"),
        "the report node and its blob roll back together"
    );
    assert_eq!(case.blobs().len(), before_blob_count);
    assert!(super::discovery_input_coverage_complete(&outcome.omissions));
    assert!(super::search_exhaustive_within_plan(&outcome.omissions));
    assert!(!super::report_details_complete(&outcome.omissions));
    Ok(())
}

#[test]
fn opposite_tcp_directions_are_discovered_in_separate_cohorts() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "asymmetric")?;
    let client_run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, b"a|b|c|d|")?;
    let server_bytes = vec![b'r'; 41 * 1024];
    let server_run = add_tcp_run(&mut case, &source, "scope-a", 1, 1, 0, &server_bytes)?;

    let execution_policy = framing_policy(&case)?;
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    for (run, expected_direction, expected_length) in [
        (client_run, "first_to_second", 8),
        (server_run, "second_to_first", server_bytes.len()),
    ] {
        let candidate = discovery_candidate(&outcome, &[run])?;
        let RecoveryCandidateState::Finished {
            result: RecoveryResult::Hypothesis { node_id },
            ..
        } = candidate.state()
        else {
            return Err("directional discovery did not retain a hypothesis report".into());
        };
        let report = decode_report(&case, *node_id)?;
        let input_runs = field!(&report, "input_runs");
        let bootstrap = field!(&report, "bootstrap");
        assert_eq!(input_runs.as_array().map(Vec::len), Some(1));
        assert_eq!(field!(item!(input_runs, 0), "byte_length"), expected_length);
        assert_eq!(
            field!(field!(&report, "cohort"), "direction"),
            expected_direction
        );
        assert_eq!(field!(bootstrap, "validation_basis"), "discovery_only");
        assert_eq!(field!(bootstrap, "discovery_samples"), &json!([run]));
        assert_eq!(field!(bootstrap, "holdout_samples"), &json!([]));
    }
    Ok(())
}

#[test]
fn partial_tcp_boundaries_keep_their_completeness_in_framing_discovery()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "partial-boundaries")?;
    let run = add_tcp_run_with_state(
        &mut case,
        TcpRunFixture {
            source: &source,
            scope_name: "scope-a",
            first_packet: 1,
            direction_index: 0,
            stream_offset: 0,
            bytes: b"one|two|",
            state: TcpRunState::IncompleteBoundaries,
        },
    )?;
    let execution_policy = framing_policy(&case)?;

    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let report = discovery_report_for(&outcome, &case, &[run])?;
    let input = item!(field!(&report, "input_runs"), 0);
    let bootstrap = field!(&report, "bootstrap");
    assert_eq!(field!(input, "start_known"), false);
    assert_eq!(field!(input, "end_observed"), false);
    assert_eq!(field!(bootstrap, "discovery_samples"), &json!([run]));
    assert_eq!(field!(bootstrap, "holdout_samples"), &json!([]));
    Ok(())
}

#[test]
fn sequence_and_generation_ambiguity_remain_excluded_from_framing_discovery()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "ambiguous-directions")?;
    let sequence_ambiguous = add_tcp_run_with_state(
        &mut case,
        TcpRunFixture {
            source: &source,
            scope_name: "scope-a",
            first_packet: 1,
            direction_index: 0,
            stream_offset: 0,
            bytes: b"sequence|",
            state: TcpRunState::SequenceAmbiguous,
        },
    )?;
    let generation_ambiguous = add_tcp_run_with_state(
        &mut case,
        TcpRunFixture {
            source: &source,
            scope_name: "scope-a",
            first_packet: 2,
            direction_index: 0,
            stream_offset: 0,
            bytes: b"generation|",
            state: TcpRunState::GenerationAmbiguous,
        },
    )?;
    let execution_policy = framing_policy(&case)?;

    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    assert!(outcome.candidates.iter().all(|candidate| {
        let framing_task = candidate.task() == &RecoveryTask::FramingDiscovery
            || matches!(candidate.task(), RecoveryTask::MaterializeFraming(_));
        !framing_task
            || candidate
                .inputs()
                .iter()
                .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
                .all(|origin| *origin != sequence_ambiguous && *origin != generation_ambiguous)
    }));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some(omitted_source),
            omitted_runs: 2,
            reason_counts,
        } if omitted_source == &source
            && reason_counts.get("invalid_context") == Some(&1)
            && reason_counts.get("generation_ambiguous") == Some(&1)
    )));
    Ok(())
}

#[test]
fn separated_tcp_runs_are_discovered_independently_across_direction_gaps()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "gapped-direction")?;
    let coverage = json!({
        "length":8,
        "observed":6,
        "missing":2,
        "conflicting":0,
        "omitted":0,
        "omitted_observations":0
    });
    let direction = add_tcp_direction(
        &mut case,
        TcpDirectionFixture {
            scope_name: "scope-a",
            first_packet: 1,
            direction_index: 0,
            coverage: &coverage,
            state: TcpRunState::Complete,
            parent_status: EvidenceStatus::Observed,
        },
    )?;
    let first = add_tcp_run_to_direction(
        &mut case,
        TcpRunNodeFixture {
            source: &source,
            first_packet: 1,
            direction,
            stream_offset: 0,
            bytes: b"one",
            boundaries: BoundaryState::EndUnobserved,
            generation_ambiguous: false,
            edge_status: EvidenceStatus::Observed,
        },
    )?;
    let second = add_tcp_run_to_direction(
        &mut case,
        TcpRunNodeFixture {
            source: &source,
            first_packet: 1,
            direction,
            stream_offset: 5,
            bytes: b"two",
            boundaries: BoundaryState::StartUnknown,
            generation_ambiguous: false,
            edge_status: EvidenceStatus::Observed,
        },
    )?;
    let execution_policy = framing_policy(&case)?;

    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let report = discovery_report_for(&outcome, &case, &[first, second])?;
    let inputs = field!(&report, "input_runs");
    assert_eq!(inputs.as_array().map(Vec::len), Some(2));
    assert_eq!(field!(item!(inputs, 0), "node_id"), first);
    assert_eq!(field!(item!(inputs, 0), "stream_offset"), 0);
    assert_eq!(field!(item!(inputs, 0), "byte_length"), 3);
    assert_eq!(field!(item!(inputs, 0), "start_known"), true);
    assert_eq!(field!(item!(inputs, 0), "end_observed"), false);
    assert_eq!(field!(item!(inputs, 1), "node_id"), second);
    assert_eq!(field!(item!(inputs, 1), "stream_offset"), 5);
    assert_eq!(field!(item!(inputs, 1), "byte_length"), 3);
    assert_eq!(field!(item!(inputs, 1), "start_known"), false);
    assert_eq!(field!(item!(inputs, 1), "end_observed"), true);
    assert_eq!(
        field!(field!(&report, "bootstrap"), "discovery_samples"),
        &json!([first, second])
    );
    assert_materialized_frames_respect_run_boundaries(
        &case,
        &source,
        &[first, second],
        (10_003, 10_005),
    )?;
    Ok(())
}

#[test]
fn boundary_preview_omission_keeps_search_result() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "partial")?;
    let bytes = vec![b'x'; 8_192];
    let run = add_tcp_run(&mut case, &source, "scope-a", 1, 0, 0, &bytes)?;
    let execution_policy = framing_policy(&case)?;

    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    assert!(!outcome.complete);
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryAnalysis {
            source_id: omitted_source,
            search_exhaustive_within_plan: true,
            report_details_complete: false,
            detail_incomplete_runs: 1,
            ..
        } if omitted_source == &source
    )));
    let candidate = discovery_candidate(&outcome, &[run])?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = candidate.state()
    else {
        return Err("framing discovery did not retain its bounded report".into());
    };
    let report = decode_report(&case, *node_id)?;
    let bootstrap = field!(&report, "bootstrap");
    assert_eq!(field!(bootstrap, "search_exhaustive_within_plan"), true);
    assert_eq!(field!(bootstrap, "report_details_complete"), false);
    Ok(())
}

#[test]
fn discovery_order_is_deterministic_and_reports_unresolved_inputs() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "ordered")?;
    let later = add_tcp_run(&mut case, &source, "scope-a", 30, 0, 0, b"late|run|")?;
    let earlier = add_tcp_run(&mut case, &source, "scope-a", 10, 0, 0, b"early|run|")?;
    let (_orphan, _mixed) = add_unresolved_tcp_runs(&mut case, &source)?;

    let execution_policy = framing_policy(&case)?;
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let candidate = discovery_candidate(&outcome, &[earlier, later])?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = candidate.state()
    else {
        return Err("ordered discovery did not retain a hypothesis report".into());
    };
    let report = decode_report(&case, *node_id)?;
    assert_eq!(
        item!(field!(&report, "input_runs"), 0).get("node_id"),
        Some(&json!(earlier))
    );
    assert_eq!(
        item!(field!(&report, "input_runs"), 1).get("node_id"),
        Some(&json!(later))
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some(omitted_source),
            omitted_runs: 1,
            reason_counts,
        } if omitted_source == &source && reason_counts.get("missing_context") == Some(&1)
    )));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryInputs {
            source_id: None,
            omitted_runs: 1,
            reason_counts,
        }
            if reason_counts.get("mixed_source") == Some(&1)
    )));
    assert_eq!(
        outcome
            .omissions
            .iter()
            .filter(|omission| matches!(
                omission,
                super::RecoveryOmission::FramingDiscoveryInputs { .. }
            ))
            .count(),
        2
    );
    assert!(!outcome.complete);
    Ok(())
}

#[test]
fn multiple_episode_parents_are_ambiguous() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "ambiguous-episode")?;
    let run = add_tcp_run(&mut case, &source, "scope-a", 10, 0, 0, b"one|two|")?;
    let direction = direction_for_run(&case, run)?;
    let second_episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"scope-b","link_type":1},
            "endpoints":[
                {"address":"endpoint-a","port":1000},
                {"address":"endpoint-b","port":2000}
            ],
            "first_packet":20,
            "generation_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: second_episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Conflicting synthetic episode parent".to_owned(),
    })?;

    let execution_policy = framing_policy(&case)?;
    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some(omitted_source),
            omitted_runs: 1,
            reason_counts,
        } if omitted_source == &source && reason_counts.get("ambiguous_context") == Some(&1)
    )));
    Ok(())
}

#[test]
fn hypothesis_episode_ancestry_accepts_only_observed_run_links() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "unobserved-context-edges")?;
    let runs = add_context_status_runs(&mut case, &source)?;
    let accepted_run = *runs.first().ok_or("edge case fixture has no TCP runs")?;
    let execution_policy = framing_policy(&case)?;

    let outcome = execute(&mut case, &framing_plan(), &execution_policy)?;

    let framing_origins = framing_candidate_origins(&outcome);
    assert!(framing_origins.contains(&accepted_run));
    assert!(framing_origins.iter().all(|origin| *origin == accepted_run));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::FramingDiscoveryInputs {
            source_id: Some(omitted_source),
            omitted_runs: 3,
            reason_counts,
        } if omitted_source == &source && reason_counts.get("invalid_context") == Some(&3)
    )));
    Ok(())
}

fn add_context_status_runs(case: &mut Case, source: &str) -> Result<Vec<u64>, Box<dyn Error>> {
    let coverage = json!({
        "length":4,
        "observed":4,
        "missing":0,
        "conflicting":0,
        "omitted":0,
        "omitted_observations":0
    });
    let edge_cases = [
        (1, EvidenceStatus::Hypothesis, EvidenceStatus::Observed),
        (2, EvidenceStatus::Unresolved, EvidenceStatus::Observed),
        (3, EvidenceStatus::Observed, EvidenceStatus::Hypothesis),
        (4, EvidenceStatus::Observed, EvidenceStatus::Unresolved),
    ];
    let mut runs = Vec::new();
    for (first_packet, episode_status, direction_status) in edge_cases {
        let direction = add_tcp_direction(
            case,
            TcpDirectionFixture {
                scope_name: "scope-a",
                first_packet,
                direction_index: 0,
                coverage: &coverage,
                state: TcpRunState::Complete,
                parent_status: episode_status,
            },
        )?;
        runs.push(add_tcp_run_to_direction(
            case,
            TcpRunNodeFixture {
                source,
                first_packet,
                direction,
                stream_offset: 0,
                bytes: b"run|",
                boundaries: BoundaryState::Complete,
                generation_ambiguous: false,
                edge_status: direction_status,
            },
        )?);
    }
    Ok(runs)
}

fn framing_candidate_origins(outcome: &super::RecoveryExecutionOutcome) -> Vec<u64> {
    outcome
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.task() == &RecoveryTask::FramingDiscovery
                || matches!(candidate.task(), RecoveryTask::MaterializeFraming(_))
        })
        .flat_map(|candidate| {
            candidate
                .inputs()
                .iter()
                .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
                .copied()
        })
        .collect::<Vec<_>>()
}

#[test]
fn compact_framing_receipt_keeps_cohort_and_omission_counts() -> Result<(), Box<dyn Error>> {
    let (full_report, bootstrap) = bounded_report_fixture()?;
    let full_length = serde_json::to_vec(&full_report)?.len();
    let (bytes, truncated) = super::framing_discovery::bounded_report_bytes(
        &full_report,
        Some(&bootstrap),
        full_length - 1,
    )?;
    let compact: Value = serde_json::from_slice(&bytes)?;
    let expected_cohort = full_report.get("cohort").ok_or("cohort is missing")?;
    assert!(truncated);
    assert_eq!(compact.get("cohort"), Some(expected_cohort));
    assert_eq!(field!(&compact, "input_run_details_omitted"), 1);
    assert_eq!(
        field!(field!(&compact, "bootstrap_summary"), "hypotheses_omitted"),
        bootstrap.hypotheses.len()
    );
    assert_eq!(
        field!(
            field!(&compact, "bootstrap_summary"),
            "boundary_details_omitted"
        ),
        bootstrap.discovery.len() + bootstrap.holdout.len()
    );
    assert_eq!(
        field!(field!(&compact, "bootstrap_summary"), "sample_ids_omitted"),
        bootstrap.discovery_samples.len() + bootstrap.holdout_samples.len()
    );
    assert_eq!(
        field!(field!(&compact, "bootstrap_summary"), "limitations_omitted"),
        bootstrap.limitations.len()
    );
    assert_eq!(
        field!(field!(&compact, "bootstrap_summary"), "prefix_offset_limit"),
        bootstrap.prefix_offset_limit
    );
    Ok(())
}

#[test]
fn minimal_framing_receipt_keeps_cohort_and_marks_dropped_field_classes()
-> Result<(), Box<dyn Error>> {
    let (full_report, bootstrap) = bounded_report_fixture()?;
    let full_length = serde_json::to_vec(&full_report)?.len();
    let (compact_bytes, _) = super::framing_discovery::bounded_report_bytes(
        &full_report,
        Some(&bootstrap),
        full_length - 1,
    )?;
    let maximum = compact_bytes.len() - 1;
    let (minimal_bytes, truncated) =
        super::framing_discovery::bounded_report_bytes(&full_report, Some(&bootstrap), maximum)?;
    let minimal: Value = serde_json::from_slice(&minimal_bytes)?;
    let expected_cohort = full_report.get("cohort").ok_or("cohort is missing")?;
    assert!(truncated);
    assert!(minimal_bytes.len() <= maximum);
    assert_eq!(minimal.get("cohort"), Some(expected_cohort));
    assert_eq!(field!(&minimal, "protocol_limits_omitted"), true);
    assert_eq!(field!(&minimal, "bootstrap_details_omitted"), true);
    assert_eq!(
        field!(&minimal, "bootstrap_hypotheses_omitted"),
        bootstrap.hypotheses.len()
    );
    assert_eq!(
        field!(&minimal, "bootstrap_run_details_omitted"),
        bootstrap.discovery.len() + bootstrap.holdout.len()
    );
    assert_eq!(
        field!(&minimal, "bootstrap_sample_ids_omitted"),
        bootstrap.discovery_samples.len() + bootstrap.holdout_samples.len()
    );
    assert_eq!(
        field!(&minimal, "bootstrap_limitations_omitted"),
        bootstrap.limitations.len()
    );
    assert_eq!(
        field!(&minimal, "bootstrap_prefix_offset_limit_omitted"),
        true
    );
    assert_eq!(field!(&minimal, "input_run_details_omitted"), 1);
    assert_eq!(field!(&minimal, "work_bound_bytes"), 33);
    Ok(())
}

#[test]
fn default_recovery_uses_typed_framing_survivors_when_report_details_are_compact()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture_with_size(&mut case, "compact-automatic-framing", 50_000_000)?;
    let mut input_runs = Vec::new();
    input_runs.try_reserve_exact(ProtocolLimits::default().max_samples)?;
    for packet in 1..=u32::try_from(ProtocolLimits::default().max_samples)? {
        input_runs.push(add_tcp_run(
            &mut case,
            &source,
            "scope-a",
            packet,
            0,
            0,
            b"one|two|",
        )?);
    }

    super::recover_case(&mut case)?;

    let report_node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "recovery_framing_discovery_report")
        .ok_or("default recovery did not retain a framing report")?;
    let report = decode_report(&case, report_node.id)?;
    assert_eq!(field!(&report, "report_truncated"), true);
    assert_eq!(
        field!(&report, "input_run_details_omitted"),
        input_runs.len()
    );
    assert!(report.get("bootstrap").is_none());

    let expected_rule = json!({"kind":"delimiter","byte":b'|'});
    let expected_basis = json!({"kind":"discovered","report_node":report_node.id});
    let receipt = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_framing_receipt"
                && node.details.get("framing_rule") == Some(&expected_rule)
                && node.details.get("selection_basis") == Some(&expected_basis)
        })
        .ok_or("compact discovery did not produce a discovered-basis delimiter receipt")?;
    let input_node = field!(&receipt.details, "input_node")
        .as_u64()
        .ok_or("framing receipt has no input node")?;
    assert!(input_runs.contains(&input_node));
    assert!(case.edges().iter().any(|edge| {
        edge.from == report_node.id
            && edge.to == receipt.id
            && edge.relation == "framing_rule_selected_from"
    }));
    assert!(case.nodes().iter().any(|node| {
        node.kind == "custom_protocol_frame"
            && node.details.get("input_node") == Some(&json!(input_node))
            && case.edges().iter().any(|edge| {
                edge.from == receipt.id && edge.to == node.id && edge.relation == "materialized"
            })
    }));
    Ok(())
}

#[path = "recovery_framing_cohort_transitions.rs"]
mod cohort_transitions;
