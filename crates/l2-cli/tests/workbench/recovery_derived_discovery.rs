use super::{RecoveryPlan, execute, policy, source};
use crate::workbench::recovery_executor::RecoveryExecutionOutcome;
use l2_workbench::{
    derivation::{Base64Alphabet, Base64Padding, Operation, Recipe},
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, Node, SourceRange},
    protocol::FramingKind,
    recovery::{RecoveryCandidate, RecoveryCandidateState, RecoveryResult, RecoveryTask},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

type TestResult<T> = Result<T, Box<dyn Error>>;

const DERIVED_TEST_WORK_BYTES: usize = 128 * 1024 * 1024;
const DERIVED_TEST_MAX_DEPTH: usize = 4;

struct TcpContext {
    source_id: String,
    episode: u64,
    direction: u64,
    run: u64,
    start_known: bool,
    end_observed: bool,
    plaintext: Vec<u8>,
    records: Vec<Vec<u8>>,
}

struct MergedContextCase {
    case: Case,
    imported_input: u64,
    capture_sources: [String; 2],
    contexts: [TcpContext; 4],
    encoded_streams: [Vec<u8>; 2],
}

struct MergedContextFixture {
    case: Case,
    outcome: RecoveryExecutionOutcome,
    imported_input: u64,
    capture_sources: [String; 2],
    contexts: [TcpContext; 4],
    encoded_streams: [Vec<u8>; 2],
}

struct DecodedContextViews<'a> {
    transform_indexes: [usize; 2],
    all: Vec<&'a Node>,
    tcp: Vec<&'a Node>,
}

struct SourceRecordExpectation<'a> {
    source_id: &'a str,
    sessions: &'a [TcpContext],
    transform_indexes: &'a [usize],
    max_depth: usize,
}

#[test]
fn rejected_automatic_compression_proposals_do_not_omit_record_inputs() -> TestResult<()> {
    let headers: &[(&[u8], Operation)] = &[
        (
            &[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 3],
            Operation::GzipDecompress {},
        ),
        (&[0x78, 0x9c], Operation::ZlibDecompress {}),
    ];
    let plan = RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    };
    for (input, operation) in headers {
        for tcp_context in [false, true] {
            let mut case = Case::new();
            let input_node = if tcp_context {
                let capture = add_capture(&mut case, "rejected-compression")?;
                add_tcp_context(&mut case, &capture, 1, input, &[], &[])?.run
            } else {
                source(&mut case, "http_body", input)?
            };

            let outcome = execute(&mut case, &plan, &policy())?;

            // A valid header admits a decoder without promising a valid compressed body
            assert!(outcome.candidates.iter().any(|candidate| {
                matches!(candidate.task(), RecoveryTask::Transform(recipe)
                    if recipe.steps.as_slice() == std::slice::from_ref(operation))
                    && candidate
                        .inputs()
                        .iter()
                        .any(|input| input.origin_node_ids().contains(&input_node))
                    && matches!(
                        candidate.state(),
                        RecoveryCandidateState::Finished {
                            result: RecoveryResult::Rejected { .. },
                            ..
                        }
                    )
            }));
            assert!(
                outcome.omissions.is_empty(),
                "a rejected speculative decoder is not an omitted record input: {:?}",
                outcome.omissions
            );
            assert!(outcome.complete);
        }
    }
    Ok(())
}

#[test]
fn automatic_discovery_keeps_merged_transform_contexts_and_schedules_derived_records()
-> TestResult<()> {
    let fixture = execute_merged_context_fixture(build_merged_context_case()?)?;
    let views = assert_merged_transform_views(&fixture)?;
    let derived_frames = assert_derived_transport_and_frames(&fixture, &views)?;
    assert_source_record_generation(&fixture, &views, &derived_frames)?;
    Ok(())
}

fn build_merged_context_case() -> TestResult<MergedContextCase> {
    let (first_plaintext, first_records) = delimited_records([0xa5, 0xb6]);
    let (second_plaintext, second_records) = delimited_records([0xc7, 0xd8]);
    let encoded_streams = [
        base64_encode(&first_plaintext),
        base64_encode(&second_plaintext),
    ];
    let mut case = Case::new();
    let imported_input = source(&mut case, "imported_source", &encoded_streams[0])?;
    let first_source = add_capture(&mut case, "first-capture")?;
    let second_source = add_capture(&mut case, "second-capture")?;
    let contexts = [
        add_tcp_context(
            &mut case,
            &first_source,
            1,
            &encoded_streams[0],
            &first_plaintext,
            &first_records,
        )?,
        add_tcp_context(
            &mut case,
            &first_source,
            2,
            &encoded_streams[1],
            &second_plaintext,
            &second_records,
        )?,
        add_tcp_context(
            &mut case,
            &second_source,
            1,
            &encoded_streams[0],
            &first_plaintext,
            &first_records,
        )?,
        add_tcp_context(
            &mut case,
            &second_source,
            2,
            &encoded_streams[1],
            &second_plaintext,
            &second_records,
        )?,
    ];
    assert_tcp_context_ranges(&case, &contexts)?;
    Ok(MergedContextCase {
        case,
        imported_input,
        capture_sources: [first_source, second_source],
        contexts,
        encoded_streams,
    })
}

fn assert_tcp_context_ranges(case: &Case, contexts: &[TcpContext]) -> TestResult<()> {
    for context in contexts {
        let run = case.node(context.run).ok_or("TCP run is missing")?;
        assert_eq!(
            run.ranges.first().map(|range| range.source.as_str()),
            Some(context.source_id.as_str())
        );
        assert!(case.edges().iter().any(|edge| {
            edge.from == context.episode
                && edge.to == context.direction
                && edge.relation == "contains"
        }));
        assert!(case.edges().iter().any(|edge| {
            edge.from == context.direction && edge.to == context.run && edge.relation == "contains"
        }));
    }
    Ok(())
}

fn execute_merged_context_fixture(
    mut fixture: MergedContextCase,
) -> TestResult<MergedContextFixture> {
    let execution_policy = merged_context_policy();
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let outcome = execute(&mut fixture.case, &plan, &execution_policy)?;
    assert!(outcome.candidate_count <= execution_policy.resources.max_candidates);
    assert!(outcome.resources.work_charged_bytes <= execution_policy.resources.max_work_bytes);
    Ok(MergedContextFixture {
        case: fixture.case,
        outcome,
        imported_input: fixture.imported_input,
        capture_sources: fixture.capture_sources,
        contexts: fixture.contexts,
        encoded_streams: fixture.encoded_streams,
    })
}

fn merged_context_policy() -> super::RecoveryExecutionPolicy {
    let mut execution_policy = policy();
    execution_policy.resources.max_candidates = 1024;
    execution_policy.resources.max_frontier = 1024;
    execution_policy.resources.max_inputs_per_candidate = 64;
    execution_policy.resources.max_origins_per_candidate = 64;
    execution_policy.resources.max_depth = DERIVED_TEST_MAX_DEPTH;
    execution_policy.expansion_limits.depth = DERIVED_TEST_MAX_DEPTH;
    execution_policy.resources.max_work_bytes = DERIVED_TEST_WORK_BYTES;
    execution_policy
        .transform_exploration
        .proposal_budget
        .max_candidates = 1;
    execution_policy
}

fn assert_merged_transform_views(
    fixture: &MergedContextFixture,
) -> TestResult<DecodedContextViews<'_>> {
    let first_plaintext = fixture.contexts[0].plaintext.as_slice();
    let second_plaintext = fixture.contexts[1].plaintext.as_slice();
    let first_origins = std::iter::once(fixture.imported_input)
        .chain(
            fixture
                .contexts
                .iter()
                .filter(|context| context.end_observed)
                .map(|context| context.run),
        )
        .collect::<BTreeSet<_>>();
    let second_origins = fixture
        .contexts
        .iter()
        .filter(|context| !context.end_observed)
        .map(|context| context.run)
        .collect::<BTreeSet<_>>();
    let (first_transform_index, first_receipt) = merged_base64_transform(
        &fixture.case,
        &fixture.outcome.candidates,
        &fixture.encoded_streams[0],
        first_plaintext,
        &first_origins,
    )?;
    let (second_transform_index, second_receipt) = merged_base64_transform(
        &fixture.case,
        &fixture.outcome.candidates,
        &fixture.encoded_streams[1],
        second_plaintext,
        &second_origins,
    )?;
    let first_views = contextual_outputs(
        &fixture.case,
        first_receipt,
        first_plaintext,
        &first_origins,
    )?;
    let second_views = contextual_outputs(
        &fixture.case,
        second_receipt,
        second_plaintext,
        &second_origins,
    )?;
    let all = first_views
        .iter()
        .chain(&second_views)
        .copied()
        .collect::<Vec<_>>();
    let expected_inputs = std::iter::once(fixture.imported_input)
        .chain(fixture.contexts.iter().map(|context| context.run))
        .collect::<BTreeSet<_>>();
    assert_eq!(all.len(), expected_inputs.len());
    for input_node in expected_inputs {
        assert_eq!(
            all.iter()
                .filter(|view| source_input(view) == Some(input_node))
                .count(),
            1,
            "each contextual transform generation should be retained once"
        );
    }
    let tcp = fixture
        .contexts
        .iter()
        .map(|context| contextual_view_for(&all, context.run))
        .collect::<TestResult<Vec<_>>>()?;
    Ok(DecodedContextViews {
        transform_indexes: [first_transform_index, second_transform_index],
        all,
        tcp,
    })
}

fn assert_derived_transport_and_frames<'a>(
    fixture: &'a MergedContextFixture,
    views: &DecodedContextViews<'a>,
) -> TestResult<Vec<&'a Node>> {
    let ancestry_ids = assert_transport_completeness_survives_decode(
        &fixture.case,
        &fixture.contexts,
        &views.tcp,
        &fixture.outcome.candidates,
        &fixture.outcome.omissions,
    )?;
    assert_eq!(
        ancestry_ids.len(),
        1,
        "different byte contents under the same recipe share an opaque ancestry identity"
    );
    let expected_records = fixture
        .contexts
        .iter()
        .map(|context| (context.run, context.records.as_slice()))
        .collect::<std::collections::HashMap<_, _>>();
    let derived_frames = frames_for_views(&fixture.case, &views.tcp, &expected_records)?;
    let expected_frame_count = fixture
        .contexts
        .iter()
        .map(|context| context.records.len())
        .sum::<usize>();
    assert_eq!(derived_frames.len(), expected_frame_count);
    assert_derived_frames_are_not_reported_as_missing_source(
        &fixture.outcome.omissions,
        &derived_frames,
    );
    assert!(
        views
            .all
            .iter()
            .filter(|view| source_input(view) == Some(fixture.imported_input))
            .all(|view| frames_for_one_view(&fixture.case, view.id).is_empty()),
        "the imported byte origin must not inherit TCP framing context"
    );
    assert_eq!(
        fixture
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == "tcp_byte_run")
            .count(),
        fixture.contexts.len(),
        "derived bytes must not be represented as synthetic TCP runs"
    );
    assert!(
        views.all.iter().all(|view| view.ranges.is_empty()),
        "transformed bytes have no literal source ranges"
    );
    assert!(
        derived_frames.iter().all(|frame| frame.ranges.is_empty()),
        "frames over transformed bytes have no literal source ranges"
    );
    Ok(derived_frames)
}

fn assert_source_record_generation(
    fixture: &MergedContextFixture,
    views: &DecodedContextViews<'_>,
    derived_frames: &[&Node],
) -> TestResult<()> {
    let record_candidates =
        scoped_record_candidates(&fixture.case, &fixture.outcome.candidates, derived_frames)?;
    assert_eq!(
        record_candidates.len(),
        2,
        "each capture source gets one schema pass"
    );
    for (source_id, sessions) in [
        (&fixture.capture_sources[0], &fixture.contexts[..2]),
        (&fixture.capture_sources[1], &fixture.contexts[2..]),
    ] {
        assert_source_record_candidate(
            &fixture.case,
            &fixture.outcome.candidates,
            &record_candidates,
            derived_frames,
            &SourceRecordExpectation {
                source_id,
                sessions,
                transform_indexes: &views.transform_indexes,
                max_depth: DERIVED_TEST_MAX_DEPTH,
            },
        )?;
    }
    Ok(())
}

#[test]
fn disabled_framing_discovery_does_not_schedule_transformed_views() -> TestResult<()> {
    let (plaintext, records) = delimited_records([0xa5, 0xb6]);
    let encoded = base64_encode(&plaintext);
    let mut case = Case::new();
    let source_id = add_capture(&mut case, "disabled-framing")?;
    let context = add_tcp_context(&mut case, &source_id, 1, &encoded, &plaintext, &records)?;
    let recipe = Recipe {
        steps: vec![Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        }],
        constraints: Vec::new(),
    };
    let selected_framing = FramingKind::Delimiter { byte: 0xff };
    let plan = RecoveryPlan {
        recipes: vec![recipe],
        framings: vec![selected_framing.clone()],
        discover_transforms: true,
        discover_framing: false,
        discover_records: false,
        ..RecoveryPlan::default()
    };
    let execution_policy = policy();

    let outcome = execute(&mut case, &plan, &execution_policy)?;

    let origins = BTreeSet::from([context.run]);
    let (_, receipt_node) =
        merged_base64_transform(&case, &outcome.candidates, &encoded, &plaintext, &origins)?;
    let views = contextual_outputs(&case, receipt_node, &plaintext, &origins)?;
    assert_eq!(views.len(), 1, "the selected decode still runs");
    assert!(
        outcome
            .candidates
            .iter()
            .all(|candidate| candidate.task() != &RecoveryTask::FramingDiscovery),
        "disabled framing discovery must not enqueue work for decoded views"
    );
    assert!(
        outcome.candidates.iter().any(|candidate| {
            candidate.task() == &RecoveryTask::MaterializeFraming(selected_framing.clone())
                && candidate
                    .inputs()
                    .iter()
                    .any(|input| input.origin_node_ids().contains(&context.run))
        }),
        "an explicitly selected framing operation remains scheduled"
    );
    assert!(
        outcome.omissions.iter().all(|omission| !matches!(
            omission,
            super::RecoveryOmission::FramingDiscoveryInputs { .. }
                | super::RecoveryOmission::FramingDiscoveryAnalysis { .. }
                | super::RecoveryOmission::FramingDiscoveryReportDetails { .. }
                | super::RecoveryOmission::ResourceExhausted {
                    task: RecoveryTask::FramingDiscovery,
                    ..
                }
        )),
        "disabled work must not create framing omissions"
    );
    Ok(())
}

#[test]
fn fully_native_covered_tcp_run_does_not_reopen_derived_framing() -> TestResult<()> {
    let (plaintext, records) = delimited_records([0xa5, 0xb6]);
    let encoded = base64_encode(&plaintext);
    let mut case = Case::new();
    let source_id = add_capture(&mut case, "native-covered-derived")?;
    let context = add_tcp_context(&mut case, &source_id, 1, &encoded, &plaintext, &records)?;
    add_http_coverage(&mut case, context.run, encoded.len(), encoded.len())?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    let origins = BTreeSet::from([context.run]);
    let (_, receipt_node) =
        merged_base64_transform(&case, &outcome.candidates, &encoded, &plaintext, &origins)?;
    let decoded = case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "decoding_output"
                && node_blob(&case, node).is_some_and(|bytes| bytes == plaintext)
                && case.edges().iter().any(|edge| {
                    edge.from == node.id
                        && edge.to == receipt_node
                        && edge.relation == "derived_from"
                })
        })
        .ok_or("the ordinary transform output is missing")?;
    assert!(
        outcome.candidates.iter().all(|candidate| {
            candidate.task() != &RecoveryTask::FramingDiscovery
                || candidate
                    .inputs()
                    .iter()
                    .all(|input| !input.origin_node_ids().contains(&decoded.id))
        }),
        "fully native-covered bytes must not seed derived unknown-wire framing"
    );
    assert!(
        case.nodes().iter().all(|node| {
            node.kind != "recovery_framing_discovery_report"
                || node_blob(&case, node)
                    .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
                    .and_then(|report| report.pointer("/input_runs")?.as_array().cloned())
                    .is_none_or(|runs| {
                        runs.iter().all(|run| {
                            run.get("node_id").and_then(Value::as_u64) != Some(decoded.id)
                        })
                    })
        }),
        "fully native-covered bytes must not produce a derived framing report"
    );
    assert!(
        outcome.omissions.iter().all(|omission| {
            !matches!(
                omission,
                super::RecoveryOmission::FramingDiscoveryInputs {
                    source_id: Some(omitted_source),
                    ..
                } if omitted_source == &source_id
            )
        }),
        "fully covered bytes are outside derived search without being reported as omitted"
    );
    Ok(())
}

#[test]
fn uncovered_native_http_tail_keeps_derived_framing_eligible() -> TestResult<()> {
    let (plaintext, records) = delimited_records([0xa5, 0xb6]);
    let encoded = base64_encode(&plaintext);
    let mut case = Case::new();
    let source_id = add_capture(&mut case, "native-http-tail")?;
    let context = add_tcp_context(&mut case, &source_id, 1, &encoded, &plaintext, &records)?;
    let covered_length = encoded
        .len()
        .checked_sub(1)
        .ok_or("encoded stream is empty")?;
    add_http_coverage(&mut case, context.run, encoded.len(), covered_length)?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy())?;

    let origins = BTreeSet::from([context.run]);
    let (_, receipt_node) =
        merged_base64_transform(&case, &outcome.candidates, &encoded, &plaintext, &origins)?;
    let views = contextual_outputs(&case, receipt_node, &plaintext, &origins)?;
    let view = views
        .first()
        .copied()
        .ok_or("the ordinary transform output is missing")?;
    assert!(
        outcome.candidates.iter().any(|candidate| {
            candidate.task() == &RecoveryTask::FramingDiscovery
                && candidate
                    .inputs()
                    .iter()
                    .any(|input| input.origin_node_ids().contains(&view.id))
        }),
        "an uncovered source tail must keep the full observed stream eligible for derived framing"
    );
    Ok(())
}

fn add_http_coverage(
    case: &mut Case,
    run: u64,
    observed_length: usize,
    covered_length: usize,
) -> TestResult<()> {
    let uncovered_length = observed_length
        .checked_sub(covered_length)
        .ok_or("HTTP coverage exceeds the observed stream")?;
    let status = if uncovered_length == 0 {
        "complete"
    } else {
        "incomplete"
    };
    let unparsed = if uncovered_length > 0 {
        json!([{
            "offset":covered_length,
            "length":uncovered_length
        }])
    } else {
        json!([])
    };
    let checks = case.add_node(
        "application_checks",
        None,
        Vec::new(),
        json!({
            "http": {
                "status":status,
                "messages":1,
                "unparsed":unparsed,
                "budget_omissions":[]
            },
            "start_known":true,
            "end_observed":uncovered_length == 0
        }),
    )?;
    let candidate = case.add_node(
        "http_message_candidate",
        None,
        Vec::new(),
        json!({
            "range":{"offset":0,"length":covered_length},
            "status":"complete",
            "framing":{"kind":"content_length","expected":covered_length}
        }),
    )?;
    case.add_edge(Edge {
        from: run,
        to: checks,
        relation: "tested_by".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Native HTTP coverage records the observed message range".to_owned(),
    })?;
    case.add_edge(Edge {
        from: run,
        to: candidate,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Hypothesis,
        reason: "A complete native HTTP message covers the observed run".to_owned(),
    })?;
    Ok(())
}

fn delimited_records(payloads: [u8; 2]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let records = vec![
        vec![0x42, 0, 2, payloads[0], 0xff],
        vec![0x42, 1, 2, payloads[1], 0xff],
    ];
    let stream = records.iter().flatten().copied().collect();
    (stream, records)
}

fn base64_encode(bytes: &[u8]) -> Vec<u8> {
    use base64::Engine as _;

    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .into_bytes()
}

fn add_capture(case: &mut Case, label: &str) -> TestResult<String> {
    let fingerprint = format!("source bytes for {label}");
    Ok(case.add_source(
        &format!("{label}.pcap"),
        "capture",
        100_000,
        &l2_workbench::sha256(fingerprint.as_bytes()),
        None,
    )?)
}

fn add_tcp_context(
    case: &mut Case,
    source_id: &str,
    packet: u64,
    bytes: &[u8],
    plaintext: &[u8],
    records: &[Vec<u8>],
) -> TestResult<TcpContext> {
    let start_known = packet == 1;
    let end_observed = packet == 1;
    let (episode, endpoints) = add_tcp_episode(case, packet)?;
    let direction = add_tcp_direction(
        case,
        episode,
        &endpoints,
        bytes.len(),
        start_known,
        end_observed,
    )?;
    let run = add_tcp_run(
        case,
        source_id,
        packet,
        bytes,
        start_known,
        end_observed,
        direction,
    )?;
    Ok(TcpContext {
        source_id: source_id.to_owned(),
        episode,
        direction,
        run,
        start_known,
        end_observed,
        plaintext: plaintext.to_vec(),
        records: records.to_vec(),
    })
}

fn add_tcp_episode(case: &mut Case, packet: u64) -> TestResult<(u64, Value)> {
    let endpoints = json!([
        {"address":"10.0.0.1","port":9000},
        {"address":"10.0.0.2","port":9001}
    ]);
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({
            "scope":{"interface":"phase-three","link_type":1},
            "endpoints":endpoints,
            "first_packet":packet,
            "generation_ambiguous":false
        }),
    )?;
    Ok((episode, endpoints))
}

fn add_tcp_direction(
    case: &mut Case,
    episode: u64,
    endpoints: &Value,
    byte_length: usize,
    start_known: bool,
    end_observed: bool,
) -> TestResult<u64> {
    let source_endpoint = endpoints
        .as_array()
        .and_then(|pair| pair.first())
        .cloned()
        .ok_or("TCP source endpoint is missing")?;
    let destination_endpoint = endpoints
        .as_array()
        .and_then(|pair| pair.get(1))
        .cloned()
        .ok_or("TCP destination endpoint is missing")?;
    let coverage = json!({
        "length":byte_length,
        "observed":byte_length,
        "missing":0,
        "conflicting":0,
        "omitted":0,
        "omitted_observations":0
    });
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
            "sequence_ambiguous":false,
            "outside_segments":0,
            "coverage":coverage
        }),
    )?;
    case.add_edge(Edge {
        from: episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "TCP direction belongs to this fixture session".to_owned(),
    })?;
    Ok(direction)
}

fn add_tcp_run(
    case: &mut Case,
    source_id: &str,
    packet: u64,
    bytes: &[u8],
    start_known: bool,
    end_observed: bool,
    direction: u64,
) -> TestResult<u64> {
    let range_offset = packet
        .checked_mul(1000)
        .ok_or("TCP source range offset overflowed")?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source_id.to_owned(),
                packet: Some(packet),
                offset: range_offset,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({
            "offset":0,
            "length":bytes.len(),
            "start_known":start_known,
            "end_observed":end_observed,
            "generation_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: direction,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "TCP run belongs to this fixture direction".to_owned(),
    })?;
    Ok(run)
}

fn assert_transport_completeness_survives_decode(
    case: &Case,
    contexts: &[TcpContext],
    views: &[&Node],
    candidates: &[RecoveryCandidate],
    omissions: &[super::RecoveryOmission],
) -> TestResult<BTreeSet<String>> {
    let mut ancestry_ids = BTreeSet::new();
    for (context, view) in contexts.iter().zip(views) {
        assert_eq!(
            node_blob(case, view),
            Some(context.plaintext.as_slice()),
            "decoded views retain the exact bytes for each source session"
        );
        ancestry_ids.insert(assert_framing_report_preserves_context(
            case, view, context, candidates, omissions,
        )?);
    }
    Ok(ancestry_ids)
}

fn assert_framing_report_preserves_context(
    case: &Case,
    view: &Node,
    context: &TcpContext,
    candidates: &[RecoveryCandidate],
    omissions: &[super::RecoveryOmission],
) -> TestResult<String> {
    let all_reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_framing_discovery_report")
        .filter_map(|node| node_blob(case, node))
        .filter_map(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .collect::<Vec<_>>();
    let reports = all_reports
        .iter()
        .filter(|report| {
            report
                .pointer("/input_runs")
                .and_then(Value::as_array)
                .is_some_and(|runs| {
                    runs.iter()
                        .any(|run| run.get("node_id").and_then(Value::as_u64) == Some(view.id))
                })
        })
        .collect::<Vec<_>>();
    let report_summary = all_reports
        .iter()
        .map(|report| {
            (
                report.get("source_id").and_then(Value::as_str),
                report
                    .pointer("/input_generation/kind")
                    .and_then(Value::as_str),
                report
                    .pointer("/input_runs")
                    .and_then(Value::as_array)
                    .map(|runs| {
                        runs.iter()
                            .filter_map(|run| run.get("node_id").and_then(Value::as_u64))
                            .collect::<Vec<_>>()
                    }),
            )
        })
        .collect::<Vec<_>>();
    let framing_candidate_count = candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::FramingDiscovery)
        .count();
    let omission_summary = summarize_omissions(omissions);
    let [report] = reports.as_slice() else {
        return Err(format!(
            "expected one derived framing report for decoded TCP input {}; retained reports: {report_summary:?}; framing candidates: {framing_candidate_count}; omission summary: {omission_summary:?}",
            context.run,
        )
        .into());
    };
    let input = report
        .pointer("/input_runs")
        .and_then(Value::as_array)
        .and_then(|runs| {
            runs.iter()
                .find(|run| run.get("node_id").and_then(Value::as_u64) == Some(view.id))
        })
        .ok_or("derived framing report lost a decoded TCP input")?;
    assert_eq!(
        report
            .pointer("/input_generation/kind")
            .and_then(Value::as_str),
        Some("transformed_stream")
    );
    let ancestry_id = report
        .pointer("/input_generation/ancestry_id")
        .and_then(Value::as_str)
        .ok_or("derived framing report lost its ancestry identity")?;
    assert_eq!(
        input.get("end_observed").and_then(Value::as_bool),
        Some(context.end_observed),
        "decoded bytes preserve the capture's terminal observation"
    );
    assert_eq!(
        input.get("start_known").and_then(Value::as_bool),
        Some(context.start_known),
        "decoded bytes preserve the capture's starting observation"
    );
    Ok(ancestry_id.to_owned())
}

fn summarize_omissions(omissions: &[super::RecoveryOmission]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for omission in omissions {
        let label = match omission {
            super::RecoveryOmission::ResourceExhausted { task, resource, .. } => {
                format!("{}:{resource:?}", task_label(task))
            }
            super::RecoveryOmission::FramingDiscoveryInputs { reason_counts, .. } => {
                format!("framing_input:{reason_counts:?}")
            }
            super::RecoveryOmission::FramingDiscoveryAnalysis { .. } => {
                "framing_analysis".to_owned()
            }
            _ => "other".to_owned(),
        };
        let count = summary.entry(label).or_insert(0_usize);
        *count += 1;
    }
    summary
}

fn assert_derived_frames_are_not_reported_as_missing_source(
    omissions: &[super::RecoveryOmission],
    frames: &[&Node],
) {
    let derived_frame_ids = frames.iter().map(|frame| frame.id).collect::<BTreeSet<_>>();
    for omission in omissions {
        let super::RecoveryOmission::RecordDiscoveryInputs { examples, .. } = omission else {
            continue;
        };
        assert!(examples.iter().all(|example| {
            example.get("reason").and_then(Value::as_str) != Some("missing_source")
                || example
                    .get("frame_node_id")
                    .and_then(Value::as_u64)
                    .is_none_or(|node_id| !derived_frame_ids.contains(&node_id))
        }));
    }
}

fn task_label(task: &RecoveryTask) -> &'static str {
    match task {
        RecoveryTask::Transform(_) => "transform",
        RecoveryTask::TransformDiscovery => "transform_discovery",
        RecoveryTask::FramingDiscovery => "framing_discovery",
        RecoveryTask::MaterializeFraming(_) => "materialize_framing",
        RecoveryTask::RecordDiscovery => "record_discovery",
        RecoveryTask::RelationalTransformDiscovery => "relational_discovery",
        RecoveryTask::AssembleRecords(_) => "assemble_records",
        RecoveryTask::EmbeddedDiscovery => "embedded_discovery",
        RecoveryTask::StructuralValidation => "structural_validation",
        RecoveryTask::RecursiveExpansion => "recursive_expansion",
    }
}

fn merged_base64_transform(
    case: &Case,
    candidates: &[RecoveryCandidate],
    encoded: &[u8],
    plaintext: &[u8],
    expected_origins: &BTreeSet<u64>,
) -> TestResult<(usize, u64)> {
    for (index, candidate) in candidates.iter().enumerate() {
        let RecoveryTask::Transform(recipe) = candidate.task() else {
            continue;
        };
        if !recipe
            .steps
            .iter()
            .any(|operation| matches!(operation, Operation::Base64Decode { .. }))
            || candidate
                .inputs()
                .first()
                .is_none_or(|input| input.blob_id() != super::blob_id(encoded))
        {
            continue;
        }
        let RecoveryCandidateState::Finished {
            result:
                RecoveryResult::Derived {
                    evidence_node_id: receipt,
                },
            ..
        } = candidate.state()
        else {
            continue;
        };
        let origins = candidate_origins(candidate);
        let has_expected_origins = expected_origins == &origins;
        let produced_plaintext = case.nodes().iter().any(|node| {
            node.kind == "decoding_output"
                && node_blob(case, node).is_some_and(|bytes| bytes == plaintext)
                && case.edges().iter().any(|edge| {
                    edge.from == node.id && edge.to == *receipt && edge.relation == "derived_from"
                })
        });
        if has_expected_origins && produced_plaintext {
            return Ok((index, *receipt));
        }
    }
    Err("automatic base64 transform did not merge all source contexts".into())
}

fn contextual_outputs<'a>(
    case: &'a Case,
    receipt: u64,
    plaintext: &[u8],
    expected_inputs: &BTreeSet<u64>,
) -> TestResult<Vec<&'a Node>> {
    let views = case
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "decoding_output"
                && node
                    .details
                    .get("shared_transform_receipt")
                    .and_then(Value::as_u64)
                    == Some(receipt)
                && node_blob(case, node).is_some_and(|bytes| bytes == plaintext)
                && source_input(node).is_some_and(|input| expected_inputs.contains(&input))
        })
        .collect::<Vec<_>>();
    if views.len() != expected_inputs.len() {
        let decoded_output_details = case
            .nodes()
            .iter()
            .filter(|node| {
                node.kind == "decoding_output"
                    && node_blob(case, node).is_some_and(|bytes| bytes == plaintext)
            })
            .map(|node| (node.id, node.details.clone()))
            .collect::<Vec<_>>();
        return Err(format!(
            "expected one decoded view for {} inputs, found {}; decoded outputs: {decoded_output_details:?}",
            expected_inputs.len(),
            views.len()
        )
        .into());
    }
    Ok(views)
}

fn source_input(node: &Node) -> Option<u64> {
    node.details
        .get("source_input_node")
        .and_then(Value::as_u64)
}

fn node_blob<'a>(case: &'a Case, node: &Node) -> Option<&'a [u8]> {
    let blob_id = node.blob.as_deref()?;
    case.blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .map(|blob| blob.bytes.as_slice())
}

fn contextual_view_for<'a>(views: &[&'a Node], source_node: u64) -> TestResult<&'a Node> {
    views
        .iter()
        .copied()
        .find(|view| source_input(view) == Some(source_node))
        .ok_or_else(|| format!("decoded context for input {source_node} is missing").into())
}

fn frames_for_views<'a>(
    case: &'a Case,
    views: &[&Node],
    expected_records_by_input: &std::collections::HashMap<u64, &[Vec<u8>]>,
) -> TestResult<Vec<&'a Node>> {
    let mut derived_frames = Vec::new();
    for view in views {
        let mut frames = frames_for_one_view(case, view.id);
        frames.sort_by_key(|frame| {
            frame
                .details
                .get("frame_index")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX)
        });
        let frame_bytes = frames
            .iter()
            .map(|frame| node_blob(case, frame).ok_or("derived frame blob is missing"))
            .collect::<Result<Vec<_>, _>>()?;
        let input_node = source_input(view).ok_or("decoded view lost its input identity")?;
        let expected_records = expected_records_by_input
            .get(&input_node)
            .ok_or("decoded view has no expected record bytes")?;
        assert_eq!(
            frame_bytes,
            expected_records
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            "the selected delimiter framing should retain exact record bytes for input {}",
            view.id,
        );
        derived_frames.extend(frames);
    }
    Ok(derived_frames)
}

fn frames_for_one_view(case: &Case, view_id: u64) -> Vec<&Node> {
    case.nodes()
        .iter()
        .filter(|node| {
            node.kind == "custom_protocol_frame"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(view_id)
                && node.details.get("framing_rule").is_some_and(|rule| {
                    rule.get("kind").and_then(Value::as_str) == Some("delimiter")
                        && rule.get("byte").and_then(Value::as_u64) == Some(0xff)
                })
        })
        .collect()
}

fn scoped_record_candidates<'a>(
    case: &Case,
    candidates: &'a [RecoveryCandidate],
    frames: &[&Node],
) -> TestResult<Vec<&'a RecoveryCandidate>> {
    let frame_ids = frames.iter().map(|frame| frame.id).collect::<BTreeSet<_>>();
    let matching = candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .filter(|candidate| !frame_ids.is_disjoint(&candidate_origins(candidate)))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        let observed_frames = case
            .nodes()
            .iter()
            .filter(|node| node.kind == "custom_protocol_frame")
            .count();
        let record_candidate_summary = candidates
            .iter()
            .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
            .take(8)
            .map(|candidate| candidate_origins(candidate).into_iter().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        return Err(format!(
            "derived record discovery is missing for {} expected frames; Case has {observed_frames} total frames and {} record candidates; initial candidate origins: {record_candidate_summary:?}",
            frame_ids.len(),
            candidates
                .iter()
                .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
                .count(),
        )
        .into());
    }
    Ok(matching)
}

fn assert_source_record_candidate(
    case: &Case,
    candidates: &[RecoveryCandidate],
    record_candidates: &[&RecoveryCandidate],
    frames: &[&Node],
    expectation: &SourceRecordExpectation<'_>,
) -> TestResult<()> {
    let expected_frames = frames
        .iter()
        .filter(|frame| frame_belongs_to_source(case, frame, expectation.sessions))
        .map(|frame| frame.id)
        .collect::<BTreeSet<_>>();
    let selected = record_candidates
        .iter()
        .copied()
        .filter(|candidate| expected_frames.is_subset(&candidate_origins(candidate)))
        .collect::<Vec<_>>();
    assert_eq!(
        selected.len(),
        1,
        "source-scoped record generation should run once"
    );
    let candidate = selected
        .first()
        .copied()
        .ok_or("source-scoped record candidate is missing")?;
    assert!(expectation.transform_indexes.iter().any(|index| {
        candidates
            .get(*index)
            .is_some_and(|transform| candidate.depth() > transform.depth())
    }));
    assert!(
        candidate.depth() <= expectation.max_depth,
        "derived work must retain the coordinator depth cap"
    );
    assert!(
        expectation
            .transform_indexes
            .iter()
            .any(|index| has_ancestor(candidates, candidate, *index))
    );

    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id: report_id },
        ..
    } = candidate.state()
    else {
        return Err("derived record discovery did not retain its report".into());
    };
    let report = report_value(case, *report_id)?;
    assert_eq!(
        report.pointer("/cohort/source_id").and_then(Value::as_str),
        Some(expectation.source_id)
    );
    assert_eq!(
        report.pointer("/cohort/scope"),
        Some(&json!({"interface":"phase-three","link_type":1}))
    );
    assert_eq!(
        report.pointer("/application/session_count"),
        Some(&json!(2))
    );
    let retained_sessions = [
        report
            .pointer("/partition/training_session_nodes")
            .and_then(Value::as_array),
        report
            .pointer("/partition/held_out_session_nodes")
            .and_then(Value::as_array),
    ]
    .into_iter()
    .flatten()
    .flatten()
    .filter_map(Value::as_u64)
    .collect::<BTreeSet<_>>();
    let expected_sessions = expectation
        .sessions
        .iter()
        .map(|session| session.episode)
        .collect::<BTreeSet<_>>();
    assert_eq!(retained_sessions, expected_sessions);
    Ok(())
}

fn frame_belongs_to_source(case: &Case, frame: &Node, sessions: &[TcpContext]) -> bool {
    let Some(input_node) = frame.details.get("input_node").and_then(Value::as_u64) else {
        return false;
    };
    let Some(view) = case.nodes().iter().find(|node| node.id == input_node) else {
        return false;
    };
    let Some(source_node) = source_input(view) else {
        return false;
    };
    sessions.iter().any(|session| session.run == source_node)
}

fn report_value(case: &Case, report_id: u64) -> TestResult<Value> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == report_id)
        .ok_or("record discovery report node is missing")?;
    if node.kind != "recovery_record_discovery_report" {
        return Err("derived discovery did not retain a record schema report".into());
    }
    let report_blob = node
        .blob
        .as_deref()
        .ok_or("record report bytes are missing")?;
    let bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == report_blob)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record report blob is missing")?;
    Ok(serde_json::from_slice(bytes)?)
}

fn candidate_origins(candidate: &RecoveryCandidate) -> BTreeSet<u64> {
    candidate
        .inputs()
        .iter()
        .flat_map(|input| input.origin_node_ids().iter().copied())
        .collect()
}

fn has_ancestor(
    candidates: &[RecoveryCandidate],
    candidate: &RecoveryCandidate,
    expected_ancestor: usize,
) -> bool {
    let mut pending = candidate.parent_ids().to_vec();
    let mut visited = BTreeSet::new();
    while let Some(parent) = pending.pop() {
        if parent.index() == expected_ancestor {
            return true;
        }
        if !visited.insert(parent.index()) {
            continue;
        }
        if let Some(parent_candidate) = candidates.get(parent.index()) {
            pending.extend(parent_candidate.parent_ids().iter().copied());
        }
    }
    false
}
