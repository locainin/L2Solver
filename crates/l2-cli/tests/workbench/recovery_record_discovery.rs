use super::super::framing_materialize::FramingSelectionBasis;
use super::{RecoveryPlan, execute, normal_policy, recover_case, recover_case_with_job};
use crate::arguments::RecoveryProfile;
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
    protocol::{
        ByteField, ByteOrder, FramingKind, IntegerField, LengthMeaning, RecordCount,
        RecordLengthMeaning, RecordSchema,
    },
    recovery::{RecoveryCandidateState, RecoveryResult, RecoveryTask},
};
use serde_json::{Value, json};
use std::error::Error;

#[path = "recovery_record_handoff.rs"]
mod record_handoff;

const REPORT_KIND: &str = "recovery_record_discovery_report";
type TestResult<T> = Result<T, Box<dyn Error>>;

struct MaterializedSession {
    episode_node: u64,
    frame_nodes: Vec<u64>,
    receipt_nodes: Vec<u64>,
}

struct SessionContext {
    episode_node: u64,
    direction_node: u64,
}

struct MaterializedRun {
    frame_nodes: Vec<u64>,
    receipt_node: u64,
}

struct UnframedSession {
    scope: String,
    episode_node: u64,
    run_node: u64,
    messages: Vec<Vec<u8>>,
}

struct SyntheticArtifact {
    session_index: usize,
    direction_index: usize,
    identifier: [u8; 2],
    bytes: Vec<u8>,
}

struct SyntheticRun {
    session_index: usize,
    direction_index: usize,
    node_id: u64,
}

struct RawDirectionalFixture {
    case: Case,
    plaintext: Vec<u8>,
    run_nodes: Vec<u64>,
}

pub(super) struct SessionRelativeFixture {
    pub(super) case: Case,
    pub(super) plaintext: Vec<u8>,
    pub(super) episode_nodes: Vec<u64>,
}

#[derive(Clone, Copy)]
struct MaterializationOptions<'a> {
    framing: &'a FramingKind,
    selection_basis: FramingSelectionBasis,
}

struct InvalidFrameExamples {
    missing_receipt: u64,
    missing_selection_basis: u64,
    malformed_selection_basis: u64,
}

struct PrimaryFixture {
    case: Case,
    source_id: String,
    ambiguous_source_id: String,
    training_episode: u64,
    held_out_episode: u64,
    frame_nodes: Vec<u64>,
    receipt_nodes: Vec<u64>,
    omitted_frame: u64,
    missing_basis_frame: u64,
    malformed_basis_frame: u64,
}

fn capture(case: &mut Case, label: &str) -> TestResult<String> {
    let contents = format!("synthetic capture for {label}");
    Ok(case.add_source(
        &format!("{label}.pcap"),
        "capture",
        1_000_000,
        &l2_workbench::sha256(contents.as_bytes()),
        None,
    )?)
}

fn record(identifier: &[u8], sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(identifier);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

fn synthetic_protocol_record(
    identifier: [u8; 2],
    sequence: u16,
    payload: &[u8],
) -> TestResult<Vec<u8>> {
    let mut body = vec![0xd7];
    body.extend_from_slice(&identifier);
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&u16::try_from(payload.len())?.to_le_bytes());
    body.extend_from_slice(payload);

    let mut wire = Vec::with_capacity(body.len() + 2);
    wire.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
    wire.extend_from_slice(&body);
    Ok(wire)
}

fn synthetic_png(pixel: [u8; 3]) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::NoCompression);
        encoder.set_filter(png::Filter::NoFilter);
        encoder.write_header()?.write_image_data(&pixel)?;
    }
    Ok(bytes)
}

fn synthetic_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 3,
            width: 2,
        },
        sequence: IntegerField {
            offset: 5,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 7,
            width: 2,
            byte_order: ByteOrder::LittleEndian,
        },
        data_offset: 9,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

fn add_synthetic_episode(case: &mut Case, first_packet: u64) -> TestResult<u64> {
    Ok(case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        episode_details("synthetic-independent-protocol", first_packet),
    )?)
}

fn add_synthetic_direction(
    case: &mut Case,
    episode_node: u64,
    direction_index: usize,
    byte_length: usize,
) -> TestResult<u64> {
    let endpoints = conversation_endpoints();
    let endpoint_items = endpoints.as_array().ok_or("endpoint array is missing")?;
    let first_endpoint = endpoint_items.first().ok_or("first endpoint is missing")?;
    let second_endpoint = endpoint_items.get(1).ok_or("second endpoint is missing")?;
    let (source_endpoint, destination_endpoint) = if direction_index == 0 {
        (first_endpoint, second_endpoint)
    } else {
        (second_endpoint, first_endpoint)
    };
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":source_endpoint,
            "destination":destination_endpoint,
            "start_known":true,
            "end_observed":true,
            "sequence_ambiguous":false,
            "coverage":{
                "length":byte_length,
                "observed":byte_length,
                "missing":0,
                "conflicting":0,
                "omitted":0,
                "omitted_observations":0
            }
        }),
    )?;
    case.add_edge(Edge {
        from: episode_node,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic direction belongs to this episode".to_owned(),
    })?;
    Ok(direction)
}

fn add_synthetic_protocol_fixture(
    case: &mut Case,
) -> TestResult<(Vec<SyntheticArtifact>, Vec<SyntheticRun>)> {
    const IDENTIFIERS: [[u8; 2]; 2] = [[0x3c, 0x81], [0xa6, 0x12]];
    const SEQUENCES: [u16; 3] = [0, 1, 256];
    const CHUNK_ENDS: [usize; 4] = [0, 17, 35, usize::MAX];

    let source = capture(case, "unrelated-length-prefixed-png-records")?;
    let mut artifacts = Vec::new();
    let mut runs = Vec::new();
    for session_index in 0..2 {
        let first_packet = 10_u64
            .checked_add(
                u64::try_from(session_index)?
                    .checked_mul(10)
                    .ok_or("packet overflow")?,
            )
            .ok_or("packet overflow")?;
        let episode_node = add_synthetic_episode(case, first_packet)?;
        for direction_index in 0..2 {
            let mut session_artifacts = Vec::new();
            for (identifier_index, identifier) in IDENTIFIERS.into_iter().enumerate() {
                let marker =
                    u8::try_from(16 + session_index * 4 + direction_index * 2 + identifier_index)?;
                session_artifacts.push(SyntheticArtifact {
                    session_index,
                    direction_index,
                    identifier,
                    bytes: synthetic_png([marker, marker + 1, marker + 2])?,
                });
            }
            let image_length = session_artifacts
                .first()
                .ok_or("synthetic artifact is missing")?
                .bytes
                .len();
            assert!(
                session_artifacts
                    .iter()
                    .all(|artifact| artifact.bytes.len() == image_length)
            );

            let mut wire = Vec::new();
            for ((start, end), sequence) in CHUNK_ENDS
                .into_iter()
                .zip(CHUNK_ENDS.into_iter().skip(1))
                .zip(SEQUENCES)
            {
                for artifact in &session_artifacts {
                    let end = end.min(artifact.bytes.len());
                    let payload = artifact
                        .bytes
                        .get(start..end)
                        .ok_or("synthetic PNG chunk range is invalid")?;
                    wire.extend_from_slice(&synthetic_protocol_record(
                        artifact.identifier,
                        sequence,
                        payload,
                    )?);
                }
            }

            let direction_node =
                add_synthetic_direction(case, episode_node, direction_index, wire.len())?;
            let packet = first_packet
                .checked_add(u64::try_from(direction_index)?)
                .ok_or("packet overflow")?;
            let run_node = add_tcp_run_in_context(case, &source, direction_node, packet, &wire)?;
            artifacts.extend(session_artifacts);
            runs.push(SyntheticRun {
                session_index,
                direction_index,
                node_id: run_node,
            });
        }
    }
    Ok((artifacts, runs))
}

fn typed_survivor_schemas(
    sessions: &[Vec<Vec<u8>>],
    limits: l2_workbench::protocol::RecordSchemaProposalLimits,
) -> TestResult<(Vec<l2_workbench::protocol::RecordSchema>, usize)> {
    let training_messages = sessions
        .first()
        .ok_or("typed discovery fixture has no training session")?
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let held_out_messages = sessions
        .get(1)
        .ok_or("typed discovery fixture has no held-out session")?
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let analysis = l2_workbench::protocol::analyze_record_schemas(
        &training_messages,
        &held_out_messages,
        limits,
    )?;
    let discovery = analysis
        .discovery
        .ok_or("typed discovery fixture has no candidate field relations")?;
    let schemas = discovery
        .surviving
        .iter()
        .map(|hypothesis| hypothesis.schema.clone())
        .collect::<Vec<_>>();
    Ok((schemas, discovery.falsifications.len()))
}

fn add_materialized_session(
    case: &mut Case,
    source: &str,
    scope_name: &str,
    first_packet: u64,
    direction_index: usize,
    messages: &[Vec<u8>],
    framing: &FramingKind,
) -> TestResult<MaterializedSession> {
    add_materialized_session_with_options(
        case,
        source,
        scope_name,
        first_packet,
        direction_index,
        messages,
        MaterializationOptions {
            framing,
            selection_basis: FramingSelectionBasis::CallerSupplied {},
        },
    )
}

fn add_materialized_session_with_options(
    case: &mut Case,
    source: &str,
    scope_name: &str,
    first_packet: u64,
    direction_index: usize,
    messages: &[Vec<u8>],
    options: MaterializationOptions<'_>,
) -> TestResult<MaterializedSession> {
    let context = add_session_context(
        case,
        scope_name,
        first_packet,
        direction_index,
        messages.iter().map(Vec::len).sum(),
    )?;
    let mut session = MaterializedSession {
        episode_node: context.episode_node,
        frame_nodes: Vec::new(),
        receipt_nodes: Vec::new(),
    };
    let mut stream_offset = 0_usize;
    for message in messages {
        let run = add_materialized_run(
            case,
            source,
            context.direction_node,
            first_packet,
            stream_offset,
            message,
            options,
        )?;
        session.frame_nodes.extend(run.frame_nodes);
        session.receipt_nodes.push(run.receipt_node);
        stream_offset = stream_offset
            .checked_add(message.len())
            .ok_or("stream offset overflow")?;
    }
    Ok(session)
}

fn add_session_context(
    case: &mut Case,
    scope_name: &str,
    first_packet: u64,
    direction_index: usize,
    byte_length: usize,
) -> TestResult<SessionContext> {
    let endpoints = conversation_endpoints();
    let episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        episode_details(scope_name, first_packet),
    )?;
    let endpoint_items = endpoints.as_array().ok_or("endpoint array is missing")?;
    let first_endpoint = endpoint_items.first().ok_or("first endpoint is missing")?;
    let second_endpoint = endpoint_items.get(1).ok_or("second endpoint is missing")?;
    let (source_endpoint, destination_endpoint) = if direction_index == 0 {
        (first_endpoint, second_endpoint)
    } else {
        (second_endpoint, first_endpoint)
    };
    let direction = case.add_node(
        "tcp_direction",
        None,
        Vec::new(),
        json!({
            "source":source_endpoint,
            "destination":destination_endpoint,
            "start_known":true,
            "end_observed":true,
            "sequence_ambiguous":false,
            "coverage":{
                "length":byte_length,
                "observed":byte_length,
                "missing":0,
                "conflicting":0,
                "omitted":0,
                "omitted_observations":0
            }
        }),
    )?;
    case.add_edge(Edge {
        from: episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic direction belongs to this episode".to_owned(),
    })?;
    Ok(SessionContext {
        episode_node: episode,
        direction_node: direction,
    })
}

fn add_tcp_run_in_context(
    case: &mut Case,
    source: &str,
    direction_node: u64,
    packet: u64,
    bytes: &[u8],
) -> TestResult<u64> {
    let source_offset = packet.checked_mul(10_000).ok_or("source offset overflow")?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(packet),
                offset: source_offset,
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
        from: direction_node,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic run belongs to this direction".to_owned(),
    })?;
    Ok(run)
}

fn add_unframed_sessions(
    case: &mut Case,
    source: &str,
    conversations: Vec<(&str, Vec<Vec<Vec<u8>>>)>,
) -> TestResult<Vec<UnframedSession>> {
    let mut sessions = Vec::new();
    for (conversation_index, (scope, conversation_sessions)) in
        conversations.into_iter().enumerate()
    {
        for (session_index, messages) in conversation_sessions.into_iter().enumerate() {
            let packet_offset = conversation_index
                .checked_mul(20)
                .and_then(|offset| offset.checked_add(session_index.checked_mul(10)?))
                .ok_or("synthetic packet number overflow")?;
            let packet = 10_u64
                .checked_add(u64::try_from(packet_offset)?)
                .ok_or("synthetic packet number overflow")?;
            let byte_length = messages
                .iter()
                .try_fold(0_usize, |total, message| total.checked_add(message.len()))
                .ok_or("synthetic session byte length overflow")?;
            let context = add_session_context(case, scope, packet, 0, byte_length)?;
            let run_node = add_tcp_run_in_context(
                case,
                source,
                context.direction_node,
                packet,
                &messages.concat(),
            )?;
            sessions.push(UnframedSession {
                scope: scope.to_owned(),
                episode_node: context.episode_node,
                run_node,
                messages,
            });
        }
    }
    Ok(sessions)
}

fn add_materialized_run(
    case: &mut Case,
    source: &str,
    direction_node: u64,
    first_packet: u64,
    stream_offset: usize,
    message: &[u8],
    options: MaterializationOptions<'_>,
) -> TestResult<MaterializedRun> {
    let source_offset = first_packet
        .checked_mul(10_000)
        .and_then(|offset| offset.checked_add(u64::try_from(stream_offset).ok()?))
        .ok_or("source offset overflow")?;
    let run = case.add_mapped_bytes_node(
        "tcp_byte_run",
        message,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(first_packet),
                offset: source_offset,
                length: u64::try_from(message.len())?,
            },
        }],
        json!({
            "offset":stream_offset,
            "length":message.len(),
            "start_known":true,
            "end_observed":true,
            "generation_ambiguous":false
        }),
    )?;
    case.add_edge(Edge {
        from: direction_node,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic run belongs to this direction".to_owned(),
    })?;
    let outcome = super::super::framing_materialize::apply_with_basis(
        case,
        run,
        options.framing,
        options.selection_basis,
    )?;
    Ok(MaterializedRun {
        frame_nodes: outcome.frame_nodes,
        receipt_node: outcome.receipt_node,
    })
}

fn conversation_endpoints() -> Value {
    json!([
        {"address":"endpoint-a","port":1000},
        {"address":"endpoint-b","port":2000}
    ])
}

fn episode_details(scope_name: &str, first_packet: u64) -> Value {
    json!({
        "scope":{"interface":scope_name,"link_type":1},
        "endpoints":conversation_endpoints(),
        "first_packet":first_packet,
        "generation_ambiguous":false
    })
}

fn add_framing_discovery_report(case: &mut Case, framing: &FramingKind) -> TestResult<u64> {
    let report = json!({
        "version":1,
        "case_scope":"current_case",
        "source_id":"synthetic-framing-source",
        "cohort":{"scope":"synthetic"},
        "bootstrap":{"hypotheses":[framing]}
    });
    let bytes = serde_json::to_vec(&report)?;
    Ok(case.add_bytes_node(
        "recovery_framing_discovery_report",
        &bytes,
        Vec::new(),
        json!({"report_schema_version":1}),
    )?)
}

fn add_unmaterialized_frame(
    case: &mut Case,
    source: &str,
    packet: u64,
    selection_basis: Option<Value>,
) -> TestResult<u64> {
    let bytes = record(b"\x11\x22\x33", 1, b"rogue");
    let mut details = json!({
        "input_node":u64::MAX,
        "frame_index":0,
        "stream_range":{"start":0,"end":bytes.len()},
        "framing_rule":{"kind":"fixed_size","bytes":bytes.len()},
        "sha256":l2_workbench::sha256(&bytes),
    });
    if let Some(selection_basis) = selection_basis {
        details
            .as_object_mut()
            .ok_or("frame details are not an object")?
            .insert("selection_basis".to_owned(), selection_basis);
    }
    Ok(case.add_mapped_bytes_node(
        "custom_protocol_frame",
        &bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source: source.to_owned(),
                packet: Some(packet),
                offset: packet.checked_mul(10_000).ok_or("source offset overflow")?,
                length: u64::try_from(bytes.len())?,
            },
        }],
        details,
    )?)
}

fn duplicate_materialized_frame(case: &mut Case, frame_id: u64) -> TestResult<u64> {
    let frame = case
        .node(frame_id)
        .ok_or_else(|| std::io::Error::other("source frame is missing"))?;
    let blob_id = frame
        .blob
        .clone()
        .ok_or_else(|| std::io::Error::other("source frame has no blob"))?;
    let bytes = case
        .blob(&blob_id)
        .ok_or_else(|| std::io::Error::other("source frame blob is missing"))?
        .bytes
        .clone();
    let range = frame
        .ranges
        .first()
        .cloned()
        .ok_or_else(|| std::io::Error::other("source frame mapping is missing"))?;
    let details = frame.details.clone();
    let receipt_node_id = case
        .edges()
        .iter()
        .find(|edge| edge.to == frame_id && edge.relation == "materialized")
        .map(|edge| edge.from)
        .ok_or_else(|| std::io::Error::other("source frame receipt is missing"))?;
    let duplicate = case.add_mapped_bytes_node(
        "custom_protocol_frame",
        &bytes,
        &[ByteMapping { offset: 0, range }],
        details,
    )?;
    case.add_edge(Edge {
        from: receipt_node_id,
        to: duplicate,
        relation: "materialized".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic duplicate receipt index".to_owned(),
    })?;
    Ok(duplicate)
}

fn recovery_plan() -> RecoveryPlan {
    RecoveryPlan {
        discover_records: true,
        ..RecoveryPlan::default()
    }
}

fn decode_report(case: &Case, node_id: u64) -> TestResult<Value> {
    let node = case
        .nodes()
        .iter()
        .find(|node| node.id == node_id && node.kind == REPORT_KIND)
        .ok_or("record discovery report node is missing")?;
    let blob_id = node.blob.as_deref().ok_or("report has no retained bytes")?;
    let blob = case
        .blobs()
        .iter()
        .find(|blob| blob.id == blob_id)
        .ok_or("report blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn report_schemas(report: &Value) -> TestResult<Vec<RecordSchema>> {
    report
        .pointer("/schema_discovery/surviving")
        .and_then(Value::as_array)
        .ok_or("automatic record discovery has no retained survivor list")?
        .iter()
        .map(|survivor| {
            let schema = survivor
                .get("schema")
                .cloned()
                .ok_or_else(|| std::io::Error::other("survivor schema is missing"))?;
            serde_json::from_value::<RecordSchema>(schema).map_err(std::io::Error::other)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn assert_synthetic_schema_survives_default_search(case: &Case) -> TestResult<()> {
    let expected_schema = synthetic_schema();
    let expected_framing = serde_json::to_value(FramingKind::LengthPrefix {
        offset: 0,
        width: 2,
        byte_order: ByteOrder::BigEndian,
        meaning: LengthMeaning::BytesAfterField,
    })?;
    let reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == REPORT_KIND)
        .map(|node| decode_report(case, node.id))
        .collect::<TestResult<Vec<_>>>()?;
    let matching_reports = reports
        .iter()
        .filter(|report| report.pointer("/cohort/framing_rule") == Some(&expected_framing))
        .collect::<Vec<_>>();
    assert_eq!(matching_reports.len(), 2);
    for report in matching_reports {
        let schemas = report_schemas(report)?;
        assert!(
            schemas.contains(&expected_schema),
            "default search omitted the synthetic schema; survivors={schemas:#?}"
        );
    }
    Ok(())
}

fn record_candidate<'a>(
    outcome: &'a super::RecoveryExecutionOutcome,
    expected_frames: &[u64],
) -> TestResult<&'a l2_workbench::recovery::RecoveryCandidate> {
    outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::RecordDiscovery
                && candidate
                    .inputs()
                    .iter()
                    .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
                    .copied()
                    .collect::<Vec<_>>()
                    == expected_frames
        })
        .ok_or_else(|| "record discovery candidate is missing".into())
}

fn candidate_frame_ids(candidate: &l2_workbench::recovery::RecoveryCandidate) -> Vec<u64> {
    candidate
        .inputs()
        .iter()
        .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
        .copied()
        .collect()
}

fn expected_record_assembly_schedules(
    schemas: &[RecordSchema],
    session_frames: &[Vec<u64>],
) -> TestResult<std::collections::BTreeSet<(String, Vec<u64>)>> {
    let mut schedules = std::collections::BTreeSet::new();
    for schema in schemas {
        let schema_key = serde_json::to_string(schema)?;
        for frames in session_frames {
            schedules.insert((schema_key.clone(), frames.clone()));
        }
    }
    Ok(schedules)
}

fn scheduled_record_assemblies(
    outcome: &super::RecoveryExecutionOutcome,
    cohort_frame_ids: &std::collections::BTreeSet<u64>,
) -> TestResult<std::collections::BTreeSet<(String, Vec<u64>)>> {
    let mut schedules = std::collections::BTreeSet::new();
    for candidate in &outcome.candidates {
        let RecoveryTask::AssembleRecords(schema) = candidate.task() else {
            continue;
        };
        let frame_ids = candidate_frame_ids(candidate);
        if frame_ids.is_empty()
            || frame_ids
                .iter()
                .any(|frame_id| !cohort_frame_ids.contains(frame_id))
        {
            continue;
        }
        schedules.insert((serde_json::to_string(schema)?, frame_ids));
    }
    Ok(schedules)
}

fn assert_scheduled_record_assemblies(
    outcome: &super::RecoveryExecutionOutcome,
    schemas: &[RecordSchema],
    session_frames: &[Vec<u64>],
    cohort_frame_ids: &std::collections::BTreeSet<u64>,
) -> TestResult<()> {
    let observed = scheduled_record_assemblies(outcome, cohort_frame_ids)?;
    let expected = expected_record_assembly_schedules(schemas, session_frames)?;
    assert!(
        observed == expected,
        "record assembly schedule mismatch: observed {} schema/session pairs, expected {}",
        observed.len(),
        expected.len()
    );
    Ok(())
}

fn frame_input_run(case: &Case, frame_id: u64) -> TestResult<u64> {
    case.nodes()
        .iter()
        .find(|node| node.id == frame_id)
        .and_then(|node| node.details.get("input_node"))
        .and_then(Value::as_u64)
        .ok_or_else(|| std::io::Error::other("framed input run is missing").into())
}

fn candidate_run_ids(
    case: &Case,
    candidate: &l2_workbench::recovery::RecoveryCandidate,
) -> TestResult<std::collections::BTreeSet<u64>> {
    candidate_frame_ids(candidate)
        .into_iter()
        .map(|frame_id| frame_input_run(case, frame_id))
        .collect()
}

fn fill_case_nodes_to_quota(case: &mut Case) -> TestResult<()> {
    while case.nodes().len() < l2_workbench::evidence::MAX_NODES {
        case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    }
    Ok(())
}

fn fill_case_edges_to_quota(case: &mut Case) -> TestResult<()> {
    let node = case.add_node("unrelated_evidence", None, Vec::new(), json!({}))?;
    while case.edges().len() < l2_workbench::evidence::MAX_EDGES {
        case.add_edge(Edge {
            from: node,
            to: node,
            relation: "quota_fixture".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "Synthetic edges fill the retained evidence quota".to_owned(),
        })?;
    }
    Ok(())
}

fn assert_record_report_quota_rollback(
    case: &Case,
    before: &Case,
    outcome: &super::RecoveryExecutionOutcome,
    expected_frames: &[u64],
    resource: l2_workbench::recovery::RecoveryResource,
) -> TestResult<()> {
    assert!(
        case == before,
        "a rejected report transaction leaves no partial evidence"
    );
    let candidate = record_candidate(outcome, expected_frames)?;
    assert!(matches!(
        candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: exhausted,
                requested: 1,
                ..
            },
            ..
        } if *exhausted == resource
    ));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery,
            input_node_ids,
            resource: exhausted,
            requested: 1,
            ..
        } if input_node_ids == expected_frames && *exhausted == resource
    )));
    assert!(!case.nodes().iter().any(|node| node.kind == REPORT_KIND));
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::AssembleRecords(_)))
    );
    assert!(!super::report_details_complete(&outcome.omissions));
    Ok(())
}

fn run_record_discovery_only(
    case: &mut Case,
    plan: &RecoveryPlan,
    policy: &super::RecoveryExecutionPolicy,
) -> TestResult<super::RecoveryExecutionOutcome> {
    let case_index = super::CaseIndex::new(case)?;
    let mut executor = super::Executor {
        case,
        plan,
        policy: policy.clone(),
        coordinator: l2_workbench::recovery::RecoveryCoordinator::new(policy.resources),
        case_index,
        candidate_ids: Vec::new(),
        candidate_index: std::collections::HashSet::new(),
        snapshot_candidates: true,
        job: None,
        validated_artifacts: std::collections::HashSet::new(),
        transform_cohorts: Vec::new(),
        derived_discovery: super::derived_discovery::DerivedDiscovery::default(),
        transform_discoveries: std::collections::HashMap::new(),
        framing_selection_bases: std::collections::HashMap::new(),
        framing_discoveries: std::collections::HashMap::new(),
        record_discoveries: std::collections::HashMap::new(),
        record_discovery_context_by_report: std::collections::HashMap::new(),
        deferred_record_discovery_plan: None,
        record_schema_report_links: std::collections::HashMap::new(),
        record_schema_associations_charged: 0,
        record_phase_work_charged: 0,
        pending_record_assemblies: std::collections::VecDeque::new(),
        pending_record_assembly_count: 0,
        relational_samples: super::RelationalSampleCollections::default(),
        relational_discoveries: std::collections::HashMap::new(),
        transform_proposal_receipts: std::collections::HashMap::new(),
        omissions: Vec::new(),
        complete_negative_transform_searches: 0,
        cycle_skips: 0,
    };
    executor.enqueue_record_discovery_if_enabled()?;
    assert!(
        executor.coordinator.pop_next()?.is_none(),
        "raw record discovery waits behind the relational barrier"
    );
    assert!(
        executor.enqueue_deferred_record_discovery()?,
        "deferred raw record discovery should be admitted after the barrier"
    );
    let candidate_id = executor
        .coordinator
        .pop_next()?
        .ok_or("record discovery candidate was not queued")?;
    executor.run_record_discovery(candidate_id)?;
    Ok(super::finish_executor(executor)?)
}

fn assert_cohort_record_scheduling(
    case: &Case,
    outcome: &super::RecoveryExecutionOutcome,
    candidate: &l2_workbench::recovery::RecoveryCandidate,
    sessions: &[&UnframedSession],
    scope: &str,
    limits: l2_workbench::protocol::RecordSchemaProposalLimits,
) -> TestResult<Vec<u64>> {
    let expected_runs = sessions
        .iter()
        .map(|session| session.run_node)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(expected_runs.len(), 2);
    assert_eq!(candidate_run_ids(case, candidate)?, expected_runs);

    let frame_ids = candidate_frame_ids(candidate);
    assert_eq!(frame_ids.len(), 6);
    let frames_by_run = cohort_frames_by_run(case, &frame_ids)?;
    assert_eq!(
        frames_by_run
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        expected_runs
    );
    assert!(frames_by_run.values().all(|frames| frames.len() == 3));

    for session in sessions {
        let direction = case
            .edges()
            .iter()
            .find(|edge| edge.to == session.run_node && edge.relation == "contains")
            .map(|edge| edge.from)
            .ok_or("session direction edge is missing")?;
        assert!(case.edges().iter().any(|edge| {
            edge.from == session.episode_node && edge.to == direction && edge.relation == "contains"
        }));
    }

    let report_node_id = report_node(candidate)?;
    let report = decode_report(case, report_node_id)?;
    let schemas = assert_cohort_record_report(
        case,
        report_node_id,
        &report,
        &frame_ids,
        sessions,
        scope,
        limits,
    )?;
    let expected_session_frames = frames_by_run.values().cloned().collect::<Vec<_>>();
    let cohort_frame_ids = frame_ids.iter().copied().collect();
    assert_scheduled_record_assemblies(
        outcome,
        &schemas,
        &expected_session_frames,
        &cohort_frame_ids,
    )?;
    Ok(frame_ids)
}

fn cohort_frames_by_run(
    case: &Case,
    frame_ids: &[u64],
) -> TestResult<std::collections::BTreeMap<u64, Vec<u64>>> {
    let mut frames_by_run = std::collections::BTreeMap::<u64, Vec<u64>>::new();
    for frame_id in frame_ids {
        frames_by_run
            .entry(frame_input_run(case, *frame_id)?)
            .or_default()
            .push(*frame_id);
    }
    Ok(frames_by_run)
}

fn assert_cohort_record_report(
    case: &Case,
    report_node_id: u64,
    report: &Value,
    frame_ids: &[u64],
    sessions: &[&UnframedSession],
    scope: &str,
    limits: l2_workbench::protocol::RecordSchemaProposalLimits,
) -> TestResult<Vec<RecordSchema>> {
    assert_eq!(
        report.pointer("/cohort/scope/interface"),
        Some(&json!(scope))
    );
    assert_eq!(
        report.pointer("/cohort/framing_rule"),
        Some(&json!({"kind":"fixed_size","bytes":14}))
    );
    assert_eq!(report.get("version"), Some(&json!(2)));
    let report_frames = report
        .pointer("/input_frame_refs")
        .and_then(Value::as_array)
        .ok_or("record report input references are missing")?
        .iter()
        .map(|reference| {
            let fields = reference
                .as_array()
                .ok_or("record report input reference is not a pair")?;
            let node_id = fields
                .first()
                .and_then(Value::as_u64)
                .ok_or("record report frame node reference is missing")?;
            let partition = fields
                .get(1)
                .and_then(Value::as_str)
                .ok_or("record report frame partition is missing")?;
            Ok((node_id, partition))
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .map(|(node_id, _)| node_id)
        .collect::<Vec<_>>();
    assert_eq!(report_frames, frame_ids);
    assert_report_frame_references(case, report, report_node_id, frame_ids)?;

    let session_messages = sessions
        .iter()
        .map(|session| session.messages.clone())
        .collect::<Vec<_>>();
    let (schemas, _) = typed_survivor_schemas(&session_messages, limits)?;
    assert!(schemas.len() > 1, "fixture should retain competing schemas");
    let report_schemas = report
        .pointer("/schema_discovery/surviving")
        .and_then(Value::as_array)
        .ok_or("record report surviving schemas are missing")?
        .iter()
        .map(|hypothesis| {
            hypothesis
                .get("schema")
                .cloned()
                .ok_or_else(|| std::io::Error::other("surviving schema detail is missing"))
                .and_then(|value| {
                    serde_json::from_value::<l2_workbench::protocol::RecordSchema>(value)
                        .map_err(std::io::Error::other)
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(report_schemas, schemas);
    Ok(schemas)
}

#[test]
fn record_discovery_uses_only_materialized_frames_and_keeps_sessions_whole() -> TestResult<()> {
    let mut fixture = build_primary_fixture()?;
    let policy = normal_policy(&fixture.case)?;
    let outcome = execute(&mut fixture.case, &recovery_plan(), &policy)?;
    let candidate = record_candidate(&outcome, &fixture.frame_nodes)?;
    let node_id = report_node(candidate)?;
    let report = decode_report(&fixture.case, node_id)?;

    assert_primary_report(&report, &fixture, node_id)?;
    assert_report_is_evidence_only(&fixture.case, &outcome, node_id);
    assert_primary_omissions(&outcome, &fixture)?;
    assert!(!super::discovery_input_coverage_complete(
        &outcome.omissions
    ));
    assert!(super::report_details_complete(&outcome.omissions));
    Ok(())
}

#[test]
fn post_materialization_discovery_schedules_every_surviving_schema_per_conversation()
-> TestResult<()> {
    let (mut case, sessions) = build_post_materialization_fixture()?;
    assert!(
        case.nodes()
            .iter()
            .all(|node| node.kind != "custom_protocol_frame")
    );

    let policy = normal_policy(&case)?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 14 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy)?;

    let discovery_candidates = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .collect::<Vec<_>>();
    assert_eq!(discovery_candidates.len(), 2);
    let mut discovery_by_runs = std::collections::BTreeMap::new();
    for candidate in discovery_candidates {
        let run_ids = candidate_run_ids(&case, candidate)?;
        assert!(
            discovery_by_runs.insert(run_ids, candidate).is_none(),
            "a session cohort was scheduled more than once"
        );
    }
    let limits = policy.record_schema_proposal_limits;
    for scope in ["conversation-a", "conversation-b"] {
        let cohort_sessions = sessions
            .iter()
            .filter(|session| session.scope == scope)
            .collect::<Vec<_>>();
        let run_ids = cohort_sessions
            .iter()
            .map(|session| session.run_node)
            .collect::<std::collections::BTreeSet<_>>();
        let candidate = discovery_by_runs
            .get(&run_ids)
            .copied()
            .ok_or("record discovery did not preserve the exact conversation cohort")?;
        assert_cohort_record_scheduling(
            &case,
            &outcome,
            candidate,
            &cohort_sessions,
            scope,
            limits,
        )?;
    }
    let training_a = sessions
        .iter()
        .find(|session| session.scope == "conversation-a")
        .ok_or("conversation A training session is missing")?;
    let training_b = sessions
        .iter()
        .find(|session| session.scope == "conversation-b")
        .ok_or("conversation B training session is missing")?;
    assert_eq!(training_a.messages, training_b.messages);
    assert_ne!(training_a.run_node, training_b.run_node);
    Ok(())
}

fn build_post_materialization_fixture() -> TestResult<(Case, Vec<UnframedSession>)> {
    let mut case = Case::new();
    let source = capture(&mut case, "post-framing-record-discovery")?;
    let sessions = add_unframed_sessions(
        &mut case,
        &source,
        vec![
            (
                "conversation-a",
                vec![
                    vec![
                        record(b"\x19\x82\xd1", 1, b"alpha"),
                        record(b"\x19\x82\xd1", 2, b"bravo"),
                        record(b"\x19\x82\xd1", 3, b"delta"),
                    ],
                    vec![
                        record(b"\x19\x82\xd1", 1, b"echo!"),
                        record(b"\x19\x82\xd1", 2, b"foxtg"),
                        record(b"\x19\x82\xd1", 3, b"hotel"),
                    ],
                ],
            ),
            (
                "conversation-b",
                vec![
                    vec![
                        record(b"\x19\x82\xd1", 1, b"alpha"),
                        record(b"\x19\x82\xd1", 2, b"bravo"),
                        record(b"\x19\x82\xd1", 3, b"delta"),
                    ],
                    vec![
                        record(b"\x19\x82\xd1", 1, b"peach"),
                        record(b"\x19\x82\xd1", 2, b"grape"),
                        record(b"\x19\x82\xd1", 3, b"berry"),
                    ],
                ],
            ),
        ],
    )?;
    Ok((case, sessions))
}

#[test]
fn automatic_framing_materialization_reaches_the_record_discovery_barrier() -> TestResult<()> {
    let mut case = Case::new();
    let source = capture(&mut case, "automatic-record-barrier")?;
    let context = add_session_context(&mut case, "automatic-scope", 1, 0, 8)?;
    let run = add_tcp_run_in_context(&mut case, &source, context.direction_node, 1, b"one|two|")?;
    let policy = normal_policy(&case)?;
    let plan = RecoveryPlan {
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy)?;

    assert!(outcome.resources.record_phase_work_charged > 0);
    assert_eq!(
        outcome.resources.record_phase_work_remaining,
        outcome
            .resources
            .max_record_phase_work
            .checked_sub(outcome.resources.record_phase_work_charged)
            .ok_or("record phase work exceeded its immutable allowance")?
    );
    assert!(!outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery | RecoveryTask::AssembleRecords(_),
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            ..
        }
    )));

    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.task() == &RecoveryTask::FramingDiscovery)
        .ok_or("automatic framing discovery candidate is missing")?;
    assert_eq!(
        discovery
            .inputs()
            .iter()
            .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
            .copied()
            .collect::<Vec<_>>(),
        [run]
    );
    let record_discoveries = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .collect::<Vec<_>>();
    assert!(!record_discoveries.is_empty());
    let materialized_frames = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .map(|node| node.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!materialized_frames.is_empty());
    for candidate in record_discoveries {
        let frame_ids = candidate
            .inputs()
            .iter()
            .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!frame_ids.is_empty());
        assert!(frame_ids.is_subset(&materialized_frames));
        for frame_id in frame_ids {
            assert!(case.edges().iter().any(|edge| {
                edge.to == frame_id
                    && edge.relation == "materialized"
                    && case.nodes().iter().any(|node| {
                        node.id == edge.from && node.kind == "custom_protocol_framing_receipt"
                    })
            }));
        }
    }
    Ok(())
}

#[test]
fn single_session_relational_cohort_is_informational_and_does_not_block_recovery() -> TestResult<()>
{
    let mut case = Case::new();
    let source = capture(&mut case, "single-session-relational-input")?;
    let wire = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\nPK\x03\x04";
    let context = add_session_context(&mut case, "single-session-http", 1, 0, wire.len())?;
    add_tcp_run_in_context(&mut case, &source, context.direction_node, 1, wire)?;

    let summary =
        recover_case_with_job(&mut case, RecoveryProfile::Normal, 64 * 1024 * 1024, None)?;
    let relational_reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_relational_transform_report")
        .filter_map(|node| node.blob.as_deref())
        .filter_map(|blob_id| case.blob(blob_id))
        .filter_map(|blob| serde_json::from_slice::<Value>(&blob.bytes).ok())
        .collect::<Vec<_>>();

    assert!(
        !relational_reports.is_empty(),
        "the observed one-session cohort should have an informational relational report"
    );
    assert!(
        relational_reports
            .iter()
            .all(|report| report.get("sessions_available").and_then(Value::as_u64) == Some(1)),
        "the report should describe the available single-session evidence"
    );
    assert!(
        relational_reports.iter().all(|report| {
            report.get("result").and_then(Value::as_str)
                == Some("not_eligible_for_independent_session_checks")
        }),
        "single-session cohorts should be reported as ineligible without implying a search ran"
    );
    assert!(
        !summary.omissions.iter().any(|omission| matches!(
            omission,
            super::RecoveryOmission::RelationalTransformAnalysis { .. }
        )),
        "lack of an independent held-out session is informational and must not block recovery"
    );
    Ok(())
}

#[test]
fn default_recovery_learns_and_applies_session_relative_record_transform() -> TestResult<()> {
    let fixture = build_session_relative_fixture()?;
    let mut case = fixture.case;
    let plaintext = fixture.plaintext;
    let episode_nodes = fixture.episode_nodes;
    let summary =
        match recover_case_with_job(&mut case, RecoveryProfile::Normal, 64 * 1024 * 1024, None) {
            Ok(summary) => summary,
            Err(error) => {
                let details = format!("recovery failed before report assertions: {error}");
                let snapshot = save_case_snapshot(
                    &case,
                    "l2-session-relative-recovery-error-",
                    Some(&details),
                )?;
                return Err(format!("{details}; snapshot={snapshot:?}").into());
            }
        };

    if !summary.discovery.input_coverage_complete {
        let omissions = summary.omissions.iter().take(8).collect::<Vec<_>>();
        let record_reports = session_relative_record_diagnostics(&case);
        let details = format!(
            "input_coverage_complete=false\nomissions={omissions:#?}\nrecord_reports={:#?}",
            record_reports.iter().take(8).collect::<Vec<_>>()
        );
        let snapshot = save_case_snapshot(&case, "l2-session-relative-coverage-", Some(&details))?;
        return Err(format!("{details}; snapshot={snapshot:?}").into());
    }
    assert_session_relative_recovery(&case, &plaintext, &episode_nodes, &summary)
}

fn assert_session_relative_recovery(
    case: &Case,
    plaintext: &[u8],
    episode_nodes: &[u64],
    summary: &super::RecoveryRunSummary,
) -> TestResult<()> {
    let relational_reports = load_relational_reports(case);
    let record_diagnostics = session_relative_record_diagnostics(case);
    let report_failure_snapshot = if relational_reports.is_empty() {
        let omissions = summary.omissions.iter().take(8).collect::<Vec<_>>();
        let details = format!(
            "input_coverage_complete={}\nomissions={omissions:#?}\nrecord_reports={record_diagnostics:#?}\n",
            summary.discovery.input_coverage_complete
        );
        Some(save_case_snapshot(
            case,
            "l2-relational-synthetic-failure-",
            Some(&details),
        )?)
    } else {
        None
    };
    assert!(
        !relational_reports.is_empty(),
        "relational analysis was not scheduled; omissions={:?}; record_reports={record_diagnostics:#?}; snapshot={report_failure_snapshot:?}",
        summary.omissions.iter().take(8).collect::<Vec<_>>(),
    );

    let Some((relational_report_node_id, relational_report)) = select_session_relative_report(case)
    else {
        return Err("relational report bytes are unavailable after scheduling".into());
    };
    let first_record_receipt_id = case
        .nodes()
        .iter()
        .find(|node| node.kind == "record_parse_receipt")
        .map(|node| node.id)
        .ok_or("no record parse receipt was retained")?;
    assert!(
        relational_report_node_id < first_record_receipt_id,
        "session-relative transform evidence should be tried before raw schema assemblies"
    );

    let report_summary =
        session_relative_report_summary(relational_report_node_id, &relational_report);
    assert_session_relative_output(
        case,
        plaintext,
        summary,
        &report_summary,
        &record_diagnostics,
    )?;
    assert_session_relative_report(&relational_report, episode_nodes, &report_summary)?;
    assert_relational_schema_handoff(
        case,
        relational_report_node_id,
        &relational_report,
        plaintext,
    )?;
    assert_decoded_frames_feed_record_parser(case, &record_diagnostics);
    Ok(())
}

fn assert_session_relative_output(
    case: &Case,
    plaintext: &[u8],
    summary: &super::RecoveryRunSummary,
    report_summary: &Value,
    record_diagnostics: &[Value],
) -> TestResult<()> {
    let exact_output_recovered = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "relational_transform_output")
        .filter_map(|node| node.blob.as_deref())
        .filter_map(|blob_id| case.blob(blob_id))
        .any(|blob| blob.bytes.as_slice() == plaintext);
    let failure_snapshot = if exact_output_recovered {
        None
    } else {
        let omissions = summary.omissions.iter().take(8).collect::<Vec<_>>();
        let candidate_parents = session_relative_candidate_parents(case);
        let failure_details = format!(
            "input_coverage_complete={}\nomissions={omissions:#?}\nreport={report_summary:#?}\ntransform_reports={:#?}\nrecord_reports={record_diagnostics:#?}\ncandidate_parents={candidate_parents:#?}\n",
            summary.discovery.input_coverage_complete,
            session_relative_transform_diagnostics(case)
        );
        Some(save_case_snapshot(
            case,
            "l2-relational-synthetic-failure-",
            Some(&failure_details),
        )?)
    };
    assert!(
        exact_output_recovered,
        "the exact PNG should be assembled across the four independently seeded sessions; report={report_summary:#?}; snapshot={failure_snapshot:?}"
    );
    Ok(())
}

fn assert_session_relative_report(
    report: &Value,
    episode_nodes: &[u64],
    report_summary: &Value,
) -> TestResult<()> {
    let heldout_sessions = report
        .get("heldout_sessions")
        .and_then(Value::as_array)
        .ok_or("relational report omitted its frozen held-out sessions")?;
    assert!(
        heldout_sessions
            .iter()
            .any(|session| session.as_u64() == episode_nodes.get(2).copied()),
        "the artifact prefix belongs to a held-out session"
    );
    assert!(
        report
            .get("application_evidence_checks")
            .and_then(Value::as_array)
            .is_some_and(|checks| checks
                .iter()
                .any(|check| { check.get("artifact_validated") == Some(&Value::Bool(true)) })),
        "the selected cohort report should retain evidence for the exact cross-session artifact; report={report_summary:#?}"
    );
    Ok(())
}

fn assert_relational_schema_handoff(
    case: &Case,
    report_node_id: u64,
    report: &Value,
    expected_artifact: &[u8],
) -> TestResult<()> {
    let checks = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .ok_or("relational report omitted application evidence")?;
    let accepted_check = checks
        .iter()
        .find(|check| {
            check.get("artifact_validated") == Some(&Value::Bool(true))
                && check
                    .get("accepted_record_schema")
                    .is_some_and(Value::is_object)
        })
        .ok_or("relational report has no exact artifact acceptance")?;
    let accepted = accepted_check
        .get("accepted_record_schema")
        .ok_or("exact artifact acceptance omitted its frozen record schema")?;
    let schema = accepted
        .get("schema")
        .ok_or("accepted record schema is missing")?;
    let strategy = accepted
        .get("strategy")
        .and_then(Value::as_str)
        .ok_or("accepted record schema omitted its discovery strategy")?;
    assert!(matches!(strategy, "fixed_layout" | "repeated_boundaries"));
    let frame_indices = accepted
        .get("frame_indices")
        .and_then(Value::as_array)
        .ok_or("accepted record schema omitted full frame membership")?;
    let frame_identities = accepted
        .get("frame_identities")
        .and_then(Value::as_array)
        .ok_or("accepted record schema omitted frame identities")?;
    assert!(!frame_indices.is_empty());
    assert_eq!(frame_indices.len(), frame_identities.len());
    for (position, (index, identity)) in frame_indices.iter().zip(frame_identities).enumerate() {
        assert_eq!(index.as_u64(), u64::try_from(position).ok());
        assert_eq!(
            identity.get("frame_index").and_then(Value::as_u64),
            u64::try_from(position).ok()
        );
        assert!(
            identity
                .get("frame_byte_length")
                .and_then(Value::as_u64)
                .is_some_and(|length| length > 0)
        );
        assert!(
            identity
                .get("frame_bytes_sha256")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.len() == 64)
        );
    }

    let expected_sha256 = l2_workbench::sha256(expected_artifact);
    let artifact_receipt = accepted
        .get("artifact_receipt")
        .ok_or("accepted schema omitted the exact assembled group receipt")?;
    assert_eq!(
        artifact_receipt
            .get("output_sha256")
            .and_then(Value::as_str),
        Some(expected_sha256.as_str())
    );
    assert_eq!(
        artifact_receipt
            .get("output_length")
            .and_then(Value::as_u64),
        u64::try_from(expected_artifact.len()).ok()
    );

    let selected_receipts = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.from == report_node_id && edge.relation == "record_schema_selected_from"
        })
        .filter_map(|edge| case.node(edge.to))
        .filter(|node| node.kind == "record_parse_receipt")
        .collect::<Vec<_>>();
    assert!(
        !selected_receipts.is_empty(),
        "the frozen relational schema was not scheduled for final assembly"
    );
    let expected_members = frame_identities
        .iter()
        .map(|identity| {
            Ok((
                identity
                    .get("input_node_id")
                    .and_then(Value::as_u64)
                    .ok_or("accepted frame omitted its input identity")?,
                identity
                    .pointer("/context/session")
                    .and_then(Value::as_u64)
                    .ok_or("accepted frame omitted its session identity")?,
                identity
                    .get("session_order")
                    .and_then(Value::as_u64)
                    .ok_or("accepted frame omitted its session order")?,
                identity
                    .get("stream_offset")
                    .and_then(Value::as_u64)
                    .ok_or("accepted frame omitted its stream offset")?,
                identity
                    .get("frame_byte_length")
                    .and_then(Value::as_u64)
                    .ok_or("accepted frame omitted its exact byte length")?,
                identity
                    .get("frame_bytes_sha256")
                    .and_then(Value::as_str)
                    .ok_or("accepted frame omitted its exact byte digest")?
                    .to_owned(),
            ))
        })
        .collect::<TestResult<std::collections::BTreeSet<_>>>()?;

    for receipt_node in selected_receipts {
        let receipt_blob_id = receipt_node
            .blob
            .as_deref()
            .ok_or("selected record receipt has no serialized evidence")?;
        let receipt_blob = case
            .blob(receipt_blob_id)
            .ok_or("selected record receipt bytes are missing")?;
        let receipt: Value = serde_json::from_slice(&receipt_blob.bytes)?;
        let inputs = receipt
            .get("inputs")
            .and_then(Value::as_array)
            .ok_or("record receipt omitted its full input list")?;
        assert_eq!(inputs.len(), expected_members.len());
        for input in inputs {
            let frame_node_id = input
                .get("input_node")
                .and_then(Value::as_u64)
                .ok_or("record receipt input omitted its frame node")?;
            let frame_node = case
                .node(frame_node_id)
                .filter(|node| node.kind == "relational_decoded_frame")
                .ok_or("record receipt did not retain a relational decoded frame")?;
            let actual_member = (
                frame_node
                    .details
                    .get("input_frame_node_id")
                    .and_then(Value::as_u64)
                    .ok_or("decoded frame omitted its source input identity")?,
                frame_node
                    .details
                    .get("session_node_id")
                    .and_then(Value::as_u64)
                    .ok_or("decoded frame omitted its session identity")?,
                frame_node
                    .details
                    .get("session_order")
                    .and_then(Value::as_u64)
                    .ok_or("decoded frame omitted its session order")?,
                frame_node
                    .details
                    .get("stream_offset")
                    .and_then(Value::as_u64)
                    .ok_or("decoded frame omitted its stream offset")?,
                u64::try_from(
                    frame_node
                        .blob
                        .as_deref()
                        .and_then(|blob_id| case.blob(blob_id))
                        .ok_or("decoded frame bytes are missing")?
                        .bytes
                        .len(),
                )?,
                frame_node
                    .blob
                    .as_deref()
                    .and_then(|blob_id| blob_id.strip_prefix("sha256:"))
                    .ok_or("decoded frame blob digest is missing")?
                    .to_owned(),
            );
            assert!(expected_members.contains(&actual_member));
            let parse_schema = input
                .pointer("/parse/schema")
                .ok_or("final record parse did not retain its schema")?;
            assert_eq!(parse_schema, schema);
        }
        let receipt_members = inputs
            .iter()
            .filter_map(|input| input.get("input_node").and_then(Value::as_u64))
            .collect::<std::collections::BTreeSet<_>>();
        let expected_frame_nodes = inputs
            .iter()
            .filter_map(|input| input.get("input_node").and_then(Value::as_u64))
            .count();
        assert_eq!(receipt_members.len(), expected_frame_nodes);

        let groups = receipt
            .pointer("/assembly/groups")
            .and_then(Value::as_array)
            .ok_or("final assembly receipt omitted its group mappings")?;
        assert!(groups.iter().any(|group| {
            group.get("output_sha256").and_then(Value::as_str) == Some(expected_sha256.as_str())
                && group.get("output_length").and_then(Value::as_u64)
                    == u64::try_from(expected_artifact.len()).ok()
        }));
    }
    Ok(())
}

fn assert_decoded_frames_feed_record_parser(case: &Case, record_diagnostics: &[Value]) {
    let decoded_frames = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "relational_decoded_frame")
        .map(|node| node.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        !decoded_frames.is_empty(),
        "supported relational rules should preserve decoded payloads inside their original frames; relational={:#?}",
        session_relative_transform_diagnostics(case)
    );
    assert!(
        case.nodes().iter().any(|node| {
            matches!(node.kind.as_str(), "record_candidate" | "record_object")
                && case
                    .edges()
                    .iter()
                    .any(|edge| edge.to == node.id && decoded_frames.contains(&edge.from))
        }),
        "decoded frames should feed the strict record parser and assembly path; record_reports={record_diagnostics:#?}; candidate_parents={:#?}",
        session_relative_candidate_parents(case)
    );
}

pub(super) fn build_session_relative_fixture() -> TestResult<SessionRelativeFixture> {
    const SPLIT_NUMERATORS: [usize; 4] = [1, 3, 1, 2];
    const ARTIFACT_PART_BY_SESSION: [usize; 4] = [2, 3, 0, 1];

    let mut case = Case::new();
    let source = capture(&mut case, "independent-relational-recovery")?;
    let plaintext = synthetic_png([31, 83, 137])?;
    let part_boundaries = [
        0,
        plaintext.len() / 5,
        plaintext.len() * 2 / 5,
        plaintext.len() * 3 / 5,
        plaintext.len(),
    ];
    let mut episode_nodes = Vec::new();
    episode_nodes
        .try_reserve_exact(ARTIFACT_PART_BY_SESSION.len())
        .map_err(|_| "synthetic session list allocation failed")?;

    // Each session carries one shuffled section and a different stream seed
    for (session_index, artifact_part) in ARTIFACT_PART_BY_SESSION.iter().copied().enumerate() {
        let split_numerator = *SPLIT_NUMERATORS
            .get(session_index)
            .ok_or("synthetic split ratio is unavailable")?;
        let wire = session_relative_session_wire(
            &plaintext,
            &part_boundaries,
            session_index,
            artifact_part,
            split_numerator,
        )?;
        let session_offset = u64::try_from(session_index)?
            .checked_mul(10)
            .ok_or("synthetic packet number overflow")?;
        let packet = 10_u64
            .checked_add(session_offset)
            .ok_or("synthetic packet number overflow")?;
        let context = add_session_context(
            &mut case,
            "independent-relational-scope",
            packet,
            0,
            wire.len(),
        )?;
        episode_nodes.push(context.episode_node);
        add_tcp_run_in_context(&mut case, &source, context.direction_node, packet, &wire)?;
    }

    Ok(SessionRelativeFixture {
        case,
        plaintext,
        episode_nodes,
    })
}

fn session_relative_session_wire(
    plaintext: &[u8],
    part_boundaries: &[usize],
    session_index: usize,
    artifact_part: usize,
    split_numerator: usize,
) -> TestResult<Vec<u8>> {
    use l2_workbench::derivation::{
        CounterByteOrder, CounterWidth, OperandRef, Operation, Recipe, SeedCounterOrder, run,
    };

    let session_byte = u8::try_from(session_index)?;
    let seed = (0..8_u8)
        .map(|byte| byte.wrapping_add(session_byte.wrapping_mul(19)))
        .collect::<Vec<_>>();
    let part_start = *part_boundaries
        .get(artifact_part)
        .ok_or("synthetic artifact start is unavailable")?;
    let part_end = *part_boundaries
        .get(
            artifact_part
                .checked_add(1)
                .ok_or("artifact part overflow")?,
        )
        .ok_or("synthetic artifact end is unavailable")?;
    let session_part = plaintext
        .get(part_start..part_end)
        .ok_or("synthetic artifact split is invalid")?;
    let scaled_split = session_part
        .len()
        .checked_mul(split_numerator)
        .ok_or("synthetic payload split overflow")?
        / 4;
    let split = scaled_split.clamp(1, session_part.len().saturating_sub(1));
    let fragment_ranges = [0..split, split..session_part.len()];
    let mut wire = Vec::new();

    // Seed and payload markers preserve the fixture's independent record grammar
    let mut seed_payload = vec![0x6b];
    seed_payload.extend_from_slice(&seed);
    wire.extend_from_slice(&synthetic_protocol_record([0x1a, 0x73], 0, &seed_payload)?);

    let mut payload_records = Vec::with_capacity(fragment_ranges.len());
    for (fragment_index, range) in fragment_ranges.into_iter().enumerate() {
        let chunk = session_part
            .get(range)
            .ok_or("synthetic plaintext split is invalid")?;
        let encrypted = run(
            chunk,
            &Recipe {
                steps: vec![Operation::Sha256CounterXor {
                    seed: OperandRef::from(seed.clone()),
                    initial_counter: 0,
                    counter_width: CounterWidth::OneByte,
                    counter_byte_order: CounterByteOrder::BigEndian,
                    seed_order: SeedCounterOrder::SeedThenCounter,
                }],
                constraints: Vec::new(),
            },
        )?;
        let mut payload = vec![0x4d];
        payload.extend_from_slice(&encrypted.output);
        let sequence = u16::try_from(artifact_part * 2 + fragment_index)?;
        payload_records.push(synthetic_protocol_record([0xb2, 0x39], sequence, &payload)?);
    }
    if session_index.is_multiple_of(2) {
        for payload_record in payload_records {
            wire.extend_from_slice(&payload_record);
        }
    } else {
        for payload_record in payload_records.into_iter().rev() {
            wire.extend_from_slice(&payload_record);
        }
    }

    Ok(wire)
}

fn session_relative_record_diagnostics(case: &Case) -> Vec<Value> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == "recovery_record_discovery_report")
        .filter_map(|node| node.blob.as_deref())
        .filter_map(|blob_id| case.blob(blob_id))
        .filter_map(|blob| serde_json::from_slice::<Value>(&blob.bytes).ok())
        .take(8)
        .map(|report| {
            let surviving = report
                .pointer("/schema_discovery/surviving")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(1)
                        .map(|item| {
                            json!({
                                "data_offset":item.pointer("/schema/data_offset"),
                                "identifier":item.pointer("/schema/identifier"),
                                "sequence":item.pointer("/schema/sequence"),
                                "length":item.pointer("/schema/length"),
                            })
                        })
                        .collect::<Vec<_>>()
                });
            json!({
                "result":report.get("result"),
                "no_candidate_reason":report.get("no_candidate_reason"),
                "partition":report.get("partition"),
                "application":report.get("application"),
                "surviving":surviving,
            })
        })
        .collect()
}

fn session_relative_candidate_parents(case: &Case) -> Vec<Value> {
    case.nodes()
        .iter()
        .filter(|node| matches!(node.kind.as_str(), "record_candidate" | "record_object"))
        .filter_map(|node| {
            let parents = case
                .edges()
                .iter()
                .filter(|edge| edge.to == node.id)
                .filter_map(|edge| {
                    case.node(edge.from)
                        .map(|parent| (parent.id, parent.kind.as_str()))
                })
                .collect::<Vec<_>>();
            let decoded_parent_count = parents
                .iter()
                .filter(|(_, kind)| *kind == "relational_decoded_frame")
                .count();
            (decoded_parent_count > 0).then(|| {
                json!({
                    "node":node.id,
                    "parents":parents.iter().take(4).collect::<Vec<_>>(),
                    "decoded_parent_count":decoded_parent_count,
                    "has_relational_hypothesis":node.details.get("relational_hypothesis").is_some(),
                })
            })
        })
        .take(8)
        .collect()
}

fn select_session_relative_report(case: &Case) -> Option<(u64, Value)> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == "recovery_relational_transform_report")
        .filter_map(|node| {
            node.blob
                .as_deref()
                .and_then(|blob_id| case.blob(blob_id))
                .and_then(|blob| serde_json::from_slice::<Value>(&blob.bytes).ok())
                .map(|report| (node.id, report))
        })
        .max_by_key(|(node_id, report)| {
            (
                report
                    .get("application_evidence_checks")
                    .and_then(Value::as_array)
                    .is_some_and(|checks| {
                        checks.iter().any(|check| {
                            check.get("artifact_validated") == Some(&Value::Bool(true))
                        })
                    }),
                report
                    .pointer("/output_application/applied_rules")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
                report
                    .get("input_sample_node_ids")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                report
                    .get("candidate_count_examined")
                    .and_then(Value::as_u64)
                    .unwrap_or_default(),
                report
                    .get("application_evidence_checks")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                *node_id,
            )
        })
}

fn session_relative_transform_diagnostics(case: &Case) -> Vec<Value> {
    load_relational_reports(case)
        .into_iter()
        .take(4)
        .map(|report| {
            json!({
                "sessions_available":report.get("sessions_available"),
                "candidate_count_examined":report.get("candidate_count_examined"),
                "candidate_count_omitted":report.get("candidate_count_omitted"),
                "candidate_limit_remaining":report.get("candidate_limit_remaining"),
                "locator_candidates_examined":report.get("locator_candidates_examined"),
                "rules":report.get("retained_rules").and_then(Value::as_array).map(|rules| {
                    rules.iter().take(8).map(|rule| json!({
                        "status":rule.get("status"),
                        "seed_locator":rule.pointer("/rule/seed_locator"),
                        "payload_locator":rule.pointer("/rule/payload_locator"),
                        "operation":rule.pointer("/rule/operation/family"),
                    })).collect::<Vec<_>>()
                }),
                "aggregate_parser_checks":report.get("aggregate_parser_checks").and_then(Value::as_array).map(|checks| {
                    checks.iter().take(5).map(|check| json!({
                        "candidate_index":check.get("candidate_index"),
                        "status":check.get("status"),
                        "parser_format":check.get("parser_format"),
                    })).collect::<Vec<_>>()
                }),
            })
        })
        .collect()
}

fn session_relative_report_summary(node_id: u64, report: &Value) -> Value {
    let output_application = report.get("output_application").map(|application| {
        json!({
            "applied_rules":application.get("applied_rules"),
            "supported_rules":application.get("supported_rules"),
            "terminal_sequence":application.get("terminal_sequence"),
            "uniqueness_established":application.get("uniqueness_established"),
        })
    });
    let candidate_preview = report
        .get("retained_rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .take(4)
                .map(|rule| {
                    json!({
                        "status":rule.get("status"),
                        "seed_locator":rule.pointer("/rule/seed_locator"),
                        "payload_locator":rule.pointer("/rule/payload_locator"),
                        "operation":rule.pointer("/rule/operation/family"),
                        "parser_format":rule.pointer("/rule/parser_format"),
                    })
                })
                .collect::<Vec<_>>()
        });
    let application_checks = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .take(8)
                .map(|check| {
                    json!({
                        "candidate_index":check.get("candidate_index"),
                        "status":check.get("status"),
                        "artifact_validated":check.get("artifact_validated"),
                        "structurally_supported":check.get("structurally_supported"),
                    })
                })
                .collect::<Vec<_>>()
        });
    let parser_checks = report
        .get("aggregate_parser_checks")
        .and_then(Value::as_array)
        .map(|checks| {
            checks
                .iter()
                .take(5)
                .map(|check| {
                    json!({
                        "candidate_index":check.get("candidate_index"),
                        "status":check.get("status"),
                        "parser_format":check.get("parser_format"),
                        "length":check.get("length"),
                    })
                })
                .collect::<Vec<_>>()
        });

    json!({
        "node":node_id,
        "input_sample_count":report.get("input_sample_node_ids").and_then(Value::as_array).map_or(0, Vec::len),
        "candidate_count_examined":report.get("candidate_count_examined"),
        "candidate_count_omitted":report.get("candidate_count_omitted"),
        "output_application":output_application,
        "candidate_preview":candidate_preview,
        "application_evidence_checks":application_checks,
        "aggregate_parser_checks":parser_checks,
    })
}

#[test]
fn default_recovery_decodes_raw_directional_runs_before_record_discovery() -> TestResult<()> {
    let RawDirectionalFixture {
        mut case,
        plaintext,
        run_nodes,
    } = build_raw_directional_fixture()?;
    let summary =
        recover_case_with_job(&mut case, RecoveryProfile::Normal, 64 * 1024 * 1024, None)?;
    let relational_reports = load_relational_reports(&case);
    assert!(summary.discovery.input_coverage_complete);
    assert!(
        reports_omit_observed_markers(&relational_reports),
        "relational reports should describe locator shapes without storing observed marker bytes"
    );
    if let Err(error) = record_handoff::assert_exact_raw_handoff(&case, &plaintext, &run_nodes) {
        let details = raw_gate_failure_summary(&relational_reports);
        let snapshot = save_case_snapshot(&case, "l2-raw-handoff-failure-", Some(&details))?;
        return Err(format!("{error}; {details}; snapshot={snapshot:?}").into());
    }
    Ok(())
}

fn raw_gate_failure_summary(reports: &[Value]) -> String {
    let reports = reports
        .iter()
        .take(4)
        .map(|report| {
            let checks = report
                .get("application_evidence_checks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(12)
                .map(|check| {
                    let alternatives = check
                        .pointer("/details/schema_alternatives")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .take(8)
                        .map(|alternative| {
                            json!({
                                "label":alternative.get("label"),
                                "status":alternative.get("status"),
                                "schemas_checked":alternative.get("schemas_checked"),
                                "schemas_structurally_supported":alternative.get("schemas_structurally_supported"),
                                "underdetermined_schemas":alternative.get("underdetermined_schemas"),
                                "variable_length_schemas":alternative.get("variable_length_schemas"),
                                "coherent_sequence_schemas":alternative.get("coherent_sequence_schemas"),
                                "sequence_conflict_schemas":alternative.get("sequence_conflict_schemas"),
                            })
                        })
                        .collect::<Vec<_>>();
                    json!({
                        "candidate_index":check.get("candidate_index"),
                        "status":check.get("status"),
                        "reason":check.get("reason"),
                        "details_reason":check.pointer("/details/reason"),
                        "schema_alternatives":alternatives,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "retained_rule_count":report.get("retained_rules").and_then(Value::as_array).map(Vec::len),
                "application_checks":checks,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&reports).unwrap_or_else(|_| "report summary unavailable".into())
}

fn build_raw_directional_fixture() -> TestResult<RawDirectionalFixture> {
    let mut case = Case::new();
    let source = capture(&mut case, "raw-relational-recovery")?;
    let plaintext = synthetic_png([53, 109, 173])?;
    let chunk_weights = [1_usize, 2, 3, 1, 4, 2, 3, 4];
    let weight_total = chunk_weights.iter().sum::<usize>();
    let mut boundaries = Vec::with_capacity(chunk_weights.len() + 1);
    boundaries.push(0_usize);
    let mut cumulative_weight = 0_usize;
    for weight in chunk_weights {
        cumulative_weight = cumulative_weight
            .checked_add(weight)
            .ok_or("synthetic chunk weight overflow")?;
        boundaries.push(plaintext.len() * cumulative_weight / weight_total);
    }

    // Each raw direction contains two adjacent shuffled chunks from one PNG
    let artifact_part_by_session = [2_usize, 3, 0, 1];
    let mut run_nodes = Vec::with_capacity(artifact_part_by_session.len());
    for (session_index, artifact_part) in artifact_part_by_session.into_iter().enumerate() {
        let wire =
            raw_directional_session_wire(&plaintext, &boundaries, artifact_part, session_index)?;
        let packet = 50 + u64::try_from(session_index)? * 10;
        let context =
            add_session_context(&mut case, "raw-relational-direction", packet, 0, wire.len())?;
        let run_node =
            add_tcp_run_in_context(&mut case, &source, context.direction_node, packet, &wire)?;
        run_nodes.push(run_node);
    }

    Ok(RawDirectionalFixture {
        case,
        plaintext,
        run_nodes,
    })
}

fn raw_directional_session_wire(
    plaintext: &[u8],
    boundaries: &[usize],
    artifact_part: usize,
    session_index: usize,
) -> TestResult<Vec<u8>> {
    use l2_workbench::derivation::{
        CounterByteOrder, CounterWidth, OperandRef, Operation, Recipe, SeedCounterOrder, run,
    };

    let mut records = Vec::with_capacity(2);
    for fragment_index in 0..2_usize {
        let sequence_index = artifact_part * 2 + fragment_index;
        let start = *boundaries
            .get(sequence_index)
            .ok_or("synthetic chunk start is unavailable")?;
        let end = *boundaries
            .get(sequence_index + 1)
            .ok_or("synthetic chunk end is unavailable")?;
        let payload = plaintext
            .get(start..end)
            .ok_or("synthetic artifact chunk is invalid")?;
        records.push(record(b"\x35\xa1", u16::try_from(sequence_index)?, payload));
    }
    if session_index % 2 == 1 {
        records.reverse();
    }

    // Distinct seeds make each session require an independent learned transform
    let session_byte = u8::try_from(session_index)?;
    let seed = (0..8_u8)
        .map(|byte| byte.wrapping_add(session_byte.wrapping_mul(23)))
        .collect::<Vec<_>>();
    let clear_records = records.concat();
    let encrypted = run(
        &clear_records,
        &Recipe {
            steps: vec![Operation::Sha256CounterXor {
                seed: OperandRef::from(seed.clone()),
                initial_counter: 0,
                counter_width: CounterWidth::OneByte,
                counter_byte_order: CounterByteOrder::BigEndian,
                seed_order: SeedCounterOrder::SeedThenCounter,
            }],
            constraints: Vec::new(),
        },
    )?;
    let mut wire = vec![u8::try_from(seed.len())?];
    wire.extend_from_slice(&seed);
    wire.push(0x4d);
    wire.extend_from_slice(&encrypted.output);
    Ok(wire)
}

fn load_relational_reports(case: &Case) -> Vec<Value> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == "recovery_relational_transform_report")
        .filter_map(|node| node.blob.as_deref())
        .filter_map(|blob_id| case.blob(blob_id))
        .filter_map(|blob| serde_json::from_slice::<Value>(&blob.bytes).ok())
        .collect()
}

fn reports_omit_observed_markers(reports: &[Value]) -> bool {
    reports.iter().all(|report| {
        report
            .get("retained_rules")
            .and_then(Value::as_array)
            .is_none_or(|rules| {
                rules.iter().all(|rule| {
                    rule.pointer("/rule/seed_locator/marker").is_none()
                        && rule.pointer("/rule/payload_locator/marker").is_none()
                })
            })
    })
}

fn save_case_snapshot(
    case: &Case,
    prefix: &str,
    details: Option<&str>,
) -> TestResult<std::path::PathBuf> {
    let snapshot_root = tempfile::Builder::new().prefix(prefix).tempdir()?.keep();
    let mut snapshot = std::fs::File::create(snapshot_root.join("case.json"))?;
    case.write_json(&mut snapshot)?;
    if let Some(details) = details {
        std::fs::write(snapshot_root.join("summary.txt"), details)?;
    }
    Ok(snapshot_root)
}

#[test]
fn clear_record_headers_do_not_admit_randomly_decoded_payloads() -> TestResult<()> {
    use l2_workbench::derivation::{
        CounterByteOrder, CounterWidth, OperandRef, Operation, Recipe, SeedCounterOrder, run,
    };

    let mut case = Case::new();
    let source = capture(&mut case, "clear-header-random-payload")?;
    for session_index in 0..4_u64 {
        let session_byte = u8::try_from(session_index)?;
        let seed = (0..8_u8)
            .map(|byte| byte.wrapping_add(session_byte * 29))
            .collect::<Vec<_>>();
        let random_payload = (0..24_u8)
            .map(|byte| 0x31_u8.wrapping_add(byte.wrapping_add(session_byte * 3) % 47))
            .collect::<Vec<_>>();
        let encrypted = run(
            &random_payload,
            &Recipe {
                steps: vec![Operation::Sha256CounterXor {
                    seed: OperandRef::from(seed.clone()),
                    initial_counter: 0,
                    counter_width: CounterWidth::OneByte,
                    counter_byte_order: CounterByteOrder::BigEndian,
                    seed_order: SeedCounterOrder::SeedThenCounter,
                }],
                constraints: Vec::new(),
            },
        )?;

        let mut seed_body = vec![0x6b];
        seed_body.extend_from_slice(&seed);
        let seed_message = synthetic_protocol_record([0x23, 0x71], 0, &seed_body)?;
        let mut payload_body = vec![0x4d];
        payload_body.extend_from_slice(&encrypted.output);
        let payload_message = synthetic_protocol_record([0xa4, 0x19], 0, &payload_body)?;
        let mut wire = seed_message;
        wire.extend_from_slice(&payload_message);

        let packet = 8 + session_index * 10;
        let context = add_session_context(
            &mut case,
            "clear-header-random-payload-scope",
            packet,
            0,
            wire.len(),
        )?;
        add_tcp_run_in_context(&mut case, &source, context.direction_node, packet, &wire)?;
    }

    let _summary =
        recover_case_with_job(&mut case, RecoveryProfile::Normal, 64 * 1024 * 1024, None)?;
    let reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_relational_transform_report")
        .filter_map(|node| node.blob.as_deref())
        .filter_map(|blob_id| case.blob(blob_id))
        .filter_map(|blob| serde_json::from_slice::<Value>(&blob.bytes).ok())
        .collect::<Vec<_>>();
    assert!(
        reports.iter().any(|report| {
            report
                .get("application_evidence_checks")
                .and_then(Value::as_array)
                .is_some_and(|checks| {
                    checks.iter().any(|check| {
                        check.get("status").and_then(Value::as_str) == Some("pending")
                            && check.pointer("/details/schema_only_constraints")
                                == Some(&Value::Bool(true))
                    })
                })
        }),
        "clear record headers should report schema support as unresolved without output"
    );
    let unexpected_outputs = case
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node.kind.as_str(),
                "relational_decoded_frame" | "relational_transform_output"
            )
        })
        .take(12)
        .map(|node| (node.id, node.kind.as_str(), &node.details))
        .collect::<Vec<_>>();
    let unexpected_candidates = unexpected_outputs
        .iter()
        .filter_map(|(_, _, details)| {
            details
                .get("relational_candidate_index")
                .and_then(Value::as_u64)
        })
        .collect::<Vec<_>>();
    let matching_gate_checks = reports
        .iter()
        .filter_map(|report| report.get("application_evidence_checks"))
        .filter_map(Value::as_array)
        .flatten()
        .filter(|check| {
            check
                .get("candidate_index")
                .and_then(Value::as_u64)
                .is_some_and(|candidate| unexpected_candidates.contains(&candidate))
        })
        .take(12)
        .cloned()
        .collect::<Vec<_>>();
    let failure_snapshot = if unexpected_outputs.is_empty() {
        None
    } else {
        let details = serde_json::to_string_pretty(&matching_gate_checks)?;
        Some(save_case_snapshot(
            &case,
            "l2-clear-header-gate-",
            Some(&details),
        )?)
    };
    assert!(
        unexpected_outputs.is_empty(),
        "valid unchanged headers must not materialize random transformed payloads: outputs={unexpected_outputs:#?}; gate_checks={matching_gate_checks:#?}; snapshot={failure_snapshot:?}"
    );
    Ok(())
}

#[test]
fn compact_record_reports_do_not_hide_typed_schema_scheduling() -> TestResult<()> {
    let mut case = Case::new();
    let source = capture(&mut case, "compact-record-report")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let sessions = vec![
        vec![
            record(b"\x19\x82\xd1", 1, b"alpha"),
            record(b"\x19\x82\xd1", 2, b"bravo"),
            record(b"\x19\x82\xd1", 3, b"delta"),
        ],
        vec![
            record(b"\x19\x82\xd1", 4, b"echo!"),
            record(b"\x19\x82\xd1", 5, b"foxtg"),
            record(b"\x19\x82\xd1", 6, b"hotel"),
        ],
    ];
    let session_frames = add_compact_report_sessions(&mut case, &source, &sessions, &framing)?;
    let mut policy = normal_policy(&case)?;
    policy.resources.max_output_bytes = 4_096;
    let limits = policy.record_schema_proposal_limits;
    let (expected_schemas, falsification_count) = typed_survivor_schemas(&sessions, limits)?;
    assert!(!expected_schemas.is_empty());

    let plan = RecoveryPlan {
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let outcome = execute(&mut case, &plan, &policy)?;
    let candidate = outcome
        .candidates
        .iter()
        .find(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .ok_or("compact record discovery candidate is missing")?;
    let report = decode_report(&case, report_node(candidate)?)?;
    let cohort_frame_ids = session_frames.iter().flatten().copied().collect::<Vec<_>>();
    let cohort_frame_set = cohort_frame_ids.iter().copied().collect();
    let report_node_id = report_node(candidate)?;
    assert_compact_report_details_omitted(
        &case,
        report_node_id,
        &report,
        &cohort_frame_ids,
        &outcome.omissions,
        &source,
        (expected_schemas.len(), falsification_count),
    )?;

    assert_scheduled_record_assemblies(
        &outcome,
        &expected_schemas,
        &session_frames,
        &cohort_frame_set,
    )?;
    Ok(())
}

fn add_compact_report_sessions(
    case: &mut Case,
    source: &str,
    sessions: &[Vec<Vec<u8>>],
    framing: &FramingKind,
) -> TestResult<Vec<Vec<u64>>> {
    let mut session_frames = Vec::new();
    for (session_index, messages) in sessions.iter().enumerate() {
        let packet = u64::try_from(session_index)?
            .checked_mul(10)
            .and_then(|value| value.checked_add(10))
            .ok_or("compact report packet number overflow")?;
        let materialized =
            add_materialized_session(case, source, "compact-scope", packet, 0, messages, framing)?;
        session_frames.push(materialized.frame_nodes);
    }
    Ok(session_frames)
}

fn assert_compact_report_details_omitted(
    case: &Case,
    report_node_id: u64,
    report: &Value,
    expected_frames: &[u64],
    omissions: &[super::RecoveryOmission],
    source: &str,
    expected_counts: (usize, usize),
) -> TestResult<()> {
    let (expected_schema_count, falsification_count) = expected_counts;
    assert_eq!(report.get("report_details_complete"), Some(&json!(false)));
    assert_eq!(report.get("version"), Some(&json!(2)));
    assert!(report.get("schema_proposal").is_none());
    assert!(report.get("schema_discovery").is_none());
    assert!(report.get("input_frames").is_none());
    assert_report_frame_references(case, report, report_node_id, expected_frames)?;
    assert_eq!(
        report.pointer("/report_detail_omissions/input_frame_descriptors"),
        Some(&json!(expected_frames.len()))
    );
    assert_eq!(
        report.pointer("/report_detail_omissions/schema_proposal_details"),
        Some(&json!(1))
    );
    assert_eq!(
        report.pointer("/report_detail_omissions/schema_survivor_details"),
        Some(&json!(expected_schema_count))
    );
    assert_eq!(
        report.pointer("/report_detail_omissions/schema_falsification_details"),
        Some(&json!(falsification_count))
    );
    assert!(omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::RecordDiscoveryReportDetails {
            source_id: omitted_source,
            omitted_input_frames,
            omitted_schema_proposals: 1,
            omitted_surviving_schemas,
            omitted_falsification_details,
        } if omitted_source == source
            && *omitted_input_frames == expected_frames.len()
            && *omitted_surviving_schemas == expected_schema_count
            && *omitted_falsification_details == falsification_count
    )));
    Ok(())
}

#[test]
fn report_node_quota_exhaustion_rolls_back_and_keeps_discovery_results_typed() -> TestResult<()> {
    let mut fixture = build_primary_fixture()?;
    fill_case_nodes_to_quota(&mut fixture.case)?;
    let before = fixture.case.clone();
    let policy = normal_policy(&fixture.case)?;
    let outcome = run_record_discovery_only(&mut fixture.case, &recovery_plan(), &policy)?;

    assert_record_report_quota_rollback(
        &fixture.case,
        &before,
        &outcome,
        &fixture.frame_nodes,
        l2_workbench::recovery::RecoveryResource::EvidenceNodes,
    )
}

#[test]
fn report_edge_quota_exhaustion_rolls_back_node_and_provenance_edges() -> TestResult<()> {
    let mut fixture = build_primary_fixture()?;
    fill_case_edges_to_quota(&mut fixture.case)?;
    let before = fixture.case.clone();
    let policy = normal_policy(&fixture.case)?;
    let outcome = run_record_discovery_only(&mut fixture.case, &recovery_plan(), &policy)?;

    assert_record_report_quota_rollback(
        &fixture.case,
        &before,
        &outcome,
        &fixture.frame_nodes,
        l2_workbench::recovery::RecoveryResource::EvidenceEdges,
    )
}

#[test]
fn record_input_omissions_survive_case_scan_work_exhaustion() -> TestResult<()> {
    let (mut case, source, mut policy) = record_input_omission_fixture()?;
    let available_work = policy.resources.max_work_bytes;
    policy.resources.max_work_bytes = 0;
    let plan = RecoveryPlan {
        discover_records: true,
        ..RecoveryPlan::default()
    };

    let outcome = execute(&mut case, &plan, &policy)?;

    assert_record_input_omissions(&outcome, &source, 3, 0, 0, 0)?;
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::RecordDiscovery,
            resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
            ..
        }
    )));
    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
    );

    policy.resources.max_work_bytes = available_work;
    let admitted_outcome = execute(&mut case, &plan, &policy)?;
    assert_record_input_omissions(&admitted_outcome, &source, 6, 1, 1, 1)
}

fn record_input_omission_fixture() -> TestResult<(Case, String, super::RecoveryExecutionPolicy)> {
    let mut case = Case::new();
    let source = capture(&mut case, "record-input-omission-accounting")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let duplicate_session = add_materialized_session(
        &mut case,
        &source,
        "duplicate-scope",
        10,
        0,
        &[record(b"\x19\x82\xd1", 1, b"alpha")],
        &framing,
    )?;
    let duplicate_frame = duplicate_session
        .frame_nodes
        .first()
        .copied()
        .ok_or("duplicate session frame is missing")?;
    duplicate_materialized_frame(&mut case, duplicate_frame)?;
    let message_limit_messages = [
        record(b"\x19\x82\xd1", 1, b"bravo"),
        record(b"\x19\x82\xd1", 2, b"delta"),
    ];
    let message_limit_session = add_materialized_session(
        &mut case,
        &source,
        "message-limit-scope",
        20,
        0,
        &message_limit_messages,
        &framing,
    )?;
    assert_eq!(message_limit_session.frame_nodes.len(), 2);
    let byte_limit_framing = FramingKind::FixedSize { bytes: 31 };
    let byte_limit_messages = [record(b"\x19\x82\xd1", 1, &[b'x'; 22])];
    let byte_limit_session = add_materialized_session(
        &mut case,
        &source,
        "byte-limit-scope",
        30,
        0,
        &byte_limit_messages,
        &byte_limit_framing,
    )?;
    assert_eq!(byte_limit_session.frame_nodes.len(), 1);
    let combined_limit_framing = FramingKind::FixedSize { bytes: 20 };
    let combined_limit_messages = [
        record(b"\x19\x82\xd1", 1, &[b'y'; 11]),
        record(b"\x19\x82\xd1", 2, &[b'z'; 11]),
    ];
    let combined_limit_session = add_materialized_session(
        &mut case,
        &source,
        "combined-limit-scope",
        40,
        0,
        &combined_limit_messages,
        &combined_limit_framing,
    )?;
    assert_eq!(combined_limit_session.frame_nodes.len(), 2);
    add_unmaterialized_frame(
        &mut case,
        &source,
        30,
        Some(json!({"kind":"caller_supplied"})),
    )?;

    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 1;
    policy
        .record_schema_proposal_limits
        .discovery
        .record_limits
        .max_input_bytes = 30;
    Ok((case, source, policy))
}

fn assert_record_input_omissions(
    outcome: &super::RecoveryExecutionOutcome,
    source: &str,
    expected_total: usize,
    expected_message_limit: usize,
    expected_byte_limit: usize,
    expected_combined_limit: usize,
) -> TestResult<()> {
    let (omitted_frames, reasons, formatted) = outcome
        .omissions
        .iter()
        .find_map(|omission| match omission {
            super::RecoveryOmission::RecordDiscoveryInputs {
                source_id: Some(omitted_source),
                omitted_frames,
                reason_counts,
                ..
            } if omitted_source == source => {
                Some((*omitted_frames, reason_counts, omission.to_string()))
            }
            _ => None,
        })
        .ok_or_else(|| std::io::Error::other("record discovery input omissions were lost"))?;
    assert_eq!(omitted_frames, expected_total);
    assert_eq!(reasons.values().sum::<usize>(), omitted_frames);
    assert_eq!(reasons.get("missing_materialization_receipt"), Some(&1));
    assert_eq!(reasons.get("duplicate_receipt_frame_index"), Some(&2));
    assert_eq!(
        reasons.get("learning_prefix_message_count_limit"),
        (expected_message_limit > 0).then_some(&expected_message_limit)
    );
    assert_eq!(
        reasons.get("learning_prefix_aggregate_byte_limit"),
        (expected_byte_limit > 0).then_some(&expected_byte_limit)
    );
    assert_eq!(
        reasons.get("learning_prefix_message_and_byte_limits"),
        (expected_combined_limit > 0).then_some(&expected_combined_limit)
    );
    if expected_message_limit > 0 {
        assert!(formatted.contains("learning_prefix_message_count_limit"));
    }
    if expected_byte_limit > 0 {
        assert!(formatted.contains("learning_prefix_aggregate_byte_limit"));
    }
    if expected_combined_limit > 0 {
        assert!(formatted.contains("learning_prefix_message_and_byte_limits"));
    }
    Ok(())
}

fn build_primary_fixture() -> TestResult<PrimaryFixture> {
    let mut case = Case::new();
    let source_id = capture(&mut case, "record-sessions")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let messages = [
        record(b"\x19\x82\xd1", 4, b"alpha"),
        record(b"\x70\x03\xa4", 8, b"bravo"),
    ];
    let held_out = record(b"\x19\x82\xd1", 12, b"delta");
    let training =
        add_materialized_session(&mut case, &source_id, "scope-a", 10, 0, &messages, &framing)?;
    let held_out_session = add_materialized_session(
        &mut case,
        &source_id,
        "scope-a",
        20,
        0,
        std::slice::from_ref(&held_out),
        &framing,
    )?;
    let invalid_frames = add_invalid_frame_examples(&mut case, &source_id)?;
    let ambiguous_source_id = add_ambiguous_episode_parent(&mut case, held_out, &framing)?;
    let mut frame_nodes = training.frame_nodes;
    frame_nodes.extend(held_out_session.frame_nodes);
    let mut receipt_nodes = training.receipt_nodes;
    receipt_nodes.extend(held_out_session.receipt_nodes);
    Ok(PrimaryFixture {
        case,
        source_id,
        ambiguous_source_id,
        training_episode: training.episode_node,
        held_out_episode: held_out_session.episode_node,
        frame_nodes,
        receipt_nodes,
        omitted_frame: invalid_frames.missing_receipt,
        missing_basis_frame: invalid_frames.missing_selection_basis,
        malformed_basis_frame: invalid_frames.malformed_selection_basis,
    })
}

fn add_invalid_frame_examples(case: &mut Case, source: &str) -> TestResult<InvalidFrameExamples> {
    let omitted =
        add_unmaterialized_frame(case, source, 30, Some(json!({"kind":"caller_supplied"})))?;
    let missing_basis = add_unmaterialized_frame(case, source, 31, None)?;
    let malformed_basis = add_unmaterialized_frame(
        case,
        source,
        32,
        Some(json!({"kind":"caller_supplied","report_node":9})),
    )?;
    Ok(InvalidFrameExamples {
        missing_receipt: omitted,
        missing_selection_basis: missing_basis,
        malformed_selection_basis: malformed_basis,
    })
}

fn add_ambiguous_episode_parent(
    case: &mut Case,
    message: Vec<u8>,
    framing: &FramingKind,
) -> TestResult<String> {
    let source = capture(case, "ambiguous-episode-parent")?;
    let stream = [message];
    let session =
        add_materialized_session(case, &source, "scope-ambiguous", 30, 0, &stream, framing)?;
    let direction = case
        .edges()
        .iter()
        .find(|edge| edge.from == session.episode_node && edge.relation == "contains")
        .map(|edge| edge.to)
        .ok_or("ambiguous fixture direction is missing")?;
    let competing_episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        episode_details("scope-ambiguous", 30),
    )?;
    case.add_edge(Edge {
        from: competing_episode,
        to: direction,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Synthetic second episode creates ambiguous ancestry".to_owned(),
    })?;
    Ok(source)
}

fn report_node(candidate: &l2_workbench::recovery::RecoveryCandidate) -> TestResult<u64> {
    match candidate.state() {
        RecoveryCandidateState::Finished {
            result: RecoveryResult::Hypothesis { node_id },
            ..
        } => Ok(*node_id),
        _ => Err("record discovery did not finish as a hypothesis report".into()),
    }
}

fn assert_primary_report(
    report: &Value,
    fixture: &PrimaryFixture,
    report_node_id: u64,
) -> TestResult<()> {
    assert_eq!(report.get("version"), Some(&json!(2)));
    assert_eq!(report.get("result"), Some(&json!("hypotheses_found")));
    assert_eq!(
        report.get("search_exhaustive_within_plan"),
        Some(&json!(false))
    );
    assert_eq!(report.get("report_details_complete"), Some(&json!(true)));
    assert_eq!(
        report.pointer("/cohort/framing_rule"),
        Some(&json!({"kind":"fixed_size","bytes":14}))
    );
    assert_eq!(
        report.pointer("/partition/basis"),
        Some(&json!("complete_sessions"))
    );
    assert_eq!(
        report.pointer("/partition/training_session_nodes"),
        Some(&json!([fixture.training_episode]))
    );
    assert_eq!(
        report.pointer("/partition/held_out_session_nodes"),
        Some(&json!([fixture.held_out_episode]))
    );
    assert_report_inputs(
        &fixture.case,
        report,
        report_node_id,
        &fixture.frame_nodes,
        &fixture.receipt_nodes,
    )
}

fn assert_report_inputs(
    case: &Case,
    report: &Value,
    report_node_id: u64,
    expected_frames: &[u64],
    expected_receipts: &[u64],
) -> TestResult<()> {
    assert_report_frame_references(case, report, report_node_id, expected_frames)?;
    let receipts = expected_frames
        .iter()
        .map(|frame_id| {
            case.edges()
                .iter()
                .find(|edge| {
                    edge.to == *frame_id
                        && edge.relation == "materialized"
                        && case.nodes().iter().any(|node| {
                            node.id == edge.from && node.kind == "custom_protocol_framing_receipt"
                        })
                })
                .map(|edge| edge.from)
                .ok_or_else(|| -> Box<dyn Error> {
                    Box::new(std::io::Error::other(
                        "materialized frame receipt link is missing",
                    ))
                })
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(receipts, expected_receipts);
    let first_frame_id = expected_frames
        .first()
        .copied()
        .ok_or("report has no expected frame")?;
    let first_frame = case
        .nodes()
        .iter()
        .find(|node| node.id == first_frame_id && node.kind == "custom_protocol_frame")
        .ok_or("first report frame does not resolve")?;
    assert_eq!(
        first_frame.details.get("selection_basis"),
        Some(&json!({"kind":"caller_supplied"}))
    );
    assert!(
        report
            .pointer("/schema_discovery/surviving")
            .and_then(Value::as_array)
            .is_some_and(|schemas| !schemas.is_empty())
    );
    assert!(report.pointer("/schema_proposal").is_some_and(|proposal| {
        proposal.get("search_exhaustive_within_plan") == Some(&Value::Bool(false))
    }));
    Ok(())
}

fn assert_report_frame_references(
    case: &Case,
    report: &Value,
    report_node_id: u64,
    expected_frames: &[u64],
) -> TestResult<()> {
    let refs = report
        .pointer("/input_frame_refs")
        .and_then(Value::as_array)
        .ok_or("report input frame references are missing")?;
    let training_count = report
        .pointer("/partition/training_message_count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or("report training partition count is missing")?;
    let held_out_count = report
        .pointer("/partition/held_out_message_count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or("report held-out partition count is missing")?;
    assert_eq!(training_count + held_out_count, expected_frames.len());
    assert_eq!(refs.len(), expected_frames.len());
    for (index, (reference, expected_frame)) in refs.iter().zip(expected_frames).enumerate() {
        let fields = reference
            .as_array()
            .ok_or("report input reference is not a pair")?;
        assert_eq!(
            fields.first().and_then(Value::as_u64),
            Some(*expected_frame)
        );
        let expected_partition = if index < training_count {
            "training"
        } else {
            "held_out"
        };
        assert_eq!(
            fields.get(1).and_then(Value::as_str),
            Some(expected_partition)
        );
        let frame = case
            .nodes()
            .iter()
            .find(|node| node.id == *expected_frame && node.kind == "custom_protocol_frame")
            .ok_or("report frame reference does not resolve in its Case graph")?;
        assert!(case.edges().iter().any(|edge| {
            edge.from == report_node_id
                && edge.to == frame.id
                && edge.relation == "record_discovery_input"
        }));
    }
    Ok(())
}

fn assert_report_is_evidence_only(
    case: &Case,
    outcome: &super::RecoveryExecutionOutcome,
    report_node: u64,
) {
    let selected_receipts = case
        .edges()
        .iter()
        .filter(|edge| edge.from == report_node && edge.relation == "record_schema_selected_from")
        .map(|edge| edge.to)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!selected_receipts.is_empty());
    assert!(selected_receipts.iter().all(|receipt_id| {
        case.nodes()
            .iter()
            .any(|node| node.id == *receipt_id && node.kind == "record_parse_receipt")
    }));
    assert!(!case.edges().iter().any(|edge| {
        edge.from == report_node
            && matches!(edge.relation.as_str(), "derived_from" | "record_assembly")
    }));
    assert!(
        outcome
            .candidates
            .iter()
            .any(|candidate| matches!(candidate.task(), RecoveryTask::AssembleRecords(_)))
    );
}

fn assert_primary_omissions(
    outcome: &super::RecoveryExecutionOutcome,
    fixture: &PrimaryFixture,
) -> TestResult<()> {
    let source_omission = outcome
        .omissions
        .iter()
        .find_map(|omission| match omission {
            super::RecoveryOmission::RecordDiscoveryInputs {
                source_id: Some(source),
                omitted_frames: 3,
                reason_counts,
                examples,
            } if source == &fixture.source_id => Some((reason_counts, examples)),
            _ => None,
        });
    let (reason_counts, examples) =
        source_omission.ok_or("expected source input omissions with retained examples")?;
    assert_eq!(
        reason_counts.get("missing_materialization_receipt"),
        Some(&1)
    );
    assert_eq!(
        reason_counts.get("missing_framing_selection_evidence"),
        Some(&1)
    );
    assert_eq!(
        reason_counts.get("invalid_framing_selection_evidence"),
        Some(&1)
    );
    assert!(
        [
            fixture.omitted_frame,
            fixture.missing_basis_frame,
            fixture.malformed_basis_frame,
        ]
        .iter()
        .all(|frame_id| examples.iter().any(|example| {
            example.get("frame_node_id").and_then(Value::as_u64) == Some(*frame_id)
        }))
    );
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::RecordDiscoveryInputs {
            source_id: Some(source),
            reason_counts,
            ..
        } if source == &fixture.ambiguous_source_id
            && reason_counts.get("ambiguous_conversation_context") == Some(&1)
    )));
    Ok(())
}

#[test]
fn record_discovery_omits_frames_from_incomplete_materialization_receipts() -> TestResult<()> {
    let mut case = Case::new();
    let source = capture(&mut case, "incomplete-framing")?;
    let mut stream = record(b"\x19\x82\xd1", 4, b"alpha");
    stream.extend(record(b"\x70\x03\xa4", 8, b"bravo"));
    stream.push(0xff);
    let framing = FramingKind::FixedSize { bytes: 14 };
    let incomplete_session = add_materialized_session(
        &mut case,
        &source,
        "scope-incomplete",
        10,
        0,
        &[stream],
        &framing,
    )?;
    assert_eq!(
        incomplete_session.frame_nodes.len(),
        2,
        "two complete prefixes precede the tail"
    );

    let policy = normal_policy(&case)?;
    let outcome = execute(&mut case, &recovery_plan(), &policy)?;

    assert!(
        !outcome
            .candidates
            .iter()
            .any(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
    );
    assert!(!case.nodes().iter().any(|node| node.kind == REPORT_KIND));
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::RecordDiscoveryInputs {
            source_id: Some(omission_source),
            omitted_frames: 2,
            reason_counts,
            ..
        } if omission_source == &source
            && reason_counts.get("incomplete_framing") == Some(&2)
    )));
    Ok(())
}

#[test]
fn combined_selection_basis_retains_its_exact_report_receipt_path() -> TestResult<()> {
    let mut case = Case::new();
    let source = capture(&mut case, "combined-framing-selection")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let selection_report = add_framing_discovery_report(&mut case, &framing)?;
    let messages = [
        record(b"\x19\x82\xd1", 4, b"alpha"),
        record(b"\x70\x03\xa4", 8, b"bravo"),
    ];
    let session = add_materialized_session_with_options(
        &mut case,
        &source,
        "scope-combined",
        10,
        0,
        &messages,
        MaterializationOptions {
            framing: &framing,
            selection_basis: FramingSelectionBasis::CallerAndDiscovered {
                report_node: selection_report,
            },
        },
    )?;
    let policy = normal_policy(&case)?;
    let outcome = execute(&mut case, &recovery_plan(), &policy)?;
    let candidate = record_candidate(&outcome, &session.frame_nodes)?;
    let report = decode_report(&case, report_node(candidate)?)?;
    let report_node_id = report_node(candidate)?;
    let input_refs = report
        .pointer("/input_frame_refs")
        .and_then(Value::as_array)
        .ok_or("record report input references are missing")?;
    let expected_basis = json!({
        "kind":"caller_and_discovered",
        "report_node":selection_report,
    });
    assert_report_frame_references(&case, &report, report_node_id, &session.frame_nodes)?;
    assert!(input_refs.iter().all(|reference| {
        reference
            .as_array()
            .and_then(|fields| fields.first())
            .and_then(Value::as_u64)
            .and_then(|frame_id| {
                case.nodes()
                    .iter()
                    .find(|node| node.id == frame_id && node.kind == "custom_protocol_frame")
            })
            .is_some_and(|frame| frame.details.get("selection_basis") == Some(&expected_basis))
    }));
    for receipt_node in session.receipt_nodes {
        let mut selection_edges = case.edges().iter().filter(|edge| {
            edge.to == receipt_node && edge.relation == "framing_rule_selected_from"
        });
        let selection_edge = selection_edges
            .next()
            .ok_or("combined selection edge is missing")?;
        assert_eq!(selection_edge.from, selection_report);
        assert_eq!(selection_edge.status, EvidenceStatus::Observed);
        assert!(selection_edges.next().is_none());
    }
    Ok(())
}

#[test]
fn independent_contexts_and_framing_rules_keep_competing_reports_separate() -> TestResult<()> {
    let mut case = Case::new();
    let first_source = capture(&mut case, "first-context")?;
    let second_source = capture(&mut case, "second-context")?;
    let bytes = record(b"\x19\x82\xd1", 4, b"alpha");
    let first_rule = FramingKind::FixedSize { bytes: 14 };
    let second_rule = FramingKind::FixedSize { bytes: 7 };
    let first_session = add_materialized_session(
        &mut case,
        &first_source,
        "scope-a",
        10,
        0,
        std::slice::from_ref(&bytes),
        &first_rule,
    )?;
    let second_session = add_materialized_session(
        &mut case,
        &second_source,
        "scope-b",
        10,
        1,
        std::slice::from_ref(&bytes),
        &second_rule,
    )?;

    let policy = normal_policy(&case)?;
    let outcome = execute(&mut case, &recovery_plan(), &policy)?;
    let candidates = outcome
        .candidates
        .iter()
        .filter(|candidate| candidate.task() == &RecoveryTask::RecordDiscovery)
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().any(|candidate| {
        candidate
            .inputs()
            .iter()
            .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
            .copied()
            .collect::<Vec<_>>()
            == first_session.frame_nodes
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate
            .inputs()
            .iter()
            .flat_map(l2_workbench::recovery::RecoveryInput::origin_node_ids)
            .copied()
            .collect::<Vec<_>>()
            == second_session.frame_nodes
    }));
    Ok(())
}

#[test]
fn no_candidates_and_budget_partial_have_distinct_report_statuses() -> TestResult<()> {
    let mut no_candidate_case = Case::new();
    let source = capture(&mut no_candidate_case, "no-record-schema")?;
    let no_candidate_framing = FramingKind::FixedSize { bytes: 1 };
    let noise_messages = [vec![0x80], vec![0x81]];
    let no_candidate_session = add_materialized_session(
        &mut no_candidate_case,
        &source,
        "scope-a",
        10,
        0,
        &noise_messages,
        &no_candidate_framing,
    )?;
    let policy = normal_policy(&no_candidate_case)?;
    let no_candidate_outcome = execute(&mut no_candidate_case, &recovery_plan(), &policy)?;
    let no_candidate = record_candidate(&no_candidate_outcome, &no_candidate_session.frame_nodes)?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = no_candidate.state()
    else {
        return Err("no-candidate discovery did not retain its report".into());
    };
    assert_eq!(
        decode_report(&no_candidate_case, *node_id)?.get("result"),
        Some(&json!("no_candidates"))
    );
    assert_eq!(
        decode_report(&no_candidate_case, *node_id)?.get("search_exhaustive_within_plan"),
        Some(&json!(true))
    );

    let mut partial_case = Case::new();
    let framing = FramingKind::FixedSize { bytes: 14 };
    let source = capture(&mut partial_case, "partial-schema-search")?;
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x70\x03\xa4", 8, b"bravo");
    let partial_session = add_materialized_session(
        &mut partial_case,
        &source,
        "scope-a",
        10,
        0,
        &[first, second],
        &framing,
    )?;
    let mut partial_policy = normal_policy(&partial_case)?;
    partial_policy.record_schema_proposal_limits.max_pair_checks = 1;
    let partial_outcome = execute(&mut partial_case, &recovery_plan(), &partial_policy)?;
    let partial_candidate = record_candidate(&partial_outcome, &partial_session.frame_nodes)?;
    let RecoveryCandidateState::Finished {
        result: RecoveryResult::Hypothesis { node_id },
        ..
    } = partial_candidate.state()
    else {
        return Err("partial discovery did not retain its report".into());
    };
    let report = decode_report(&partial_case, *node_id)?;
    assert_eq!(report.get("result"), Some(&json!("hypotheses_found")));
    assert_eq!(
        report.get("search_exhaustive_within_plan"),
        Some(&json!(false))
    );
    assert_eq!(
        report.pointer("/schema_proposal/search_exhaustive_within_plan"),
        Some(&json!(false))
    );
    assert!(partial_outcome.omissions.iter().any(|omission| matches!(
        omission,
        super::RecoveryOmission::RecordDiscoveryAnalysis { .. }
    )));
    Ok(())
}

#[test]
fn record_discovery_work_and_output_exhaustion_finish_without_reports() -> TestResult<()> {
    let mut work_case = Case::new();
    let source = capture(&mut work_case, "record-work-ceiling")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let messages = [
        record(b"\x19\x82\xd1", 4, b"alpha"),
        record(b"\x70\x03\xa4", 8, b"bravo"),
    ];
    let work_session = add_materialized_session(
        &mut work_case,
        &source,
        "scope-a",
        10,
        0,
        &messages,
        &framing,
    )?;
    let mut work_policy = normal_policy(&work_case)?;
    let work_plan = super::record_discovery::apply_input_limits(
        super::record_discovery::collect_input_plan(&work_case)?,
        work_policy.record_schema_proposal_limits,
    )?;
    let work_bound = super::record_discovery::case_work_bound(
        &work_plan,
        work_policy.record_schema_proposal_limits,
    )?;
    work_policy.record_phase_work_limit = work_bound
        .checked_sub(1)
        .ok_or("record discovery work bound is empty")?;
    let work_outcome = execute(&mut work_case, &recovery_plan(), &work_policy)?;
    let work_candidate = record_candidate(&work_outcome, &work_session.frame_nodes)?;
    assert!(matches!(
        work_candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::WorkBytes,
                ..
            },
            ..
        }
    ));
    assert!(
        !work_case
            .nodes()
            .iter()
            .any(|node| node.kind == REPORT_KIND)
    );

    let mut output_case = Case::new();
    let source = capture(&mut output_case, "record-output-ceiling")?;
    let output_session = add_materialized_session(
        &mut output_case,
        &source,
        "scope-a",
        10,
        0,
        &messages,
        &framing,
    )?;
    let mut output_policy = normal_policy(&output_case)?;
    output_policy.resources.max_output_bytes = 1;
    let output_outcome = execute(&mut output_case, &recovery_plan(), &output_policy)?;
    let output_candidate = record_candidate(&output_outcome, &output_session.frame_nodes)?;
    assert!(matches!(
        output_candidate.state(),
        RecoveryCandidateState::Finished {
            result: RecoveryResult::ResourceExhausted {
                resource: l2_workbench::recovery::RecoveryResource::OutputBytes,
                ..
            },
            ..
        }
    ));
    assert!(
        !output_case
            .nodes()
            .iter()
            .any(|node| node.kind == REPORT_KIND)
    );
    Ok(())
}

#[test]
fn default_recovery_enables_record_discovery_for_existing_materialized_frames() -> TestResult<()> {
    let mut case = Case::new();
    let source = capture(&mut case, "default-record-discovery")?;
    let framing = FramingKind::FixedSize { bytes: 14 };
    let first = record(b"\x19\x82\xd1", 4, b"alpha");
    let second = record(b"\x70\x03\xa4", 8, b"bravo");
    let held_out = record(b"\x19\x82\xd1", 12, b"delta");
    add_materialized_session(
        &mut case,
        &source,
        "scope-a",
        10,
        0,
        &[first, second],
        &framing,
    )?;
    add_materialized_session(&mut case, &source, "scope-a", 20, 0, &[held_out], &framing)?;

    let summary = recover_case(&mut case)?;

    assert!(summary.candidate_count > 0);
    assert!(case.nodes().iter().any(|node| node.kind == REPORT_KIND));
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_assembly_receipt")
    );
    Ok(())
}

#[test]
fn default_recovery_retains_the_unrelated_length_prefixed_record_schema() -> TestResult<()> {
    let mut case = Case::new();
    let (artifacts, runs) = add_synthetic_protocol_fixture(&mut case)?;
    assert_eq!(artifacts.len(), 8);
    assert_eq!(runs.len(), 4);
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| (artifact.session_index, artifact.direction_index))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        runs.iter()
            .map(|run| (run.session_index, run.direction_index, run.node_id))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );

    let summary = match recover_case(&mut case) {
        Ok(summary) => summary,
        Err(error) => {
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            for node in case.nodes() {
                *counts.entry(node.kind.clone()).or_default() += 1;
            }
            let last_nodes = case
                .nodes()
                .iter()
                .rev()
                .take(12)
                .map(|node| (node.id, node.kind.as_str(), node.blob.as_deref()))
                .collect::<Vec<_>>();
            let last_edges = case
                .edges()
                .iter()
                .rev()
                .take(12)
                .map(|edge| (edge.from, edge.to, edge.relation.as_str()))
                .collect::<Vec<_>>();
            eprintln!(
                "recovery error={error:?}; nodes={} edges={}; node_counts={counts:?}; last_nodes={last_nodes:?}; last_edges={last_edges:?}",
                case.nodes().len(),
                case.edges().len()
            );
            return Err(error.into());
        }
    };
    assert!(summary.candidate_count > 0);
    assert_synthetic_schema_survives_default_search(&case)?;
    let recovered_artifacts = artifacts
        .iter()
        .filter(|artifact| case.blobs().iter().any(|blob| blob.bytes == artifact.bytes))
        .map(|artifact| {
            (
                artifact.session_index,
                artifact.direction_index,
                artifact.identifier,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        recovered_artifacts.len(),
        artifacts.len(),
        "the default recovery path must retain every independently generated PNG; recovered={recovered_artifacts:?}, edges={}, validated={}, omissions={}",
        case.edges().len(),
        summary.validated_artifact_count,
        summary.omissions.len()
    );
    assert!(summary.validated_artifact_count >= artifacts.len());
    Ok(())
}
