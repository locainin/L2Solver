use super::super::{
    RecoveryExecutionOutcome, RecoveryExecutionPolicy, RecoveryOmission, execute, normal_policy,
};
use super::{
    REPORT_KIND, RecoveryPlan, TestResult, UnframedSession, add_unframed_sessions, capture,
    decode_report, receipt_has_exact_artifact, record, selected_record_receipt_ids,
};
use l2_workbench::{evidence::Case, protocol::FramingKind};
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom};

const PAYLOAD_BYTES: usize = 16;
const FRAME_BYTES: usize = 26;
const ALTERNATE_FRAME_BYTES: usize = 22;

struct MixedRun {
    case: Case,
    sessions: Vec<UnframedSession>,
    archives: Vec<Vec<u8>>,
    outcome: RecoveryExecutionOutcome,
}

struct MixedFixture {
    case: Case,
    sessions: Vec<UnframedSession>,
    archives: Vec<Vec<u8>>,
    plan: RecoveryPlan,
    policy: RecoveryExecutionPolicy,
}

fn first_difference<T: Eq>(left: &[T], right: &[T]) -> Option<usize> {
    left.iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
}

fn value_difference<'a>(
    left: &'a Value,
    right: &'a Value,
    path: &str,
) -> Option<(String, &'a Value, &'a Value)> {
    if left == right {
        return None;
    }
    match (left, right) {
        (Value::Object(a), Value::Object(b)) if a.len() == b.len() && a.keys().eq(b.keys()) => {
            a.iter().find_map(|(key, value)| {
                b.get(key)
                    .and_then(|other| value_difference(value, other, &format!("{path}/{key}")))
            })
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => a
            .iter()
            .zip(b)
            .enumerate()
            .find_map(|(index, (x, y))| value_difference(x, y, &format!("{path}/{index}"))),
        _ => Some((path.to_owned(), left, right)),
    }
}

fn value_summary(value: &Value) -> String {
    match value {
        Value::Object(values) => format!("object with {} keys", values.len()),
        Value::Array(values) => format!("array with {} items", values.len()),
        Value::String(value) => value.chars().take(80).collect(),
        _ => value.to_string(),
    }
}

fn assert_exact_case_equality(actual: &Case, expected: &Case) -> TestResult<()> {
    if let Some(index) = first_difference(actual.blobs(), expected.blobs()) {
        let describe = |case: &Case| {
            case.blobs()
                .get(index)
                .map(|blob| (blob.id.clone(), blob.bytes.len()))
        };
        return Err(format!(
            "blob {index} differs: actual={:?}, expected={:?}",
            describe(actual),
            describe(expected)
        )
        .into());
    }
    if let Some(index) = first_difference(actual.nodes(), expected.nodes()) {
        if let (Some(left), Some(right)) = (actual.nodes().get(index), expected.nodes().get(index))
        {
            if let Some((path, left, right)) =
                value_difference(&left.details, &right.details, "details")
            {
                return Err(format!(
                    "node {index} differs at {path}: actual={}, expected={}",
                    value_summary(left),
                    value_summary(right)
                )
                .into());
            }
        }
        let describe = |case: &Case| {
            case.nodes()
                .get(index)
                .map(|node| (node.id, node.kind.clone(), node.blob.clone()))
        };
        return Err(format!(
            "node {index} differs: actual={:?}, expected={:?}",
            describe(actual),
            describe(expected)
        )
        .into());
    }
    if let Some(index) = first_difference(actual.edges(), expected.edges()) {
        return Err(format!(
            "edge {index} differs: actual={:?}, expected={:?}",
            actual.edges().get(index),
            expected.edges().get(index)
        )
        .into());
    }
    let mut left = tempfile::tempfile()?;
    let mut right = tempfile::tempfile()?;
    actual.write_json(&mut left)?;
    expected.write_json(&mut right)?;
    let length = left.metadata()?.len();
    if length != right.metadata()?.len() {
        return Err("serialized cases have different lengths".into());
    }
    left.seek(SeekFrom::Start(0))?;
    right.seek(SeekFrom::Start(0))?;
    let mut left_buffer = [0_u8; 16 * 1024];
    let mut right_buffer = [0_u8; 16 * 1024];
    let mut offset = 0_u64;
    while offset < length {
        let count = usize::try_from((length - offset).min(left_buffer.len() as u64))?;
        left.read_exact(&mut left_buffer[..count])?;
        right.read_exact(&mut right_buffer[..count])?;
        if left_buffer[..count] != right_buffer[..count] {
            return Err(format!("serialized cases differ at or after byte {offset}").into());
        }
        offset += u64::try_from(count)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum HeldoutChange {
    None,
    UnknownControl,
    CorruptData,
    InvalidArtifacts,
    VariableControls,
    AlternateLayout,
    StructuredControls,
}

fn aligned_archive(contents: &[u8]) -> TestResult<Vec<u8>> {
    for padding in 0..PAYLOAD_BYTES {
        let mut member = contents.to_vec();
        member.resize(member.len() + padding, b'~');
        let archive = super::super::tests::stored_zip_entries(&[(b"payload.bin", &member)])?;
        if archive.len().is_multiple_of(PAYLOAD_BYTES) {
            return Ok(archive);
        }
    }
    Err("could not align the independently generated archive".into())
}

fn mixed_messages(archive: &[u8], session: u8) -> TestResult<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    for (sequence, payload) in archive.chunks_exact(PAYLOAD_BYTES).enumerate() {
        let mut data = vec![0x51];
        data.extend(record(
            &[session + 4, session + 13, session + 29],
            u16::try_from(sequence)?,
            payload,
        ));
        assert_eq!(data.len(), FRAME_BYTES);

        // Control messages occupy the same frame width but do not use the data layout
        let mut control = vec![0xa6];
        for offset in 0..FRAME_BYTES - 1 {
            let byte = usize::from(session) * 37 + sequence * 19 + offset * 23 + 11;
            control.push(u8::try_from(byte % 251)?);
        }
        messages.push(data);
        messages.push(control);
    }
    Ok(messages)
}

fn alternate_messages(archive: &[u8], session: u8) -> TestResult<Vec<Vec<u8>>> {
    let mut messages = Vec::new();
    for (sequence, payload) in archive.chunks_exact(PAYLOAD_BYTES).enumerate() {
        let mut data = vec![session + 20, session + 40, 0x39, u8::try_from(sequence)?];
        data.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
        data.extend_from_slice(payload);
        assert_eq!(data.len(), ALTERNATE_FRAME_BYTES);
        let mut control = Vec::new();
        for offset in 0..ALTERNATE_FRAME_BYTES {
            let value = usize::from(session) * 13 + sequence * 17 + offset * 29;
            control.push(u8::try_from(value % 251)?);
        }
        *control.get_mut(2).ok_or("control type is missing")? = 0xc5;
        messages.push(data);
        messages.push(control);
    }
    Ok(messages)
}

fn mixed_fixture(change: HeldoutChange) -> TestResult<MixedFixture> {
    let mut archives = [
        b"first observed message family".as_slice(),
        b"second observed message family".as_slice(),
        b"a changed independent session".as_slice(),
        b"another changed independent session".as_slice(),
    ]
    .into_iter()
    .map(aligned_archive)
    .collect::<TestResult<Vec<_>>>()?;
    if matches!(change, HeldoutChange::InvalidArtifacts) {
        // Keep the record layout while replacing every archive with ordinary bytes
        for (index, archive) in archives.iter_mut().enumerate() {
            for (offset, byte) in archive.iter_mut().enumerate() {
                *byte = b'A' + u8::try_from((index + offset) % 23)?;
            }
        }
    }
    let mut messages = archives
        .iter()
        .enumerate()
        .map(|(index, archive)| {
            let session = u8::try_from(index)?;
            if matches!(change, HeldoutChange::AlternateLayout) {
                alternate_messages(archive, session)
            } else {
                mixed_messages(archive, session)
            }
        })
        .collect::<TestResult<Vec<_>>>()?;
    if matches!(change, HeldoutChange::VariableControls) {
        // Control selectors vary while every data frame keeps the same message type
        for session in &mut messages {
            for control in session.iter_mut().skip(1).step_by(2) {
                let value = *control.get(1).ok_or("control value is missing")? | 0x80;
                *control.first_mut().ok_or("control selector is missing")? = value;
            }
        }
    }
    if matches!(change, HeldoutChange::StructuredControls) {
        // Control frames use a valid record layout but a separate object identifier
        for (session_index, session) in messages.iter_mut().enumerate() {
            let session_id = u8::try_from(session_index)?;
            for (sequence, control) in session.iter_mut().skip(1).step_by(2).enumerate() {
                let mut replacement = vec![0xa6];
                replacement.extend(record(
                    &[session_id + 64, session_id + 73, session_id + 89],
                    u16::try_from(sequence)?,
                    &[b'~'; PAYLOAD_BYTES],
                ));
                *control = replacement;
            }
        }
    }
    let heldout = messages.get_mut(2).ok_or("held-out session is missing")?;
    match change {
        HeldoutChange::None
        | HeldoutChange::InvalidArtifacts
        | HeldoutChange::VariableControls
        | HeldoutChange::AlternateLayout
        | HeldoutChange::StructuredControls => {}
        HeldoutChange::UnknownControl => {
            let control = heldout
                .last_mut()
                .ok_or("held-out control frame is missing")?;
            *control.first_mut().ok_or("control selector is missing")? = 0xee;
        }
        HeldoutChange::CorruptData => {
            let data_index = heldout
                .len()
                .checked_sub(2)
                .ok_or("held-out data is missing")?;
            let data = heldout
                .get_mut(data_index)
                .ok_or("held-out data frame is missing")?;
            // The payload is still present, but the selected record's length is contradictory
            *data.get_mut(9).ok_or("data length is missing")? = 15;
        }
    }
    let mut case = Case::new();
    let source = capture(&mut case, "independent mixed message families")?;
    let sessions = add_unframed_sessions(&mut case, &source, vec![("mixed", messages)])?;
    let mut policy = normal_policy(&case)?;
    // Four samples per session include both layouts in both training sessions
    policy.record_schema_proposal_limits.discovery.max_messages = 16;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize {
            bytes: if matches!(change, HeldoutChange::AlternateLayout) {
                ALTERNATE_FRAME_BYTES
            } else {
                FRAME_BYTES
            },
        }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    Ok(MixedFixture {
        case,
        sessions,
        archives,
        plan,
        policy,
    })
}

fn execute_mixed_sessions(change: HeldoutChange) -> TestResult<MixedRun> {
    let MixedFixture {
        mut case,
        sessions,
        archives,
        plan,
        policy,
    } = mixed_fixture(change)?;
    let outcome = execute(&mut case, &plan, &policy)?;
    Ok(MixedRun {
        case,
        sessions,
        archives,
        outcome,
    })
}

fn sampled_data_messages(sessions: &[UnframedSession]) -> Vec<&[u8]> {
    sessions
        .iter()
        .flat_map(|session| session.messages.iter().take(4).step_by(2))
        .map(Vec::as_slice)
        .collect()
}

fn assert_data_family_has_strict_schema(change: HeldoutChange) -> TestResult<()> {
    use l2_workbench::protocol::{
        Direction, MessageContext, MessageFamilyLimits, MessageRole, MessageSample,
        RecordAssemblyInput, analyze_record_schemas, assemble_record_groups_from_inputs,
        discover_message_families, parse_records_with_limits,
    };

    let fixture = mixed_fixture(change)?;
    let mut family_samples = Vec::new();
    for (session_index, session) in fixture.sessions[..2].iter().enumerate() {
        for (index, bytes) in session.messages.iter().take(4).enumerate() {
            family_samples.push(MessageSample {
                sample: u64::try_from(session_index * 4 + index + 1)?,
                role: MessageRole::Unclassified,
                bytes,
                context: Some(MessageContext {
                    source: "training source".into(),
                    scope: "training scope".into(),
                    session: u64::try_from(session_index + 1)?,
                    direction: Direction::FirstToSecond,
                }),
            });
        }
    }
    let training_ids = family_samples
        .iter()
        .map(|sample| sample.sample)
        .collect::<Vec<_>>();
    let family_report = discover_message_families(
        &family_samples,
        &training_ids,
        MessageFamilyLimits {
            max_selectors: 8,
            max_families_per_selector: 4,
            ..MessageFamilyLimits::default()
        },
    )?;
    assert!(
        family_report.selectors.iter().any(|selector| {
            selector
                .families
                .iter()
                .any(|family| family.training_samples == [1, 3, 5, 7])
                && selector
                    .families
                    .iter()
                    .any(|family| family.training_samples == [2, 4, 6, 8])
        }),
        "existing training-only family discovery did not separate the layouts: selectors={:?}, coverage={:?}",
        family_report.selectors,
        family_report.observation_coverage
    );
    let training = sampled_data_messages(&fixture.sessions[..2]);
    let heldout = sampled_data_messages(&fixture.sessions[2..]);
    let limits = fixture.policy.record_schema_proposal_limits;
    let report = analyze_record_schemas(&training, &heldout, limits)?;
    let Some(discovery) = report.discovery.as_ref() else {
        return Err("data-only proposal found no schema discovery space".into());
    };
    let recovers_all = discovery.surviving.iter().any(|hypothesis| {
        fixture
            .sessions
            .iter()
            .zip(&fixture.archives)
            .all(|(session, archive)| {
                let frames = session.messages.iter().step_by(2).collect::<Vec<_>>();
                let Ok(parsed) = frames
                    .iter()
                    .map(|frame| {
                        parse_records_with_limits(
                            frame,
                            &hypothesis.schema,
                            limits.discovery.record_limits,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                else {
                    return false;
                };
                let inputs = frames
                    .iter()
                    .zip(&parsed)
                    .map(|(frame, parsed)| RecordAssemblyInput::new(frame, parsed))
                    .collect::<Vec<_>>();
                assemble_record_groups_from_inputs(&inputs, limits.discovery.record_limits)
                    .is_ok_and(|assembly| {
                        assembly
                            .groups()
                            .iter()
                            .any(|group| group.candidate_bytes() == archive.as_slice())
                    })
            })
    });
    assert!(
        recovers_all,
        "data-only discovery did not retain a schema that assembles all sessions: examined={}; survivors={}",
        discovery.examined_combinations,
        discovery.surviving.len()
    );
    Ok(())
}

#[test]
fn training_data_family_has_a_strict_schema_that_assembles_every_full_session() -> TestResult<()> {
    assert_data_family_has_strict_schema(HeldoutChange::None)
}

#[test]
fn alternate_training_data_has_a_strict_schema_that_assembles_every_full_session() -> TestResult<()>
{
    assert_data_family_has_strict_schema(HeldoutChange::AlternateLayout)
}

#[test]
fn mixed_control_and_data_families_recover_each_independent_full_session() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::None)?;
    let report_results = run
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == REPORT_KIND)
        .take(4)
        .map(|node| {
            let report = decode_report(&run.case, node.id)?;
            Ok(json!({
                "result":report.get("result"),
                "reason":report.get("no_candidate_reason"),
            }))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let frame_count = run
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "custom_protocol_frame")
        .count();
    for archive in &run.archives {
        assert!(
            run.case.blobs().iter().any(|blob| blob.bytes == *archive),
            "each session must recover its exact archive; frame count: {frame_count}; report results: {report_results:?}; first omissions: {:?}",
            run.outcome.omissions.iter().take(4).collect::<Vec<_>>()
        );
    }
    assert!(run.outcome.validated_artifact_count >= run.archives.len());

    let mut all_frames = Vec::new();
    let mut data_frames = Vec::new();
    for session in &run.sessions {
        let mut frames = run
            .case
            .nodes()
            .iter()
            .filter(|node| {
                node.kind == "custom_protocol_frame"
                    && node.details.get("input_node").and_then(Value::as_u64)
                        == Some(session.run_node)
            })
            .map(|node| {
                node.details
                    .get("frame_index")
                    .and_then(Value::as_u64)
                    .map(|index| (index, node.id))
                    .ok_or("materialized frame is missing its index")
            })
            .collect::<Result<Vec<_>, _>>()?;
        frames.sort_unstable();
        assert_eq!(
            frames.len(),
            session.messages.len(),
            "all original control and data observations must remain in the Case"
        );
        data_frames.push(
            frames
                .iter()
                .filter_map(|(index, id)| index.is_multiple_of(2).then_some(*id))
                .collect::<Vec<_>>(),
        );
        all_frames.extend(frames.into_iter().map(|(_, id)| id));
    }

    let reports = run
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == REPORT_KIND)
        .map(|node| Ok((node.id, decode_report(&run.case, node.id)?)))
        .collect::<TestResult<Vec<_>>>()?;
    assert!(reports.iter().any(|(_, report)| {
        let examined = report.pointer("/family_search/groups_examined").and_then(Value::as_u64);
        let surviving = report.pointer("/family_search/groups_with_schemas").and_then(Value::as_u64);
        matches!((examined, surviving), (Some(examined), Some(surviving)) if examined >= surviving && surviving > 0)
    }), "the bounded family search must report actual examined groups and survivors");
    let expected_first_training = format!(
        "sha256:{}",
        l2_workbench::sha256(&run.sessions[0].messages[0])
    );
    assert!(
        reports.iter().any(|(_, report)| {
            report
                .pointer("/family_search/groups")
                .and_then(Value::as_array)
                .is_some_and(|groups| {
                    groups.iter().any(|group| {
                        group
                            .get("training_examples")
                            .and_then(Value::as_array)
                            .is_some_and(|frames| {
                                frames.iter().any(|frame| {
                                    frame.get("blob_id").and_then(Value::as_str)
                                        == Some(expected_first_training.as_str())
                                })
                            })
                    })
                })
        }),
        "the family search must identify the selected training frames"
    );
    let expected_data_count = data_frames.iter().map(Vec::len).sum::<usize>();
    let (report_node, report) = reports
        .iter()
        .find(|(_, report)| {
            report.pointer("/family_selection/selected_frame_count")
                == Some(&json!(expected_data_count))
                && report.pointer("/family_selection/excluded_frame_count")
                    == Some(&json!(all_frames.len() - expected_data_count))
        })
        .ok_or("the family selection must report all selected and excluded frames")?;
    let training = run.sessions[..2]
        .iter()
        .map(|session| session.episode_node)
        .collect::<Vec<_>>();
    let heldout = run.sessions[2..]
        .iter()
        .map(|session| session.episode_node)
        .collect::<Vec<_>>();
    assert_eq!(
        report.pointer("/partition/training_session_nodes"),
        Some(&json!(training))
    );
    assert_eq!(
        report.pointer("/partition/held_out_session_nodes"),
        Some(&json!(heldout))
    );
    assert_eq!(
        report.pointer("/family_selection/unassigned_frame_count"),
        Some(&json!(0))
    );

    let receipts = selected_record_receipt_ids(&run.case, *report_node)
        .into_iter()
        .map(|id| {
            let node = run.case.node(id).ok_or("record receipt is missing")?;
            let blob = node
                .blob
                .as_deref()
                .and_then(|id| run.case.blob(id))
                .ok_or("record receipt bytes are missing")?;
            Ok(serde_json::from_slice::<Value>(&blob.bytes)?)
        })
        .collect::<TestResult<Vec<_>>>()?;
    for (frames, archive) in data_frames.iter().zip(&run.archives) {
        let digest = l2_workbench::sha256(archive);
        assert!(
            receipts.iter().any(|receipt| {
                let applied = receipt
                    .get("inputs")
                    .and_then(Value::as_array)
                    .map(|inputs| {
                        inputs
                            .iter()
                            .filter_map(|input| input.get("input_node").and_then(Value::as_u64))
                            .collect::<Vec<_>>()
                    });
                applied.as_ref() == Some(frames)
                    && receipt_has_exact_artifact(receipt, &digest, archive.len())
            }),
            "each artifact must be tied to all of its selected data frames"
        );
    }
    Ok(())
}

#[test]
fn unseen_heldout_control_value_is_reported_without_discarding_data() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::UnknownControl)?;
    assert!(
        run.archives
            .iter()
            .all(|archive| { run.case.blobs().iter().any(|blob| blob.bytes == *archive) })
    );
    let reports = run
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == REPORT_KIND)
        .map(|node| decode_report(&run.case, node.id))
        .collect::<TestResult<Vec<_>>>()?;
    assert!(
        reports.iter().any(|report| {
            report.pointer("/family_selection/unassigned_frame_count") == Some(&json!(1))
                && report.pointer("/family_selection/application_complete") == Some(&json!(false))
        }),
        "a value absent from training must stay unassigned in application coverage"
    );
    Ok(())
}

#[test]
fn data_family_survives_when_training_controls_have_no_shared_selector() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::VariableControls)?;
    assert!(
        run.archives.iter().all(|archive| run
            .case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == *archive))
    );
    let controls = run
        .sessions
        .iter()
        .map(|session| session.messages.len() / 2)
        .sum::<usize>();
    assert!(
        run.case
            .nodes()
            .iter()
            .filter(|node| node.kind == REPORT_KIND)
            .any(|node| {
                decode_report(&run.case, node.id).is_ok_and(|report| {
                    report.pointer("/family_selection/unassigned_frame_count")
                        == Some(&json!(controls))
                        && report.pointer("/family_selection/application_complete")
                            == Some(&json!(false))
                })
            }),
        "variable control values must remain unassigned while data is recovered"
    );
    Ok(())
}

#[test]
fn alternate_field_widths_and_selector_offset_recover_each_session() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::AlternateLayout)?;
    if !run
        .archives
        .iter()
        .all(|archive| run.case.blobs().iter().any(|blob| blob.bytes == *archive))
    {
        let summaries = run.case.nodes().iter().filter(|node| node.kind == REPORT_KIND).take(8)
            .map(|node| {
                let report = decode_report(&run.case, node.id)?;
                Ok(json!({"result":report.get("result"),"reason":report.get("no_candidate_reason"),"family":report.get("family_selection"),"search":report.get("family_search")}))
            }).collect::<TestResult<Vec<_>>>()?;
        let expected_frames = run
            .sessions
            .iter()
            .map(|session| {
                (
                    session.episode_node,
                    session
                        .messages
                        .iter()
                        .take(4)
                        .step_by(2)
                        .map(|frame| l2_workbench::sha256(frame))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        return Err(format!(
            "alternate layout was not recovered; validated={}, expected_learning={expected_frames:?}, reports={summaries:?}",
            run.outcome.validated_artifact_count
        )
        .into());
    }
    assert!(run.outcome.validated_artifact_count >= run.archives.len());
    Ok(())
}

#[test]
fn uniform_schema_survivors_do_not_suppress_mixed_family_search() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::StructuredControls)?;
    assert!(
        run.archives.iter().all(|archive| run
            .case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == *archive))
    );
    let reports = run
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == REPORT_KIND)
        .map(|node| decode_report(&run.case, node.id))
        .collect::<TestResult<Vec<_>>>()?;
    assert!(
        reports.iter().any(
            |report| report.get("result") == Some(&json!("hypotheses_found"))
                && report
                    .pointer("/family_search/groups_with_schemas")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| count > 0)
        ),
        "a uniform schema survivor must not prevent learning separate supported message families"
    );
    assert!(reports.iter().any(|report| {
        report
            .get("family_selection")
            .is_some_and(|value| !value.is_null())
    }));
    Ok(())
}

#[test]
fn malformed_selected_heldout_data_is_rejected_by_the_full_session_parser() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::CorruptData)?;
    let session = run.sessions.get(2).ok_or("held-out session is missing")?;
    let final_data_index = u64::try_from(
        session
            .messages
            .len()
            .checked_sub(2)
            .ok_or("missing data")?,
    )?;
    let frame = run
        .case
        .nodes()
        .iter()
        .find(|node| {
            node.kind == "custom_protocol_frame"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(session.run_node)
                && node.details.get("frame_index").and_then(Value::as_u64) == Some(final_data_index)
        })
        .ok_or("malformed data frame is missing")?
        .id;
    assert!(
        run.outcome.omissions.iter().any(|omission| matches!(
            omission,
            RecoveryOmission::RecordInputRejected { input_node_id, .. } if *input_node_id == frame
        )),
        "the selected malformed record must be parsed and reported, not filtered away"
    );
    let expected = run.archives.get(2).ok_or("held-out archive is missing")?;
    assert!(!run.case.blobs().iter().any(|blob| blob.bytes == *expected));
    Ok(())
}

#[test]
fn mixed_families_without_structured_artifacts_publish_no_validated_artifacts() -> TestResult<()> {
    let run = execute_mixed_sessions(HeldoutChange::InvalidArtifacts)?;
    assert_eq!(
        run.outcome.validated_artifact_count, 0,
        "a coherent record layout cannot make arbitrary payload bytes a validated artifact"
    );
    Ok(())
}

#[test]
fn family_memory_limit_reports_incomplete_analysis_without_leaking_a_lease() -> TestResult<()> {
    let MixedFixture {
        mut case,
        sessions: _,
        archives: _,
        plan,
        policy,
    } = mixed_fixture(HeldoutChange::None)?;
    let memory = l2_workbench::job::MemoryBudget::new(0);
    let outcome =
        super::super::execute_internal(&mut case, &plan, &policy, true, None, Some(&memory), None)?;
    assert_eq!(outcome.validated_artifact_count, 0);
    assert!(
        case.nodes()
            .iter()
            .filter(|node| node.kind == REPORT_KIND)
            .any(|node| {
                decode_report(&case, node.id).is_ok_and(|report| {
                    report.get("strategy_omission") == Some(&json!("message_family_memory_limit"))
                        && report.get("search_exhaustive_within_plan") == Some(&json!(false))
                })
            })
    );
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn family_memory_admission_covers_recovery_and_releases_after_completion() -> TestResult<()> {
    let MixedFixture {
        mut case,
        sessions: _,
        archives,
        plan,
        policy,
    } = mixed_fixture(HeldoutChange::None)?;
    let memory = l2_workbench::job::MemoryBudget::new(256 * 1024 * 1024);
    let outcome =
        super::super::execute_internal(&mut case, &plan, &policy, true, None, Some(&memory), None)?;
    assert!(outcome.validated_artifact_count >= archives.len());
    assert!(
        archives
            .iter()
            .all(|archive| case.blobs().iter().any(|blob| blob.bytes == *archive))
    );
    let snapshot = memory.snapshot()?;
    assert!(snapshot.peak_bytes > 0);
    assert!(snapshot.peak_bytes <= snapshot.limit_bytes);
    assert_eq!(snapshot.used_bytes, 0);
    Ok(())
}

#[test]
fn funnel_distinguishes_uniform_failure_from_the_family_schema_survivor() -> TestResult<()> {
    let MixedFixture {
        mut case,
        sessions: _,
        archives: _,
        plan,
        policy,
    } = mixed_fixture(HeldoutChange::None)?;
    let job = l2_workbench::job::Job::new("mixed family funnel");
    let progress = super::super::JobProgress::new(job.clone());
    super::super::execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;
    let transitions = serde_json::to_value(job.snapshot()?.recovery_transitions)?;
    let stages = transitions
        .get("cohorts")
        .and_then(Value::as_array)
        .ok_or("cohort funnels are missing")?
        .iter()
        .flat_map(|cohort| {
            cohort
                .get("stages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|stage| stage.get("stage") == Some(&json!("schema")))
        .collect::<Vec<_>>();
    assert!(
        stages.iter().any(|stage| {
            stage
                .get("observed_candidates")
                .and_then(Value::as_u64)
                .is_some_and(|count| count >= 2)
                && stage
                    .get("candidates_with_survivors")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| count > 0)
        }),
        "the uniform and family learning batches must be counted separately: {stages:?}"
    );
    Ok(())
}

#[test]
fn checkpoint_restores_pending_family_assemblies_with_the_same_provenance() -> TestResult<()> {
    use super::super::execution_state::{SchedulerCursor, step};
    use super::super::{CaseIndex, CaseIndexScanLedger, checkpoint, finish_executor, test_support};
    use l2_workbench::evidence::CaseSnapshotLimits;

    let MixedFixture {
        case,
        sessions: _,
        archives,
        plan,
        policy,
    } = mixed_fixture(HeldoutChange::None)?;
    let mut uninterrupted = case.try_clone()?;
    // A cloned Case needs its own equivalent discovery snapshot and scan charge
    let mut expected_policy = normal_policy(&uninterrupted)?;
    expected_policy.record_schema_proposal_limits = policy.record_schema_proposal_limits;
    assert!(
        serde_json::to_vec(&expected_policy)? == serde_json::to_vec(&policy)?,
        "the two runs must use equivalent policy settings"
    );
    let expected = execute(&mut uninterrupted, &plan, &expected_policy)?;

    let mut running = case;
    let mut executor = test_support::build_executor(&mut running, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    let mut family_pending = false;
    let mut inspected_reports = std::collections::BTreeSet::new();
    let mut has_family_report = false;
    for _ in 0..20_000 {
        assert!(
            step(&mut executor, &mut cursor)?,
            "no family assembly was queued"
        );
        for node in executor
            .case
            .nodes()
            .iter()
            .filter(|node| node.kind == REPORT_KIND)
        {
            if inspected_reports.insert(node.id) {
                has_family_report |= decode_report(executor.case, node.id)?
                    .get("family_selection")
                    .is_some_and(|value| !value.is_null());
            }
        }
        if has_family_report && executor.pending_record_assembly_count > 0 {
            family_pending = true;
            break;
        }
    }
    assert!(family_pending, "no pending family assembly was found");
    // The queued schemas and their ordered selected input IDs must survive unchanged
    let pending_before = serde_json::to_vec(&executor.pending_record_assemblies)?;
    let snapshot_limits = CaseSnapshotLimits::new(64 * 1024 * 1024, 64 * 1024 * 1024);
    let mut graph = Vec::new();
    let mut blobs = Vec::new();
    executor
        .case
        .write_snapshot(&mut graph, &mut blobs, snapshot_limits)?;
    let mut state = Vec::new();
    checkpoint::write(&executor, &cursor, &mut state, 32 * 1024 * 1024)?;
    drop(executor);

    let (mut restored_case, _) =
        Case::from_snapshot(graph.as_slice(), blobs.as_slice(), snapshot_limits)?;
    assert_exact_case_equality(&restored_case, &running)?;
    drop(running);
    let (mut restored, mut restored_cursor) = checkpoint::read(
        &mut restored_case,
        &plan,
        &policy,
        state.as_slice(),
        32 * 1024 * 1024,
        None,
    )?;
    let pending_after = serde_json::to_vec(&restored.pending_record_assemblies)?;
    assert!(
        pending_before == pending_after,
        "pending family assembly membership changed during restoration"
    );
    while step(&mut restored, &mut restored_cursor)? {}
    let actual = finish_executor(restored)?;

    assert_exact_case_equality(&restored_case, &uninterrupted)?;
    assert!(
        actual.candidates == expected.candidates,
        "candidate histories differ: actual={}, expected={}",
        actual.candidates.len(),
        expected.candidates.len()
    );
    assert!(
        actual.omissions == expected.omissions,
        "omission histories differ: actual={}, expected={}",
        actual.omissions.len(),
        expected.omissions.len()
    );
    assert_eq!(actual.resources, expected.resources);
    assert!(archives.iter().all(|archive| {
        restored_case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == *archive)
    }));
    Ok(())
}
