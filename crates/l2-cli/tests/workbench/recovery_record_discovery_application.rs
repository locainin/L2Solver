use super::super::{RecoveryExecutionOutcome, RecoveryOmission, execute, normal_policy};
use super::{
    RecoveryPlan, TestResult, UnframedSession, add_unframed_sessions, candidate_frame_ids, capture,
    decode_report, receipt_has_exact_artifact, record, report_node, report_schemas,
    selected_record_receipt_ids,
};
use l2_workbench::{
    evidence::Case,
    protocol::{FramingKind, RecordSchema},
    recovery::RecoveryTask,
};
use serde_json::{Value, json};

struct BoundedLearningRun {
    case: Case,
    sessions: Vec<UnframedSession>,
    archives: [Vec<u8>; 2],
    outcome: RecoveryExecutionOutcome,
}

struct BoundedLearningEvidence {
    report_node_id: u64,
    report: Value,
    full_session_frames: Vec<Vec<u64>>,
    schemas: Vec<RecordSchema>,
}

#[test]
fn bounded_learning_applies_the_frozen_schema_to_full_sessions() -> TestResult<()> {
    let BoundedLearningRun {
        case,
        sessions,
        archives,
        outcome,
    } = execute_bounded_learning_archive_fixture(false)?;
    let BoundedLearningEvidence {
        report_node_id,
        report,
        full_session_frames,
        schemas,
    } = assert_bounded_learning_application(&case, &outcome, &sessions)?;

    assert!(
        archives
            .iter()
            .all(|archive| case.blobs().iter().any(|blob| blob.bytes == *archive)),
        "late records from each full session must contribute to the exact recovered archive"
    );
    assert!(outcome.validated_artifact_count >= archives.len());
    assert!(
        super::super::discovery_input_coverage_complete(&outcome.omissions),
        "a bounded learning sample must not claim that retained application inputs were lost"
    );
    assert!(
        !outcome.omissions.iter().any(|omission| matches!(
            omission,
            RecoveryOmission::RecordDiscoveryInputs { omitted_frames, .. } if *omitted_frames > 0
        )),
        "training exclusions must be distinct from ineligible record inputs"
    );
    assert!(
        !outcome.complete,
        "bounded learning omissions remain visible"
    );
    assert_full_session_schema_candidates(&outcome, &schemas, &full_session_frames);
    for (frames, archive) in full_session_frames.iter().zip(&archives) {
        let receipts = selected_full_session_receipts(&case, report_node_id, frames)?;
        let expected_sha256 = l2_workbench::sha256(archive);
        assert!(
            receipts.iter().any(|receipt| {
                receipt_has_exact_artifact(receipt, &expected_sha256, archive.len())
            }),
            "the selected receipt must bind the exact archive to every full-session input"
        );
    }
    assert_learning_omission_is_reported(&outcome, &report, &full_session_frames);
    Ok(())
}

#[test]
fn a_corrupt_late_frame_is_rejected_after_bounded_schema_learning() -> TestResult<()> {
    let BoundedLearningRun {
        case,
        sessions,
        archives,
        outcome,
    } = execute_bounded_learning_archive_fixture(true)?;
    let BoundedLearningEvidence {
        report_node_id,
        report,
        full_session_frames,
        schemas,
    } = assert_bounded_learning_application(&case, &outcome, &sessions)?;
    let corrupt_frame = full_session_frames
        .get(1)
        .and_then(|frames| frames.last())
        .copied()
        .ok_or("corrupt held-out frame is missing")?;
    let valid_archive = archives.first().ok_or("valid session archive is missing")?;
    let corrupt_archive = archives
        .get(1)
        .ok_or("corrupt session archive is missing")?;

    assert!(
        case.blobs().iter().any(|blob| blob.bytes == *valid_archive),
        "the unaffected session must still recover its exact archive"
    );
    assert!(
        !case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == *corrupt_archive),
        "a late malformed record must prevent claiming its incomplete archive"
    );
    assert!(
        outcome.omissions.iter().any(|omission| matches!(
            omission,
            RecoveryOmission::RecordInputRejected {
                input_node_id,
                ..
            } if *input_node_id == corrupt_frame
        )),
        "the strict full-session parser must identify the rejected late input"
    );
    assert!(
        !outcome.complete,
        "learning and application omissions stay visible"
    );
    assert_full_session_schema_candidates(&outcome, &schemas, &full_session_frames);
    let valid_frames = full_session_frames
        .first()
        .ok_or("valid full session is missing")?;
    let valid_receipts = selected_full_session_receipts(&case, report_node_id, valid_frames)?;
    let expected_sha256 = l2_workbench::sha256(valid_archive);
    assert!(
        valid_receipts.iter().any(|receipt| {
            receipt_has_exact_artifact(receipt, &expected_sha256, valid_archive.len())
        }),
        "the unaffected session receipt must bind its exact archive to all inputs"
    );
    let corrupt_frames = full_session_frames
        .get(1)
        .ok_or("corrupt full session is missing")?;
    let corrupt_receipts = selected_full_session_receipts(&case, report_node_id, corrupt_frames)?;
    let mut late_rejection_found = false;
    for receipt in &corrupt_receipts {
        late_rejection_found |= receipt_rejects_frame(receipt, corrupt_frame)?;
    }
    assert!(
        late_rejection_found,
        "the full-session receipt must retain the late strict-parse rejection"
    );
    assert_learning_omission_is_reported(&outcome, &report, &full_session_frames);
    Ok(())
}

fn execute_bounded_learning_archive_fixture(
    corrupt_second_session_tail: bool,
) -> TestResult<BoundedLearningRun> {
    let archives = [
        aligned_stored_zip(b"first session member")?,
        aligned_stored_zip(b"second session member")?,
    ];
    let mut messages = archives
        .iter()
        .map(|archive| archive_record_messages(archive))
        .collect::<TestResult<Vec<_>>>()?;
    if corrupt_second_session_tail {
        let final_record = messages
            .get_mut(1)
            .and_then(|session| session.last_mut())
            .ok_or("second session has no late record")?;
        // The frame remains bounded, while its declared payload length contradicts its bytes
        *final_record
            .get_mut(8)
            .ok_or("final record length field is missing")? = 4;
    }

    let mut case = Case::new();
    let source = capture(&mut case, "bounded-record-learning-application")?;
    let sessions = add_unframed_sessions(&mut case, &source, vec![("bounded-learning", messages)])?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    policy
        .record_schema_proposal_limits
        .discovery
        .record_limits
        .max_input_bytes = 56;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 14 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let outcome = execute(&mut case, &plan, &policy)?;
    Ok(BoundedLearningRun {
        case,
        sessions,
        archives,
        outcome,
    })
}

fn aligned_stored_zip(member: &[u8]) -> TestResult<Vec<u8>> {
    for padding in 0..5 {
        let mut contents = member.to_vec();
        contents.resize(contents.len() + padding, b'!');
        let archive = super::super::tests::stored_zip_entries(&[(b"member.bin", &contents)])?;
        if archive.len().is_multiple_of(5) {
            return Ok(archive);
        }
    }
    Err("could not align stored ZIP length to the record payload width".into())
}

fn archive_record_messages(archive: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    if !archive.len().is_multiple_of(5) {
        return Err("record archive must align to complete payload chunks".into());
    }
    archive
        .chunks_exact(5)
        .enumerate()
        .map(|(index, payload)| Ok(record(b"\x19\x82\xd1", u16::try_from(index)?, payload)))
        .collect()
}

fn assert_bounded_learning_application(
    case: &Case,
    outcome: &RecoveryExecutionOutcome,
    sessions: &[UnframedSession],
) -> TestResult<BoundedLearningEvidence> {
    let full_session_frames = sessions
        .iter()
        .map(|session| materialized_frames_for_run(case, session.run_node))
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(full_session_frames.len(), 2);
    assert!(full_session_frames.iter().all(|frames| frames.len() > 2));
    let learned_frames = full_session_frames
        .iter()
        .flat_map(|frames| frames.iter().take(2).copied())
        .collect::<Vec<_>>();
    let discovery = outcome
        .candidates
        .iter()
        .find(|candidate| {
            candidate.task() == &RecoveryTask::RecordDiscovery
                && candidate_frame_ids(candidate) == learned_frames
        })
        .ok_or("bounded record discovery candidate is missing")?;
    let report_node_id = report_node(discovery)?;
    let report = decode_report(case, report_node_id)?;
    let report_refs = report
        .pointer("/input_frame_refs")
        .and_then(Value::as_array)
        .ok_or("record report omitted its bounded learning references")?;
    let report_frame_ids = report_refs
        .iter()
        .map(|reference| reference.as_array()?.first()?.as_u64())
        .collect::<Option<Vec<_>>>()
        .ok_or("record report has an invalid learning frame reference")?;
    assert_eq!(report_frame_ids, learned_frames);
    assert_eq!(
        report.pointer("/application/eligible_frame_count"),
        Some(&json!(
            full_session_frames.iter().map(Vec::len).sum::<usize>()
        ))
    );
    assert_eq!(
        report.pointer("/application/session_count"),
        Some(&json!(2))
    );
    assert_eq!(
        report.pointer("/application/learning_sampled_frame_count"),
        Some(&json!(4))
    );
    assert_eq!(
        report.pointer("/input_omissions/eligibility_omitted_frame_count"),
        Some(&json!(0)),
        "learning limits do not make otherwise eligible frames fail provenance checks"
    );

    assert_eq!(
        report.pointer("/input_omissions/learning_budget_omitted_frame_count"),
        Some(&json!(
            full_session_frames.iter().map(Vec::len).sum::<usize>() - learned_frames.len()
        ))
    );
    let schemas = report_schemas(&report)?;
    assert!(
        !schemas.is_empty(),
        "the bounded training prefix must retain a schema"
    );
    Ok(BoundedLearningEvidence {
        report_node_id,
        report,
        full_session_frames,
        schemas,
    })
}

fn assert_full_session_schema_candidates(
    outcome: &RecoveryExecutionOutcome,
    schemas: &[RecordSchema],
    full_session_frames: &[Vec<u64>],
) {
    for expected_frames in full_session_frames {
        assert!(
            outcome.candidates.iter().any(|candidate| {
                candidate_frame_ids(candidate) == *expected_frames
                    && matches!(candidate.task(), RecoveryTask::AssembleRecords(schema) if schemas.contains(schema))
            }),
            "a retained schema must be applied to every full session, including frames omitted from learning: {expected_frames:?}"
        );
    }
}

fn selected_full_session_receipts(
    case: &Case,
    report_node_id: u64,
    expected_frames: &[u64],
) -> TestResult<Vec<Value>> {
    let mut matching = Vec::new();
    for receipt_id in selected_record_receipt_ids(case, report_node_id) {
        let receipt_node = case
            .node(receipt_id)
            .ok_or("selected record receipt is missing")?;
        let receipt = receipt_json(case, receipt_node)?;
        if receipt_input_node_ids(&receipt)? == expected_frames {
            matching.push(receipt);
        }
    }
    Ok(matching)
}

fn receipt_rejects_frame(receipt: &Value, rejected_frame: u64) -> TestResult<bool> {
    let inputs = receipt
        .pointer("/inputs")
        .and_then(Value::as_array)
        .ok_or("record receipt omitted its full input list")?;
    Ok(inputs.iter().any(|input| {
        input.get("input_node").and_then(Value::as_u64) == Some(rejected_frame)
            && input.get("parse_error").and_then(Value::as_str).is_some()
    }))
}

fn receipt_json(case: &Case, receipt_node: &l2_workbench::evidence::Node) -> TestResult<Value> {
    let blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or("record receipt has no serialized bytes")?;
    let blob = case
        .blob(blob_id)
        .ok_or("record receipt bytes are missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

fn receipt_input_node_ids(receipt: &Value) -> TestResult<Vec<u64>> {
    let inputs = receipt
        .pointer("/inputs")
        .and_then(Value::as_array)
        .ok_or("record receipt omitted its full input list")?;
    inputs
        .iter()
        .map(|input| {
            input
                .get("input_node")
                .and_then(Value::as_u64)
                .ok_or_else(|| std::io::Error::other("record receipt input identity is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn materialized_frames_for_run(case: &Case, run_node: u64) -> TestResult<Vec<u64>> {
    let mut frames = case
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == "custom_protocol_frame"
                && node.details.get("input_node").and_then(Value::as_u64) == Some(run_node)
        })
        .map(|node| {
            let frame_index = node
                .details
                .get("frame_index")
                .and_then(Value::as_u64)
                .ok_or("materialized frame index is missing")?;
            Ok((frame_index, node.id))
        })
        .collect::<TestResult<Vec<_>>>()?;
    frames.sort_unstable_by_key(|(frame_index, _)| *frame_index);
    Ok(frames.into_iter().map(|(_, node_id)| node_id).collect())
}

fn assert_learning_omission_is_reported(
    outcome: &RecoveryExecutionOutcome,
    report: &Value,
    full_session_frames: &[Vec<u64>],
) {
    let total_frames = full_session_frames.iter().map(Vec::len).sum::<usize>();
    assert!(total_frames > 4, "fixture must exceed the learning cap");
    let omitted_frames = total_frames - 4;
    assert!(outcome.omissions.iter().any(|omission| matches!(
        omission,
        RecoveryOmission::RecordDiscoveryLearningSample {
            unsampled_frames: omitted,
            ..
        } if *omitted == omitted_frames
    )));
    assert_eq!(
        report.pointer("/input_omissions/learning_budget_omitted_frame_count"),
        Some(&json!(omitted_frames))
    );
}
