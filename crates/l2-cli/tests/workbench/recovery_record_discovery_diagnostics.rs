use super::super::{JobProgress, RecoveryPlan, execute_internal, normal_policy};
use super::{TestResult, add_unframed_sessions, capture, decode_report};
use l2_workbench::{
    evidence::Case,
    job::{
        Counter, Job, RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
    },
    protocol::FramingKind,
    recovery::{RecoveryCandidateState, RecoveryResult, RecoveryTask},
};

fn aligned_archive(contents: &[u8]) -> TestResult<Vec<u8>> {
    for padding in 0..5 {
        let mut member = contents.to_vec();
        member.resize(member.len() + padding, b'~');
        let archive = super::super::tests::stored_zip_entries(&[(b"data.bin", &member)])?;
        if archive.len().is_multiple_of(5) {
            return Ok(archive);
        }
    }
    Err("archive could not be aligned to the independent record payload".into())
}

fn message_parts(archive: &[u8], identifier: [u8; 3]) -> TestResult<Vec<Vec<u8>>> {
    archive
        .as_chunks::<5>()
        .0
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let mut frame = Vec::with_capacity(11);
            frame.extend_from_slice(&u16::try_from(index)?.to_be_bytes());
            frame.push(u8::try_from(payload.len())?);
            frame.extend_from_slice(&identifier);
            frame.extend_from_slice(payload);
            Ok(frame)
        })
        .collect()
}

#[test]
fn funnel_keeps_separate_cohorts_and_sessions_with_observed_schema_survivors() -> TestResult<()> {
    let first = aligned_archive(b"funnel first cohort private bytes")?;
    let second = aligned_archive(b"funnel second cohort private bytes")?;
    let mut case = Case::new();
    let source = capture(&mut case, "funnel separate cohorts")?;
    let sessions = add_unframed_sessions(
        &mut case,
        &source,
        vec![
            (
                "first",
                vec![
                    message_parts(&first, *b"A5m")?,
                    message_parts(&first, *b"B6n")?,
                ],
            ),
            (
                "second",
                vec![
                    message_parts(&second, *b"C7p")?,
                    message_parts(&second, *b"D8q")?,
                ],
            ),
        ],
    )?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 11 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let job = Job::new("cohort funnel");
    let progress = JobProgress::new(job.clone());
    execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;

    let encoded = serde_json::to_string(&job.snapshot()?.recovery_transitions)?;
    assert!(
        !encoded.contains("private bytes"),
        "diagnostics must not contain captured bytes"
    );
    let summary: serde_json::Value = serde_json::from_str(&encoded)?;
    assert_distinct_funnel_cohorts(&summary, &source, &sessions)
}

fn assert_distinct_funnel_cohorts(
    summary: &serde_json::Value,
    source: &str,
    sessions: &[super::UnframedSession],
) -> TestResult<()> {
    let cohorts = summary
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .ok_or("per-cohort funnel is missing")?;
    assert_eq!(cohorts.len(), 2, "distinct scopes must not be merged");
    let source_digest = source
        .strip_prefix("sha256:")
        .ok_or("invalid source identity")?;
    for group in sessions.as_chunks::<2>().0 {
        let session_nodes = group
            .iter()
            .map(|session| session.episode_node)
            .collect::<Vec<_>>();
        let cohort = cohorts
            .iter()
            .find(|cohort| cohort.get("sessions") == Some(&serde_json::json!(session_nodes)))
            .ok_or("funnel must retain each cohort's distinct session identities")?;
        assert_eq!(
            cohort.get("source_sha256"),
            Some(&serde_json::json!(source_digest))
        );
        assert!(
            cohort
                .get("cohort_sha256")
                .and_then(serde_json::Value::as_str)
                .is_some()
        );
        let stages = cohort
            .get("stages")
            .and_then(serde_json::Value::as_array)
            .ok_or("cohort stages are missing")?;
        assert!(
            stages.iter().any(|stage| {
                stage.get("stage") == Some(&serde_json::json!("schema"))
                    && stage
                        .get("candidates_with_survivors")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|count| count > 0)
            }),
            "a surviving schema must be attributed to its cohort"
        );
    }
    Ok(())
}

#[test]
fn independent_alternative_order_reaches_schema_assembly_and_exact_validated_artifacts()
-> TestResult<()> {
    let archives = [
        aligned_archive(b"first external session")?,
        aligned_archive(b"second external session")?,
    ];
    let sessions = vec![
        message_parts(&archives[0], *b"A7p")?,
        message_parts(&archives[1], *b"B3q")?,
    ];
    let mut case = Case::new();
    let source_id = capture(&mut case, "alternative-order-diagnostics")?;
    add_unframed_sessions(&mut case, &source_id, vec![("independent", sessions)])?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 11 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let job = Job::new("alternative order inference");
    let progress = JobProgress::new(job.clone());
    let outcome = execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;
    assert!(
        outcome.candidates.iter().any(|candidate| {
            candidate.task() == &RecoveryTask::RecordDiscovery
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Hypothesis { .. },
                        ..
                    }
                )
        }),
        "a framed cohort must reach schema discovery"
    );
    assert!(
        outcome.candidates.iter().any(|candidate| {
            matches!(candidate.task(), RecoveryTask::AssembleRecords(_))
                && matches!(
                    candidate.state(),
                    RecoveryCandidateState::Finished {
                        result: RecoveryResult::Derived { .. },
                        ..
                    }
                )
        }),
        "a discovered schema must reach actual record assembly"
    );
    for archive in &archives {
        assert!(
            case.blobs().iter().any(|blob| blob.bytes == *archive),
            "an independent session's exact archive is missing"
        );
    }
    assert!(
        outcome.validated_artifact_count >= 2,
        "the full independent archives must pass structural validation"
    );
    assert_pipeline_progress(&case, &job)
}

fn assert_pipeline_progress(case: &Case, job: &Job) -> TestResult<()> {
    let snapshot = job.snapshot()?;
    let applied_inputs = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "record_parse_receipt")
        .map(|node| -> TestResult<usize> {
            let blob_id = node.blob.as_deref().ok_or("record receipt has no bytes")?;
            let blob = case.blob(blob_id).ok_or("record receipt blob is missing")?;
            let receipt: serde_json::Value = serde_json::from_slice(&blob.bytes)?;
            Ok(receipt
                .get("inputs")
                .and_then(serde_json::Value::as_array)
                .ok_or("record receipt omitted input applications")?
                .len())
        })
        .collect::<TestResult<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    assert!(applied_inputs > 0);
    assert_eq!(
        snapshot.counters.get(&Counter::RecordInputApplications),
        Some(&u64::try_from(applied_inputs)?),
        "only committed parser input applications are counted, including repeated schema trials"
    );
    let records = snapshot.recovery_transitions.records();
    assert!(
        records
            .iter()
            .any(|record| record.stage() == RecoveryTransitionStage::Schema
                && record.outcome() == RecoveryTransitionOutcome::LearningSampleOmitted),
        "bounded learning samples are reported separately from input eligibility failures"
    );
    for (stage, disposition) in [
        (
            RecoveryTransitionStage::Framing,
            RecoveryTransitionOutcome::Derived,
        ),
        (
            RecoveryTransitionStage::Schema,
            RecoveryTransitionOutcome::ReportRetained,
        ),
        (
            RecoveryTransitionStage::Assembly,
            RecoveryTransitionOutcome::Derived,
        ),
        (
            RecoveryTransitionStage::Validation,
            RecoveryTransitionOutcome::Validated,
        ),
    ] {
        let observed = records
            .iter()
            .find(|record| record.stage() == stage && record.outcome() == disposition)
            .ok_or("expected observed pipeline transition is missing")?;
        let Some(RecoveryTransitionSample::Candidate(sample)) = observed.sample() else {
            return Err("candidate transition must retain a bounded evidence reference".into());
        };
        let node = case
            .node(sample.input_node_id)
            .ok_or("transition input node is missing")?;
        let blob = node.blob.as_deref().ok_or("transition input has no blob")?;
        let expected = blob
            .strip_prefix("sha256:")
            .and_then(l2_workbench::parse_sha256_digest);
        assert_eq!(
            expected,
            Some(sample.input_blob_sha256),
            "transition input identity must bind the exact Case bytes"
        );
        assert!(
            sample
                .evidence_node_id
                .is_some_and(|node_id| case.node(node_id).is_some()),
            "completed events must identify their retained evidence"
        );
    }
    Ok(())
}

#[test]
fn late_record_family_is_learned_after_uninformative_prefix_without_using_held_out_sessions()
-> TestResult<()> {
    let archives = [
        aligned_archive(b"late-family-first")?,
        aligned_archive(b"late-family-second")?,
    ];
    let mut sessions = Vec::new();
    for (archive, identifier) in archives.iter().zip([*b"P2r", *b"Q8s"]) {
        let mut frames = vec![vec![0; 11]; 3];
        frames.extend(message_parts(archive, identifier)?);
        sessions.push(frames);
    }
    let mut case = Case::new();
    let source_id = capture(&mut case, "late-record-family")?;
    add_unframed_sessions(&mut case, &source_id, vec![("late-family", sessions)])?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 11 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let outcome = execute_internal(&mut case, &plan, &policy, true, None, None, None)?;
    for archive in &archives {
        assert!(
            case.blobs().iter().any(|blob| blob.bytes == *archive),
            "a later repeated record family must recover the exact independent session artifact"
        );
    }
    assert!(outcome.validated_artifact_count >= 2);
    let reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_record_discovery_report")
        .map(|node| decode_report(&case, node.id))
        .collect::<TestResult<Vec<_>>>()?;
    assert!(
        reports
            .iter()
            .any(|report| report.get("result") == Some(&serde_json::json!("no_candidates")))
    );
    let later = reports
        .iter()
        .find(|report| {
            report.pointer("/partition/sampling") == Some(&serde_json::json!("session_suffix"))
                && report.get("result") == Some(&serde_json::json!("hypotheses_found"))
        })
        .ok_or("later session samples must produce an independently checked schema report")?;
    let training = later
        .pointer("/partition/training_session_nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or("training sessions missing")?;
    let heldout = later
        .pointer("/partition/held_out_session_nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or("held-out sessions missing")?;
    assert!(!training.is_empty() && !heldout.is_empty());
    assert!(
        training.iter().all(|session| !heldout.contains(session)),
        "the sampled held-out session cannot train a rule"
    );
    Ok(())
}

#[test]
fn empty_discovery_report_is_not_counted_as_a_surviving_schema() -> TestResult<()> {
    let mut case = Case::new();
    let source_id = capture(&mut case, "no-schema-transition")?;
    add_unframed_sessions(
        &mut case,
        &source_id,
        vec![("noise", vec![vec![vec![0], vec![0]]])],
    )?;
    let policy = normal_policy(&case)?;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 1 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let job = Job::new("empty schema report");
    let progress = JobProgress::new(job.clone());
    execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;
    let snapshot = job.snapshot()?;
    let records = snapshot.recovery_transitions.records();
    assert!(
        records
            .iter()
            .any(|record| record.stage() == RecoveryTransitionStage::Schema
                && record.outcome() == RecoveryTransitionOutcome::ReportRetained)
    );
    assert!(
        !records
            .iter()
            .any(|record| record.stage() == RecoveryTransitionStage::Schema
                && record.outcome() == RecoveryTransitionOutcome::Hypothesis),
        "an empty discovery report is not evidence of a surviving schema"
    );
    let report_node = case
        .nodes()
        .iter()
        .find(|node| node.kind == "recovery_record_discovery_report")
        .ok_or("schema report missing")?;
    let report = decode_report(&case, report_node.id)?;
    let reason = report
        .get("no_candidate_reason")
        .and_then(serde_json::Value::as_str)
        .ok_or("schema failure reason missing")?;
    let summary = serde_json::to_value(&snapshot.recovery_transitions)?;
    let cohort = summary
        .get("cohorts")
        .and_then(serde_json::Value::as_array)
        .and_then(|cohorts| cohorts.first())
        .ok_or("schema cohort missing")?;
    let stages = cohort
        .get("stages")
        .and_then(serde_json::Value::as_array)
        .ok_or("cohort stages missing")?;
    let schema = stages
        .iter()
        .find(|stage| stage.get("stage") == Some(&serde_json::json!("schema")))
        .ok_or("schema stage missing")?;
    assert!(
        schema
            .get("no_survivor_reasons")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|reasons| reasons.contains(&serde_json::json!(reason))),
        "the funnel must retain the observed report reason"
    );
    Ok(())
}

#[test]
fn partially_rejected_record_batches_preserve_exact_input_contradictions() -> TestResult<()> {
    let archives = [
        aligned_archive(b"partially-rejected-one")?,
        aligned_archive(b"partially-rejected-two")?,
    ];
    let mut sessions = Vec::new();
    for (archive, identifier) in archives.iter().zip([*b"R6t", *b"S4u"]) {
        let mut frames = vec![vec![0; 11]; 3];
        frames.extend(message_parts(archive, identifier)?);
        sessions.push(frames);
    }
    let mut case = Case::new();
    let source_id = capture(&mut case, "rejected-input-transitions")?;
    add_unframed_sessions(&mut case, &source_id, vec![("partial", sessions)])?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 11 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let job = Job::new("partial record rejection");
    let progress = JobProgress::new(job.clone());
    let outcome = execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;
    let snapshot = job.snapshot()?;
    let rejection = snapshot
        .recovery_transitions
        .records()
        .iter()
        .find(|record| {
            record.stage() == RecoveryTransitionStage::Assembly
                && record.outcome() == RecoveryTransitionOutcome::InputContradicted
        })
        .ok_or("a rejected input from a partly successful batch must be reported")?;
    let Some(RecoveryTransitionSample::Candidate(sample)) = rejection.sample() else {
        return Err("rejected input sample is missing".into());
    };
    assert!(outcome.omissions.iter().any(|omission| matches!(omission,
        super::super::RecoveryOmission::RecordInputRejected { input_node_id, .. } if *input_node_id == sample.input_node_id)));
    let node = case
        .node(sample.input_node_id)
        .ok_or("rejected frame is missing")?;
    let actual_source = node
        .ranges
        .first()
        .ok_or("rejected frame has no source provenance")?;
    let recorded_source = sample
        .source_range
        .ok_or("transition did not retain its source range")?;
    assert_eq!(recorded_source.offset, actual_source.offset);
    assert_eq!(recorded_source.length, actual_source.length);
    assert_eq!(recorded_source.packet, actual_source.packet);
    assert_eq!(
        actual_source
            .source
            .strip_prefix("sha256:")
            .and_then(l2_workbench::parse_sha256_digest),
        Some(recorded_source.source_sha256)
    );
    assert!(
        sample
            .evidence_node_id
            .is_some_and(|id| case.node(id).is_some())
    );
    assert!(
        archives
            .iter()
            .any(|archive| case.blobs().iter().any(|blob| blob.bytes == *archive)),
        "a rejected control frame must not hide a separately validated data artifact"
    );
    Ok(())
}

#[test]
fn contradictory_held_out_suffix_cannot_validate_the_training_schema() -> TestResult<()> {
    use l2_workbench::protocol::parse_records;

    let training_archive = aligned_archive(b"late-family-training")?;
    let heldout_archive = aligned_archive(b"late-family-heldout")?;
    let mut training = vec![vec![0; 11]; 3];
    training.extend(message_parts(&training_archive, *b"T2v")?);
    let mut heldout = vec![vec![0; 11]; 3];
    let mut contradictory = message_parts(&heldout_archive, *b"U3w")?;
    for frame in &mut contradictory {
        *frame.get_mut(2).ok_or("held-out length field is missing")? = 6;
    }
    heldout.extend(contradictory.clone());
    let expected = alternative_schema();
    assert!(
        parse_records(
            contradictory.first().ok_or("held-out record is missing")?,
            &expected
        )
        .is_err(),
        "the held-out length must contradict the training schema"
    );
    let mut case = Case::new();
    let source_id = capture(&mut case, "contradictory-heldout-suffix")?;
    add_unframed_sessions(
        &mut case,
        &source_id,
        vec![("contradictory", vec![training, heldout])],
    )?;
    let mut policy = normal_policy(&case)?;
    policy.record_schema_proposal_limits.discovery.max_messages = 4;
    let plan = RecoveryPlan {
        framings: vec![FramingKind::FixedSize { bytes: 11 }],
        discover_records: true,
        ..RecoveryPlan::default()
    };
    execute_internal(&mut case, &plan, &policy, true, None, None, None)?;
    let reports = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "recovery_record_discovery_report")
        .map(|node| decode_report(&case, node.id))
        .collect::<TestResult<Vec<_>>>()?;
    let suffix = reports
        .iter()
        .find(|report| {
            report.pointer("/partition/sampling") == Some(&serde_json::json!("session_suffix"))
        })
        .ok_or("bounded later-session analysis is missing")?;
    let survivors = suffix
        .pointer("/schema_discovery/surviving")
        .and_then(serde_json::Value::as_array)
        .ok_or("suffix report has no strict parser results")?;
    let expected_json = serde_json::to_value(&expected)?;
    assert!(
        survivors
            .iter()
            .all(|candidate| candidate.get("schema") != Some(&expected_json)),
        "a schema contradicted by an independent held-out session cannot survive"
    );
    assert!(
        !case
            .blobs()
            .iter()
            .any(|blob| blob.bytes == heldout_archive),
        "a contradictory session must not publish its intended but unassembled bytes"
    );
    Ok(())
}

fn alternative_schema() -> l2_workbench::protocol::RecordSchema {
    use l2_workbench::protocol::{
        ByteField, ByteOrder, IntegerField, RecordCount, RecordLengthMeaning, RecordSchema,
    };
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 3,
            width: 3,
        },
        sequence: IntegerField {
            offset: 0,
            width: 2,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 6,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

#[test]
fn record_cohort_events_bind_admitted_and_omitted_frames_to_their_source() -> TestResult<()> {
    use super::{add_materialized_session, add_unmaterialized_frame, record, recovery_plan};
    use l2_workbench::job::{RecoveryCohortReason, RecoveryTransitionSample};
    let mut case = Case::new();
    let source = capture(&mut case, "record-cohort-transitions")?;
    let messages = [record(b"abc", 1, b"hello"), record(b"abc", 2, b"world")];
    let session = add_materialized_session(
        &mut case,
        &source,
        "cohort",
        10,
        0,
        &messages,
        &FramingKind::FixedSize { bytes: 14 },
    )?;
    let omitted = add_unmaterialized_frame(
        &mut case,
        &source,
        30,
        Some(serde_json::json!({"kind":"caller_supplied"})),
    )?;
    let policy = normal_policy(&case)?;
    let job = Job::new("record cohort transitions");
    let progress = JobProgress::new(job.clone());
    let plan = recovery_plan();
    execute_internal(&mut case, &plan, &policy, true, Some(&progress), None, None)?;
    let snapshot = job.snapshot()?;
    let source_digest = source
        .strip_prefix("sha256:")
        .and_then(l2_workbench::parse_sha256_digest)
        .ok_or("invalid source identity")?;
    for (outcome, expected_node, reason) in [
        (
            RecoveryTransitionOutcome::CohortAdmitted,
            *session
                .frame_nodes
                .first()
                .ok_or("missing admitted frame")?,
            RecoveryCohortReason::Admitted,
        ),
        (
            RecoveryTransitionOutcome::CohortOmitted,
            omitted,
            RecoveryCohortReason::MissingMaterializationReceipt,
        ),
    ] {
        let record = snapshot
            .recovery_transitions
            .records()
            .iter()
            .find(|record| {
                record.stage() == RecoveryTransitionStage::Schema && record.outcome() == outcome
            })
            .ok_or("record cohort transition is missing")?;
        let Some(RecoveryTransitionSample::Cohort(sample)) = record.sample() else {
            return Err("record cohort source sample is missing".into());
        };
        assert_eq!(sample.source_sha256, Some(source_digest));
        assert_eq!(sample.input_node_id, Some(expected_node));
        assert_eq!(sample.reason, reason);
        if outcome == RecoveryTransitionOutcome::CohortAdmitted {
            assert!(sample.candidate_index.is_some());
            assert!(sample.input_batch_sha256.is_some());
            assert!(sample.task_sha256.is_some());
        } else {
            assert_eq!(sample.candidate_index, None);
        }
        let node = case
            .node(expected_node)
            .ok_or("cohort input node is missing")?;
        let digest = node
            .blob
            .as_deref()
            .and_then(|blob| blob.strip_prefix("sha256:"))
            .and_then(l2_workbench::parse_sha256_digest);
        assert_eq!(sample.input_blob_sha256, digest);
    }
    Ok(())
}
