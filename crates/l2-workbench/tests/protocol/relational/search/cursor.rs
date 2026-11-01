use super::{
    OwnedRecord, RelationalCandidateEvaluation, RelationalParserScope,
    RelationalTransformEvaluationOptions, TestResult, borrow_samples, search_plan,
    synthetic_sessions,
};
use l2_workbench::{
    job::{Job, MemoryBudget, MemoryLease},
    protocol::{
        RelationalCandidateOutputs, RelationalCursorError, RelationalReplayHistory,
        RelationalRestoreBudget, RelationalSearchSession, RelationalSearchStep,
        RelationalTransformCandidate,
        infer_relational_transform_candidates_with_evaluator_and_history,
    },
};
use sha2::{Digest, Sha256};
use std::convert::Infallible;

const CHECKPOINT_LIMIT: usize = 4 * 1024 * 1024;
const SCOPE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

type CheckpointFixture = (
    Vec<OwnedRecord>,
    l2_workbench::protocol::RelationalTransformPlan,
    RelationalTransformEvaluationOptions,
    Vec<u8>,
    MemoryLease,
);

#[path = "cursor/absolute_resume.rs"]
mod absolute_resume;
#[path = "cursor/corruption.rs"]
mod corruption;
#[path = "cursor/resources.rs"]
mod resources;
#[path = "cursor/session.rs"]
mod session;

fn evaluate(candidate: &RelationalTransformCandidate) -> RelationalCandidateEvaluation<usize> {
    RelationalCandidateEvaluation {
        priority: u8::from(!candidate.discovery.supported_sessions.is_empty()),
        work_bytes: 1,
        assessment: candidate.discovery.checks.len(),
    }
}

fn decode_assessment(
    _: &RelationalTransformCandidate,
    _: Option<&RelationalCandidateOutputs>,
    value: serde_json::Value,
    _: &mut RelationalRestoreBudget,
) -> Result<usize, RelationalCursorError<serde_json::Error>> {
    serde_json::from_value(value).map_err(RelationalCursorError::Assessment)
}

fn rehash(mut envelope: serde_json::Value) -> TestResult<Vec<u8>> {
    let payload = serde_json::to_vec(envelope.pointer("/payload").ok_or("missing payload")?)?;
    *envelope.pointer_mut("/digest").ok_or("missing digest")? =
        serde_json::to_value(<[u8; 32]>::from(Sha256::digest(&payload)))?;
    Ok(serde_json::to_vec(&envelope)?)
}

fn checkpoint_fixture() -> TestResult<CheckpointFixture> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions::default();
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = session.step(None, 7, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    assert!(
        session
            .encode_checkpoint(&cursor, 8, &memory, |value, writer| serde_json::to_writer(
                writer, value
            ))
            .is_err()
    );
    let (bytes, lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    Ok((records, plan, options, bytes, lease))
}

fn assert_resume_rejected(
    samples: &[l2_workbench::protocol::RelationalRecordSample<'_>],
    plan: &l2_workbench::protocol::RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    history: Option<&mut RelationalReplayHistory>,
    bytes: &[u8],
) -> TestResult<()> {
    let mut session = RelationalSearchSession::new(samples, plan, None, options, history)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut calls = 0;
    let restored = session.restore_checkpoint(
        bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |candidate, outputs, value, work| {
            calls += 1;
            decode_assessment(candidate, outputs, value, work)
        },
    );
    assert!(matches!(
        restored,
        Err(RelationalCursorError::InvalidCheckpoint | RelationalCursorError::Search(_))
    ));
    assert_eq!(calls, 0);
    Ok(())
}

#[test]
fn rejects_corrupt_and_oversized_checkpoints() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    assert!(
        session
            .restore_checkpoint(
                &bytes,
                8,
                &memory,
                &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
                decode_assessment
            )
            .is_err()
    );
    let mut damaged = bytes.clone();
    let index = damaged.len() / 2;
    *damaged.get_mut(index).ok_or("empty checkpoint")? ^= 1;
    assert!(
        session
            .restore_checkpoint(
                &damaged,
                CHECKPOINT_LIMIT,
                &memory,
                &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
                decode_assessment
            )
            .is_err()
    );
    let mut incompatible: serde_json::Value = serde_json::from_slice(&bytes)?;
    *incompatible.get_mut("version").ok_or("missing version")? = serde_json::json!(999);
    let incompatible = serde_json::to_vec(&incompatible)?;
    assert!(
        session
            .restore_checkpoint(
                &incompatible,
                CHECKPOINT_LIMIT,
                &memory,
                &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
                decode_assessment
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn oversized_assessment_stops_conversion_before_remaining_candidates() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 200;
    plan.limits.max_retained_candidates = 16;
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let step = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (normal, normal_lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    let payload: serde_json::Value = serde_json::from_slice(&normal)?;
    let count = payload
        .pointer("/payload/search/candidates")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing candidates")?
        .len();
    assert!(count > 1);
    drop(payload);
    drop(normal);
    drop(normal_lease);
    let mut converted = 0;
    let result = session.encode_checkpoint(&cursor, 1024, &memory, |_, writer| {
        converted += 1;
        writer.write_all(&[b'0'; 1025])
    });
    assert!(matches!(
        result,
        Err(l2_workbench::protocol::RelationalCursorError::CheckpointTooLarge)
    ));
    assert_eq!(converted, 1);
    assert_eq!(
        memory
            .snapshot()?
            .used(l2_workbench::job::MemoryClass::Executor),
        0
    );
    Ok(())
}

#[test]
fn rejects_impossible_saved_work_and_parameter_positions() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    // A valid checksum does not make impossible accounting into a valid cursor
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    *changed
        .pointer_mut("/payload/search/candidates_examined")
        .ok_or("missing count")? = serde_json::json!(plan.limits.max_candidates + 1);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    let field = changed
        .pointer_mut("/payload/position/current/parameters/candidate_index")
        .ok_or("missing parameter index")?;
    let index = field.as_u64().ok_or("invalid parameter index")?;
    *field = serde_json::json!(index + 1);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)?;
    Ok(())
}

#[test]
fn rejects_a_retained_rule_outside_the_selected_plan() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    let field = changed
        .pointer_mut("/payload/search/candidates/0/candidate/rule/parser_format")
        .ok_or("fixture has no retained rule")?;
    *field = serde_json::json!("png");
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)
}

#[test]
fn rejects_a_retained_candidate_without_discovery_support() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    let candidate = changed
        .pointer_mut("/payload/search/candidates/0/candidate")
        .ok_or("fixture has no retained rule")?;
    *candidate.get_mut("discovery").ok_or("missing discovery")? = serde_json::json!({
        "status": "not_evaluated", "supported_sessions": [], "contradicted_sessions": [],
        "unresolved_sessions": [], "checks": []
    });
    *candidate.get_mut("status").ok_or("missing status")? =
        serde_json::json!("discovery_contradicted");
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)
}

#[test]
fn rejects_payload_selector_that_disagrees_with_its_locator() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    let field = changed
        .pointer_mut("/payload/payload_locators/0/selector/marker/0")
        .ok_or("fixture has no payload marker")?;
    let marker = field.as_u64().ok_or("invalid payload marker")?;
    *field = serde_json::json!(marker ^ 1);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)
}

#[test]
fn rejects_a_current_pair_inconsistent_with_the_saved_initial_phase() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    let count = changed
        .pointer("/payload/payload_locators")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing payload locators")?
        .len();
    assert!(count > 1);
    assert_eq!(
        changed
            .pointer("/payload/position/stage/stage")
            .and_then(serde_json::Value::as_str),
        Some("initial")
    );
    let field = changed
        .pointer_mut("/payload/position/current/payload")
        .ok_or("missing current pair")?;
    let index = usize::try_from(field.as_u64().ok_or("invalid current pair")?)?;
    *field = serde_json::json!((index + 1) % count);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)
}

#[test]
fn rejects_changed_inputs_plan_options_and_history() -> TestResult<()> {
    let (records, plan, options, bytes, _encoded_memory) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut wrong_history = RelationalReplayHistory::new(256 * 1024);
    assert_resume_rejected(&samples, &plan, options, Some(&mut wrong_history), &bytes)?;
    let mut changed_plan = plan.clone();
    changed_plan.limits.max_work_bytes -= 1;
    assert_resume_rejected(&samples, &changed_plan, options, None, &bytes)?;
    let mut changed_samples = samples.clone();
    changed_samples.first_mut().ok_or("missing sample")?.sample += 100_000;
    assert_resume_rejected(&changed_samples, &plan, options, None, &bytes)?;
    let mut changed_records = records.clone();
    *changed_records
        .first_mut()
        .and_then(|record| record.2.first_mut())
        .ok_or("missing input byte")? ^= 1;
    let changed_bytes = borrow_samples(&changed_records)?;
    assert_resume_rejected(&changed_bytes, &plan, options, None, &bytes)?;
    let changed_options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 1,
    };
    assert_resume_rejected(&samples, &plan, changed_options, None, &bytes)?;
    let mut unsupported = plan;
    unsupported.parser_scope = RelationalParserScope::EachSession;
    assert!(RelationalSearchSession::new(&samples, &unsupported, None, options, None).is_err());
    Ok(())
}

fn shift_saved_range(envelope: &mut serde_json::Value) -> TestResult<()> {
    let candidates = envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing candidates")?;
    let mut changed_range = false;
    'candidates: for candidate in candidates {
        let Some(outputs) = candidate
            .pointer_mut("/outputs/discovery")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        for output in outputs {
            let Some(mappings) = output
                .get_mut("payload_mappings")
                .and_then(serde_json::Value::as_array_mut)
            else {
                continue;
            };
            for mapping in mappings {
                let Some(start) = mapping
                    .pointer("/source_range/start")
                    .and_then(serde_json::Value::as_u64)
                else {
                    continue;
                };
                let Some(end) = mapping
                    .pointer("/source_range/end")
                    .and_then(serde_json::Value::as_u64)
                else {
                    continue;
                };
                if start > 0 {
                    *mapping
                        .pointer_mut("/source_range/start")
                        .ok_or("missing range start")? = serde_json::json!(start - 1);
                    *mapping
                        .pointer_mut("/source_range/end")
                        .ok_or("missing range end")? = serde_json::json!(end - 1);
                    changed_range = true;
                    break 'candidates;
                }
            }
        }
    }
    assert!(changed_range, "fixture has no in-range mapping to alter");
    Ok(())
}

#[test]
fn restored_output_provenance_must_reference_exact_input_ranges() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(saved) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_memory) =
        session.encode_checkpoint(&saved, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    drop(saved);
    drop(session);
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    let candidates = envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing candidates")?;
    let output = candidates
        .iter_mut()
        .find_map(|candidate| {
            candidate
                .pointer_mut("/outputs/discovery")
                .and_then(serde_json::Value::as_array_mut)
                .and_then(|outputs| outputs.first_mut())
        })
        .ok_or("fixture has no retained discovery output")?;
    *output
        .pointer_mut("/payload_mappings/0/source_range/end")
        .ok_or("missing source range")? = serde_json::json!(usize::MAX);
    let changed = rehash(envelope)?;
    assert_resume_rejected(&samples, &plan, options, None, &changed)?;

    // A range can fit the sample and still disagree with the frozen locator
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    shift_saved_range(&mut envelope)?;
    assert_resume_rejected(&samples, &plan, options, None, &rehash(envelope)?)?;
    Ok(())
}
