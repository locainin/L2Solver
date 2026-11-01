use super::{
    CHECKPOINT_LIMIT, CheckpointFixture, Infallible, Job, OwnedRecord, RelationalCursorError,
    RelationalParserScope, RelationalRestoreBudget, RelationalSearchSession, RelationalSearchStep,
    RelationalTransformEvaluationOptions, SCOPE, TestResult, assert_resume_rejected,
    borrow_samples, decode_assessment, evaluate, rehash, search_plan, synthetic_sessions,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use l2_workbench::{
    derivation::CounterWidth,
    job::{MemoryBudget, MemoryClass},
    protocol::{Direction, RelationalCounterReset, RelationalTransformPlan},
};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

fn output_checkpoint_fixture() -> TestResult<CheckpointFixture> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let RelationalSearchStep::Paused(cursor) = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("fixture did not pause".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    Ok((records, plan, options, bytes, lease))
}

fn first_output_mut(envelope: &mut Value) -> TestResult<&mut Value> {
    envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(Value::as_array_mut)
        .and_then(|candidates| {
            candidates
                .iter_mut()
                .find_map(|candidate| candidate.pointer_mut("/outputs/discovery/0/bytes"))
        })
        .ok_or_else(|| "fixture has no retained discovery output".into())
}

fn padded_output_mut(envelope: &mut Value) -> TestResult<&mut Value> {
    envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(Value::as_array_mut)
        .and_then(|candidates| {
            candidates.iter_mut().find_map(|candidate| {
                candidate
                    .pointer_mut("/outputs/discovery")
                    .and_then(Value::as_array_mut)?
                    .iter_mut()
                    .find_map(|output| {
                        let bytes = output.get_mut("bytes")?;
                        bytes
                            .as_str()
                            .is_some_and(|encoded| encoded.ends_with('='))
                            .then_some(bytes)
                    })
            })
        })
        .ok_or_else(|| "fixture has no padded discovery output".into())
}

#[test]
fn checkpoint_output_requires_canonical_padded_base64() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = output_checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let envelope: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(envelope.get("version").and_then(Value::as_u64), Some(3));
    let mut valid = envelope.clone();
    let output = first_output_mut(&mut valid)?
        .as_str()
        .ok_or("output was not encoded as a string")?;
    let decoded = STANDARD.decode(output)?;
    assert!(!decoded.is_empty());
    assert_eq!(STANDARD.encode(&decoded), output);

    // Alter unused trailing bits while keeping the same decoded bytes under a permissive decoder
    let mut changed = envelope.clone();
    let padded = padded_output_mut(&mut changed)?;
    let mut encoded = padded
        .as_str()
        .ok_or("invalid output encoding")?
        .as_bytes()
        .to_vec();
    let trailing = encoded
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'=')
        .count();
    let final_symbol = encoded
        .len()
        .checked_sub(trailing)
        .and_then(|length| length.checked_sub(1))
        .ok_or("padded output has no Base64 symbol")?;
    let symbol = *encoded.get(final_symbol).ok_or("missing Base64 symbol")?;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let index = alphabet
        .iter()
        .position(|byte| *byte == symbol)
        .ok_or("invalid Base64 alphabet")?;
    assert_eq!(index & 1, 0);
    let replacement = *alphabet.get(index + 1).ok_or("missing Base64 symbol")?;
    *encoded
        .get_mut(final_symbol)
        .ok_or("missing Base64 symbol")? = replacement;
    *padded = Value::String(String::from_utf8(encoded)?);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)?;

    // A fresh digest must not make malformed or noncanonical text acceptable
    for invalid in ["*", "A", "AA=", "AB==", "AA===", "AA=A"] {
        let mut changed = envelope.clone();
        *first_output_mut(&mut changed)? = Value::String(invalid.to_owned());
        assert_resume_rejected(&samples, &plan, options, None, &rehash(changed)?)?;
    }
    let mut numeric = envelope;
    *first_output_mut(&mut numeric)? = serde_json::json!([0, 1, 2]);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(numeric)?)?;
    Ok(())
}

#[test]
fn checkpoint_keeps_discovery_and_heldout_outputs_in_their_sessions() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = output_checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut envelope: Value = serde_json::from_slice(&bytes)?;
    let candidate = envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(Value::as_array_mut)
        .and_then(|candidates| {
            candidates.iter_mut().find(|candidate| {
                candidate
                    .pointer("/outputs/heldout/0")
                    .is_some_and(Value::is_object)
            })
        })
        .ok_or("fixture has no held-out output")?;
    let heldout = candidate
        .pointer_mut("/outputs/heldout")
        .and_then(Value::as_array_mut)
        .ok_or("missing held-out outputs")?
        .remove(0);
    candidate
        .pointer_mut("/outputs/discovery")
        .and_then(Value::as_array_mut)
        .ok_or("missing discovery outputs")?
        .push(heldout);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(envelope)?)
}

#[derive(Deserialize)]
struct RawEnvelope<'a> {
    version: u32,
    #[serde(borrow)]
    payload: &'a RawValue,
}

#[test]
fn escaped_output_string_is_admitted_before_decoding() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = output_checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let raw: RawEnvelope<'_> = serde_json::from_slice(&bytes)?;
    let mut envelope: Value = serde_json::from_slice(&bytes)?;
    let encoded = first_output_mut(&mut envelope)?
        .as_str()
        .ok_or("output was not encoded as a string")?;
    let mut escaped = String::new();
    for byte in encoded.bytes() {
        write!(&mut escaped, "\\u{byte:04x}")?;
    }
    let payload = raw.payload.get().replacen(
        &format!("\"bytes\":\"{encoded}\""),
        &format!("\"bytes\":\"{escaped}\""),
        1,
    );
    assert_ne!(payload, raw.payload.get(), "fixture output was not escaped");
    let digest = <[u8; 32]>::from(Sha256::digest(payload.as_bytes()));
    let escaped = format!(
        "{{\"version\":{},\"digest\":{},\"payload\":{payload}}}",
        raw.version,
        serde_json::to_string(&digest)?
    );
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let limit = u64::try_from(escaped.len())? * 3 - 1;
    let denied = MemoryBudget::new(limit);
    let mut calls = 0;
    let result = session.restore_checkpoint(
        escaped.as_bytes(),
        CHECKPOINT_LIMIT,
        &denied,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |context, candidate, outputs, value, work| {
            calls += 1;
            decode_assessment(context, candidate, outputs, value, work)
        },
    );
    assert!(matches!(result, Err(RelationalCursorError::Memory(_))));
    assert_eq!(calls, 0);
    assert_eq!(denied.snapshot()?.used(MemoryClass::Executor), 0);

    // JSON escaping changes the representation, not the canonical decoded Base64 text
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (_cursor, _restored_lease) = session.restore_checkpoint(
        escaped.as_bytes(),
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        decode_assessment,
    )?;
    Ok(())
}

fn large_search_fixture() -> (
    Vec<OwnedRecord>,
    RelationalTransformPlan,
    RelationalTransformEvaluationOptions,
) {
    const PAYLOAD_BYTES: usize = 512 * 1024 + 17;
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        records.push((
            u32::from(session),
            Direction::FirstToSecond,
            vec![0x31, session, session.wrapping_mul(3)],
        ));
        let mut payload = Vec::with_capacity(PAYLOAD_BYTES + 1);
        payload.push(0x82);
        payload.extend(
            (0_u8..=u8::MAX)
                .cycle()
                .take(PAYLOAD_BYTES)
                .map(|byte| byte.wrapping_add(session)),
        );
        records.push((u32::from(session), Direction::SecondToFirst, payload));
    }
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.counter_widths = vec![CounterWidth::EightBytes];
    plan.counter_resets = vec![RelationalCounterReset::PerRecord];
    plan.limits.max_seed_bytes = 2;
    plan.limits.max_locator_offset = 2;
    plan.limits.max_locator_candidates = 32;
    plan.limits.max_candidates = 12;
    plan.limits.max_retained_candidates = 1;
    plan.limits.max_record_bytes = PAYLOAD_BYTES + 1;
    plan.limits.max_total_bytes = 3 * 1024 * 1024;
    plan.limits.max_work_bytes = 512 * 1024 * 1024;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 3 * 1024 * 1024,
    };
    (records, plan, options)
}

fn assert_large_checkpoint_outputs(bytes: &[u8]) -> TestResult<u64> {
    let envelope: Value = serde_json::from_slice(bytes)?;
    let retained = envelope
        .pointer("/payload/search/output_bytes_retained")
        .and_then(Value::as_u64)
        .ok_or("missing retained output count")?;
    assert!(
        retained >= 2 * 1024 * 1024,
        "fixture did not retain large outputs"
    );
    let candidate = envelope
        .pointer("/payload/search/candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .ok_or("missing retained candidates")?;
    for split in ["discovery", "heldout"] {
        let outputs = candidate
            .pointer(&format!("/outputs/{split}"))
            .and_then(Value::as_array)
            .ok_or("missing output split")?;
        assert!(!outputs.is_empty(), "{split} has no retained output");
        assert!(
            outputs
                .iter()
                .all(|output| output.get("bytes").is_some_and(Value::is_string))
        );
    }
    Ok(retained)
}

#[test]
fn multi_megabyte_outputs_restore_with_bounded_memory_and_unchanged_search() -> TestResult<()> {
    const ENCODED_LIMIT: usize = 6 * 1024 * 1024;
    let (records, plan, options) = large_search_fixture();
    let samples = borrow_samples(&records)?;
    let job = Job::new("original multi-megabyte search").work_scope(SCOPE)?;
    let mut session = RelationalSearchSession::new(&samples, &plan, Some(&job), options, None)?;
    let RelationalSearchStep::Paused(saved) = session.step(None, 1, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("large fixture did not pause".into());
    };
    let encoded_memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) =
        session.encode_checkpoint(&saved, ENCODED_LIMIT, &encoded_memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    let retained = assert_large_checkpoint_outputs(&bytes)?;
    let work_at_pause = job.work_snapshot()?;
    let mut original_calls = Vec::new();
    let RelationalSearchStep::Complete(original) =
        session.step(Some(saved), usize::MAX, |_, candidate, _, _| {
            original_calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        })?
    else {
        return Err("original search did not finish".into());
    };
    let final_work = job.work_snapshot()?;
    drop(session);

    let resumed_job = Job::new("resumed multi-megabyte search").work_scope(SCOPE)?;
    resumed_job.restore_work(work_at_pause)?;
    let mut resumed =
        RelationalSearchSession::new(&samples, &plan, Some(&resumed_job), options, None)?;
    let restore_memory = MemoryBudget::new(24 * 1024 * 1024);
    let mut restore_work = RelationalRestoreBudget::new(usize::MAX, usize::MAX);
    let (cursor, restored_lease) = resumed.restore_checkpoint(
        &bytes,
        ENCODED_LIMIT,
        &restore_memory,
        &mut restore_work,
        decode_assessment,
    )?;
    assert!(restore_work.verification_work_bytes() > 0);
    assert!(restored_lease.bytes() >= retained);
    let mut resumed_calls = Vec::new();
    let RelationalSearchStep::Complete(actual) =
        resumed.step(Some(cursor), usize::MAX, |_, candidate, _, _| {
            resumed_calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        })?
    else {
        return Err("resumed search did not finish".into());
    };
    assert_eq!(actual, original);
    assert_eq!(resumed_calls, original_calls);
    assert_eq!(resumed_job.work_snapshot()?, final_work);
    let output = actual
        .evaluations
        .iter()
        .filter_map(|evaluation| evaluation.outputs.as_ref())
        .flat_map(|outputs| outputs.discovery.iter().chain(&outputs.heldout))
        .next()
        .ok_or("final report has no captured output")?;
    assert!(
        serde_json::to_value(output)?
            .get("bytes")
            .is_some_and(Value::is_array)
    );
    Ok(())
}
