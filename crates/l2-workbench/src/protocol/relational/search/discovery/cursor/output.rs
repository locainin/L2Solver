//! Recheck retained output bytes against the frozen rule and source ranges

use super::super::super::replay::{LocatedPayload, saved_output_inputs, transform_work_estimate};
use super::{
    Job, PreparedSearch, RelationalAppliedOutput, RelationalCursorError, RelationalFit,
    RelationalRecordSample, RelationalRestoreBudget, RelationalSha256CounterXor,
    RelationalTransformError, RelationalTransformPlan, RelationalTransformRule, SearchState,
    SessionGroup,
};
use crate::{derivation, protocol::RelationalCounterReset};
use sha2::{Digest, Sha256};

// A full chunk ends on a SHA-256 mask boundary, even across source record boundaries
pub(super) const CHUNK_BYTES: usize = 4 * 1024;
const MASK_BYTES: usize = 32;

pub(super) fn verify_retained_outputs<T, E>(
    samples: &[RelationalRecordSample<'_>],
    prepared: &PreparedSearch,
    search: &SearchState<'_, T>,
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    work: &mut RelationalRestoreBudget,
) -> Result<(), RelationalCursorError<E>> {
    let mut search_work_remaining = search.work_bytes;
    for retained in &search.candidates {
        let Some(outputs) = &retained.outputs else {
            continue;
        };
        for (fit, groups, outputs) in [
            (
                &retained.candidate.discovery,
                &prepared.discovery_groups,
                &outputs.discovery,
            ),
            (
                &retained.candidate.heldout,
                &prepared.heldout_groups,
                &outputs.heldout,
            ),
        ] {
            for output in outputs {
                verify_output(
                    samples,
                    groups,
                    fit,
                    output,
                    &retained.candidate.rule,
                    plan,
                    job,
                    work,
                    &mut search_work_remaining,
                )?;
            }
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "check one output against its complete frozen context"
)]
fn verify_output<E>(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    fit: &RelationalFit,
    output: &RelationalAppliedOutput,
    rule: &RelationalTransformRule,
    plan: &RelationalTransformPlan,
    job: Option<&Job>,
    work: &mut RelationalRestoreBudget,
    search_work_remaining: &mut usize,
) -> Result<(), RelationalCursorError<E>> {
    if let Some(job) = job {
        job.check_cancelled()
            .map_err(|error| RelationalCursorError::Search(error.into()))?;
    }
    let group = groups
        .iter()
        .find(|group| group.id == output.session)
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    let check = fit
        .checks
        .iter()
        .find(|check| check.session == output.session)
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    let digest = check
        .output_sha256
        .as_deref()
        .and_then(crate::hashing::parse_sha256_digest)
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    // Admit the locator scans before resolving the source ranges again
    let marker_bytes = rule
        .seed_locator
        .marker
        .len()
        .checked_add(rule.payload_locator.marker.len())
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    let lookup_work = marker_bytes
        .checked_add(4 * size_of::<usize>())
        .and_then(|per_record| per_record.checked_mul(group.sample_indices.len()))
        .and_then(|amount| amount.checked_add(marker_bytes))
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    if !work.try_charge_verification(lookup_work) {
        return Err(RelationalCursorError::RestoreWorkLimit);
    }
    let inputs = saved_output_inputs(samples, group, rule, plan.limits, output)
        .map_err(RelationalCursorError::Search)?
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    let operation = rule.operation.sha256_counter_xor();
    let estimated = transform_work_estimate(
        &inputs.payloads,
        inputs.seed.bytes.len(),
        operation.counter_width,
        rule.counter_reset,
    )
    .ok_or(RelationalCursorError::InvalidCheckpoint)?;
    // Captured outputs must fit within the work recorded by the original search
    if estimated > *search_work_remaining || output.work_bytes != estimated {
        return Err(RelationalCursorError::InvalidCheckpoint);
    }
    *search_work_remaining -= estimated;
    let mut verifier = ChunkVerifier {
        expected: &output.bytes,
        seed: inputs.seed.bytes,
        operation,
        job,
        work,
        output_offset: 0,
        digest: Sha256::new(),
    };
    verify_payloads(&inputs.payloads, rule.counter_reset, &mut verifier)?;
    if verifier.output_offset != output.bytes.len()
        || <[u8; 32]>::from(verifier.digest.finalize()) != digest
    {
        return Err(RelationalCursorError::InvalidCheckpoint);
    }
    Ok(())
}

fn verify_payloads<E>(
    payloads: &[LocatedPayload<'_>],
    reset: RelationalCounterReset,
    verifier: &mut ChunkVerifier<'_>,
) -> Result<(), RelationalCursorError<E>> {
    match reset {
        RelationalCounterReset::Continuous => verify_continuous(payloads, verifier),
        RelationalCounterReset::PerRecord => {
            for payload in payloads {
                let mut record_offset = 0;
                for chunk in payload.bytes.chunks(CHUNK_BYTES) {
                    verifier.verify(chunk, record_offset)?;
                    record_offset += chunk.len();
                }
            }
            Ok(())
        }
    }
}

struct ChunkVerifier<'a> {
    expected: &'a [u8],
    seed: &'a [u8],
    operation: RelationalSha256CounterXor,
    job: Option<&'a Job>,
    work: &'a mut RelationalRestoreBudget,
    output_offset: usize,
    digest: Sha256,
}

impl ChunkVerifier<'_> {
    fn verify<E>(
        &mut self,
        input: &[u8],
        counter_offset: usize,
    ) -> Result<(), RelationalCursorError<E>> {
        if let Some(job) = self.job {
            job.check_cancelled()
                .map_err(|error| RelationalCursorError::Search(error.into()))?;
        }
        // The charge includes the canonical transform and the output digest
        let amount = derivation::sha256_counter_xor_work(
            input.len(),
            self.seed.len(),
            self.operation.counter_width,
        )
        .and_then(|work| work.checked_add(input.len()))
        .ok_or(RelationalCursorError::InvalidCheckpoint)?;
        if !self.work.try_charge_verification(amount) {
            return Err(RelationalCursorError::RestoreWorkLimit);
        }
        let offset = u64::try_from(counter_offset / MASK_BYTES)
            .map_err(|_| RelationalCursorError::InvalidCheckpoint)?;
        let counter = self
            .operation
            .initial_counter
            .checked_add(offset)
            .ok_or(RelationalCursorError::InvalidCheckpoint)?;
        let transformed = derivation::preview_sha256_counter_xor(
            input,
            self.seed,
            counter,
            self.operation.counter_width,
            self.operation.counter_byte_order,
            self.operation.seed_order,
        )
        .map_err(|error| match error {
            derivation::StepFailure::AllocationFailed => {
                RelationalCursorError::Search(RelationalTransformError::AllocationFailed)
            }
            _ => RelationalCursorError::InvalidCheckpoint,
        })?;
        let end = self
            .output_offset
            .checked_add(input.len())
            .ok_or(RelationalCursorError::InvalidCheckpoint)?;
        if self.expected.get(self.output_offset..end) != Some(transformed.as_slice()) {
            return Err(RelationalCursorError::InvalidCheckpoint);
        }
        self.digest.update(&transformed);
        self.output_offset = end;
        Ok(())
    }
}

fn verify_continuous<E>(
    payloads: &[LocatedPayload<'_>],
    verifier: &mut ChunkVerifier<'_>,
) -> Result<(), RelationalCursorError<E>> {
    let mut buffer = [0_u8; CHUNK_BYTES];
    let mut buffered = 0_usize;
    let mut processed = 0_usize;
    for payload in payloads {
        let mut source = payload.bytes;
        while !source.is_empty() {
            // Carry a partial mask block across record boundaries
            let count = source.len().min(CHUNK_BYTES - buffered);
            let part = source
                .get(..count)
                .ok_or(RelationalCursorError::InvalidCheckpoint)?;
            let target = buffer
                .get_mut(buffered..buffered + count)
                .ok_or(RelationalCursorError::InvalidCheckpoint)?;
            target.copy_from_slice(part);
            buffered += count;
            source = source
                .get(count..)
                .ok_or(RelationalCursorError::InvalidCheckpoint)?;
            if buffered == CHUNK_BYTES {
                verifier.verify(&buffer, processed)?;
                processed += buffered;
                buffered = 0;
            }
        }
    }
    if buffered > 0 {
        verifier.verify(
            buffer
                .get(..buffered)
                .ok_or(RelationalCursorError::InvalidCheckpoint)?,
            processed,
        )?;
    }
    Ok(())
}
