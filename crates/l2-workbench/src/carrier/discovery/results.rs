//! Durable, paged discovery results with source and plan integrity receipts

mod integrity;
mod model;
mod reader;
mod writer;

pub use model::{
    DEFAULT_MAX_RESULT_PAGE_BYTES, DEFAULT_MAX_RESULT_RECORD_BYTES, ReplayReceipt, ResultPage,
    ResultReadOptions, StoreOptions, StoredDiscoverySummary,
};
pub use reader::DiscoveryResultStore;
pub(super) use writer::StoreWriter;
pub use writer::discover_samples_to_store;

use super::{
    engine,
    model::{
        DiscoveryCandidate, DiscoveryError, DiscoveryIdentity, DiscoveryPlan, DiscoverySample,
        Partition,
    },
};
use integrity::invalid_store;
use std::error::Error;

/// Replay one stored candidate after verifying source mappings and exact plan identity
///
/// # Errors
/// Rejects changed sources, plans, missing candidates, or output mismatches
pub fn replay_candidate(
    samples: &[DiscoverySample<'_>],
    plan: &DiscoveryPlan,
    store: &DiscoveryResultStore,
    candidate_id: usize,
) -> Result<ReplayReceipt, Box<dyn Error>> {
    replay_candidate_with_identity(samples, plan, store, candidate_id, None)
}

pub(super) fn replay_candidate_with_identity(
    samples: &[DiscoverySample<'_>],
    plan: &DiscoveryPlan,
    store: &DiscoveryResultStore,
    candidate_id: usize,
    cohort_identity: Option<&DiscoveryIdentity>,
) -> Result<ReplayReceipt, Box<dyn Error>> {
    // Opening already verified this store and pins the same read snapshot for replay
    let plan_bytes = serde_json::to_vec(plan)?;
    if crate::sha256(&plan_bytes) != store.summary().plan_sha256 {
        return Err(invalid_store(
            "discovery plan identity does not match stored results",
        ));
    }
    store.verify_sample_receipts(samples)?;
    let expected_identity = if let Some(identity) = cohort_identity {
        identity.clone()
    } else {
        let sample = samples
            .first()
            .ok_or_else(|| invalid_store("replay has no source samples"))?;
        DiscoveryIdentity {
            source_scope: sample.source_scope.clone(),
            direction: sample.direction.clone(),
            local_identity: sample.local_identity.clone(),
        }
    };
    if expected_identity != store.summary().identity {
        return Err(invalid_store("source scope or endpoint identity changed"));
    }
    let candidate = store.candidate(candidate_id)?;
    if let Some(summary) = candidate.discovery.as_ref() {
        store.validate_output_rows(candidate_id, Partition::Discovery, summary)?;
    }
    if let Some(summary) = candidate.control.as_ref() {
        store.validate_output_rows(candidate_id, Partition::Control, summary)?;
    }
    let mut replay_plan = plan.clone();
    replay_plan.widths = vec![candidate.width];
    replay_plan.phases = vec![candidate.phase];
    replay_plan.start_offsets = vec![candidate.source_byte_offset];
    replay_plan.reset_modes = vec![candidate.reset_mode];
    replay_plan.sample_orders = vec![candidate.sample_order];
    replay_plan.max_candidates = 1;
    replay_plan.max_work_bytes = plan.max_work_bytes;
    let mut replay_sink = ReplaySink::default();
    engine::discover_with_identity(
        samples,
        &replay_plan,
        cohort_identity,
        store.summary().omitted_empty_sample_ids.clone(),
        Some(&mut replay_sink),
    )?;
    let mut actual = replay_sink
        .candidate
        .take()
        .ok_or_else(|| invalid_store("selected candidate could not be replayed"))?;
    let expected = candidate;
    actual.id = expected.id;
    actual.competitor_count = expected.competitor_count;
    let matches_stored_output = actual == expected;
    if !matches_stored_output {
        return Err(invalid_store(
            "replayed candidate does not match its stored summary",
        ));
    }
    Ok(ReplayReceipt {
        candidate_id,
        plan_sha256: store.summary().plan_sha256.clone(),
        result_sha256: store.summary().result_sha256.clone(),
        matches_stored_output,
    })
}

#[derive(Default)]
struct ReplaySink {
    candidate: Option<DiscoveryCandidate>,
}

impl engine::DiscoveryResultSink for ReplaySink {
    fn records_receipts(&self) -> bool {
        false
    }

    fn begin(
        &mut self,
        _plan: &DiscoveryPlan,
        _identity: &DiscoveryIdentity,
        _omitted: &[u64],
        _input_bytes: usize,
        _parameter_space_size: usize,
    ) -> Result<(), DiscoveryError> {
        Ok(())
    }

    fn sample_receipt(
        &mut self,
        _receipt: &super::model::DiscoverySampleReceipt,
    ) -> Result<(), DiscoveryError> {
        Ok(())
    }

    fn output(
        &mut self,
        _candidate_id: usize,
        _partition: Partition,
        _unit_index: usize,
        _bytes: &[u8],
    ) -> Result<(), DiscoveryError> {
        Ok(())
    }

    fn printable_run(&mut self, _run: &super::model::PrintableRun) -> Result<(), DiscoveryError> {
        Ok(())
    }

    fn candidate(&mut self, candidate: &DiscoveryCandidate) -> Result<(), DiscoveryError> {
        self.candidate = Some(candidate.clone());
        Ok(())
    }
}
