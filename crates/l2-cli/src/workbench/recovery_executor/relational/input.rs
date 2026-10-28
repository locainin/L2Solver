// Collect session-relative transform samples without erasing transport provenance

use super::super::framing_discovery::{
    FramingDiscoveryPlan, NativeHttpCoverage, range_covered_by_native_messages,
};
use super::super::peer_cohort::{self, PeerCohort};
use super::{
    Executor, RAW_RUN_FRAMING_RULE, RawRelationalRunInput, RecordCohortKey, RecordCohortOrigin,
    RecordFrameInput, RecoveryExecutionError, RelationalCohortKey, RelationalLane, SampleCohort,
    StoredSample, admit_sample_views, invalid_policy, operational, try_clone_string,
};
use l2_workbench::{
    evidence::Case,
    protocol::{ByteRange as StreamRange, Direction, MessageContext},
    recovery::RecoveryError,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_relational/input.rs"]
mod tests;

impl Executor<'_> {
    pub(in crate::workbench::recovery_executor) fn collect_relational_raw_runs(
        &mut self,
        source_id: &str,
        scope_json: &str,
        direction: Direction,
        runs: &[RawRelationalRunInput],
        plan: &FramingDiscoveryPlan,
    ) -> Result<(), RecoveryExecutionError> {
        // A reused transport tuple may contain episodes with different observed roles
        let groups = group_by_peer(
            self.case,
            runs.iter().map(|run| (run.episode_node_id, run)),
            direction,
        )?;
        for (peer, runs) in groups {
            self.collect_raw_cohort(source_id, scope_json, &peer, &runs, plan)?;
        }
        Ok(())
    }

    fn collect_raw_cohort(
        &mut self,
        source_id: &str,
        scope_json: &str,
        peer: &PeerCohort,
        runs: &[&RawRelationalRunInput],
        plan: &FramingDiscoveryPlan,
    ) -> Result<(), RecoveryExecutionError> {
        let key = RelationalCohortKey {
            source_id: source_id.to_owned(),
            scope_json: scope_json.to_owned(),
            endpoints_json: peer.endpoints_json.clone(),
            direction: peer.direction,
            framing_rule_json: RAW_RUN_FRAMING_RULE.to_owned(),
            schema_json: "{\"input\":\"raw_directional_byte_run\"}".to_owned(),
        };
        let normal_limits = self.policy.relational_transform_plan.limits;
        let incremental_limits = self
            .policy
            .relational_incremental_plan
            .as_ref()
            .map(|plan| plan.limits);
        let CollectedRawSamples {
            incoming,
            incomplete_sessions,
            omitted_runs,
        } = collect_raw_samples(self.case, &key, runs, plan.native_http_coverage_by_run())?;
        if incoming.is_empty() && incomplete_sessions.is_empty() && omitted_runs == 0 {
            return Ok(());
        }
        let source_eligibility_omissions = plan.source_eligibility_omissions(source_id);
        let incremental_key = self.reserve_incremental_metadata(&key, &incoming, runs.len());
        let normal_index = self.relational_cohort_index(key, runs.len(), RelationalLane::Normal)?;
        if let Some(index) = normal_index {
            let cohort = self
                .relational_samples
                .cohorts
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            update_raw_coverage(
                cohort,
                source_eligibility_omissions,
                &incomplete_sessions,
                omitted_runs,
            )?;
            admit_sample_views(self.case, Some(cohort), None, &incoming, normal_limits)?;
        }
        if let (Some(key), Some(limits)) = (incremental_key, incremental_limits)
            && let Some(index) = self.incremental_cohort_index(key, runs.len())?
        {
            let cohort = self
                .relational_samples
                .incremental_cohorts
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            let result = update_raw_coverage(
                cohort,
                source_eligibility_omissions,
                &incomplete_sessions,
                omitted_runs,
            )
            .and_then(|()| {
                admit_sample_views(
                    self.case,
                    None,
                    Some((cohort, limits)),
                    &incoming,
                    normal_limits,
                )
            });
            self.handle_incremental_allocation(result)?;
        }
        Ok(())
    }

    fn reserve_incremental_metadata(
        &mut self,
        key: &RelationalCohortKey,
        incoming: &[StoredSample],
        visited_count: usize,
    ) -> Option<RelationalCohortKey> {
        let limit = self
            .policy
            .relational_incremental_plan
            .as_ref()?
            .limits
            .max_total_bytes;
        if self.relational_samples.incremental_metadata_stop.is_some() {
            return None;
        }
        let retained = self
            .relational_samples
            .incremental_cohorts
            .iter()
            .find(|cohort| cohort.key.as_ref() == Some(key));
        let Some(requested) = incremental_metadata_bound(key, incoming, retained, visited_count)
        else {
            self.stop_incremental_metadata("incremental_metadata_limit");
            return None;
        };
        let Some(total) = self
            .relational_samples
            .incremental_metadata_used
            .checked_add(requested)
        else {
            self.stop_incremental_metadata("incremental_metadata_limit");
            return None;
        };
        if total > limit {
            self.stop_incremental_metadata("incremental_metadata_limit");
            return None;
        }
        // Charge the whole batch before any extra cohort or sample allocation
        self.relational_samples.incremental_metadata_used = total;
        try_clone_cohort_key(key).map_or_else(
            |_| {
                self.stop_incremental_metadata("incremental_metadata_allocation_failed");
                None
            },
            Some,
        )
    }

    fn stop_incremental_metadata(&mut self, reason: &'static str) {
        // Discard every pending view: later omitted records could otherwise leave a partial session
        self.relational_samples.incremental_cohorts = Vec::new();
        self.relational_samples.histories = super::history::RelationalReplayHistories::default();
        self.relational_samples.incremental_metadata_stop = Some(reason.into());
    }

    fn incremental_cohort_index(
        &mut self,
        key: RelationalCohortKey,
        incoming_count: usize,
    ) -> Result<Option<usize>, RecoveryExecutionError> {
        match self.relational_cohort_index(key, incoming_count, RelationalLane::Incremental) {
            Ok(index) => Ok(index),
            Err(error) if incremental_allocation_failed(&error) => {
                self.stop_incremental_metadata("incremental_metadata_allocation_failed");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn handle_incremental_allocation(
        &mut self,
        result: Result<(), RecoveryExecutionError>,
    ) -> Result<(), RecoveryExecutionError> {
        match result {
            Ok(()) => Ok(()),
            Err(error) if incremental_allocation_failed(&error) => {
                self.stop_incremental_metadata("incremental_metadata_allocation_failed");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn relational_cohort_index(
        &mut self,
        key: RelationalCohortKey,
        incoming_count: usize,
        lane: RelationalLane,
    ) -> Result<Option<usize>, RecoveryExecutionError> {
        let limits = match lane {
            RelationalLane::Normal => self.policy.relational_transform_plan.limits,
            RelationalLane::Incremental => match &self.policy.relational_incremental_plan {
                Some(plan) => plan.limits,
                None => return Ok(None),
            },
        };
        if let Some(index) = self
            .relational_samples
            .cohorts(lane)
            .iter()
            .position(|cohort| cohort.key.as_ref() == Some(&key))
        {
            return Ok(Some(index));
        }
        if self.relational_samples.cohorts(lane).len() >= limits.max_cohorts {
            self.relational_session_omission(
                &key.source_id,
                0,
                incoming_count,
                false,
                "cohort_limit",
                limits,
            )?;
            return Ok(None);
        }
        self.relational_samples
            .cohorts_mut(lane)
            .try_reserve(1)
            .map_err(|source| operational("relational cohort allocation failed", source))?;
        let cohorts = self.relational_samples.cohorts_mut(lane);
        let index = cohorts.len();
        cohorts.push(SampleCohort::new(key));
        Ok(Some(index))
    }

    pub(in crate::workbench::recovery_executor) fn collect_relational_frame_samples(
        &mut self,
        frame_key: &RecordCohortKey,
        frames: &[RecordFrameInput],
        source_coverage_complete: bool,
        source_eligibility_omissions: usize,
    ) -> Result<(), RecoveryExecutionError> {
        if matches!(&frame_key.origin, RecordCohortOrigin::Relational { .. }) || frames.is_empty() {
            return Ok(());
        }
        let groups = group_by_peer(
            self.case,
            frames.iter().map(|frame| (frame.episode_node_id, frame)),
            frame_key.direction,
        )?;
        for (peer, frames) in groups {
            self.collect_frame_cohort(
                frame_key,
                &peer,
                &frames,
                source_coverage_complete,
                source_eligibility_omissions,
            )?;
        }
        Ok(())
    }

    fn collect_frame_cohort(
        &mut self,
        frame_key: &RecordCohortKey,
        peer: &PeerCohort,
        frames: &[&RecordFrameInput],
        source_coverage_complete: bool,
        source_eligibility_omissions: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let eligible_frames = uncovered_source_frames(
            self.case,
            &frame_key.origin,
            frames,
            self.policy.framing_discovery_plan.as_deref(),
        )?;
        if eligible_frames.is_empty() {
            return Ok(());
        }

        let schema_json = match &frame_key.origin {
            RecordCohortOrigin::TcpMaterialized => {
                "{\"input\":\"source_framed_message\"}".to_owned()
            }
            RecordCohortOrigin::Transformed { ancestry_id } => serde_json::json!({
                "input":"transformed_stream",
                "ancestry_id":ancestry_id,
            })
            .to_string(),
            RecordCohortOrigin::Relational { .. } => return Ok(()),
        };
        let key = RelationalCohortKey {
            source_id: frame_key.source_id.clone(),
            scope_json: frame_key.scope_json.clone(),
            endpoints_json: peer.endpoints_json.clone(),
            direction: peer.direction,
            framing_rule_json: frame_key.framing_rule_json.clone(),
            schema_json,
        };
        let normal_limits = self.policy.relational_transform_plan.limits;
        let incremental_limits = self
            .policy
            .relational_incremental_plan
            .as_ref()
            .map(|plan| plan.limits);
        let incoming = stored_frame_samples(self.case, frame_key, peer, &eligible_frames)?;

        let incremental_key =
            self.reserve_incremental_metadata(&key, &incoming, eligible_frames.len());
        let normal_index =
            self.relational_cohort_index(key, eligible_frames.len(), RelationalLane::Normal)?;
        if let Some(index) = normal_index {
            let cohort = self
                .relational_samples
                .cohorts
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            update_frame_coverage(
                cohort,
                source_coverage_complete,
                source_eligibility_omissions,
            );
            admit_sample_views(self.case, Some(cohort), None, &incoming, normal_limits)?;
        }
        if let (Some(key), Some(limits)) = (incremental_key, incremental_limits)
            && let Some(index) = self.incremental_cohort_index(key, eligible_frames.len())?
        {
            let cohort = self
                .relational_samples
                .incremental_cohorts
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            update_frame_coverage(
                cohort,
                source_coverage_complete,
                source_eligibility_omissions,
            );
            let result = admit_sample_views(
                self.case,
                None,
                Some((cohort, limits)),
                &incoming,
                normal_limits,
            );
            self.handle_incremental_allocation(result)?;
        }
        Ok(())
    }
}

// Account conservatively for retained samples, scheduled copies, indexes, and cohort keys
fn incremental_metadata_bound(
    key: &RelationalCohortKey,
    samples: &[StoredSample],
    retained: Option<&SampleCohort>,
    visited_count: usize,
) -> Option<usize> {
    const COHORT_COPIES: usize = 8;
    const SAMPLE_COPIES: usize = 12;
    const INDEX_BYTES_PER_ITEM: usize = 512;
    const COHORT_OVERHEAD: usize = 4_096;
    let key_bytes = key
        .source_id
        .capacity()
        .checked_add(key.scope_json.capacity())?
        .checked_add(key.endpoints_json.capacity())?
        .checked_add(key.framing_rule_json.capacity())?
        .checked_add(key.schema_json.capacity())?
        .checked_add(std::mem::size_of::<SampleCohort>())?;
    let retained_index_entries = retained.map_or(Some(0), |cohort| {
        cohort
            .incomplete_sessions
            .len()
            .checked_add(cohort.omitted_sample_ids.len())
    })?;
    let mut total = key_bytes
        .checked_mul(COHORT_COPIES)?
        .checked_add(COHORT_OVERHEAD)?
        .checked_add(
            visited_count
                .checked_add(retained_index_entries)?
                .checked_mul(INDEX_BYTES_PER_ITEM)?,
        )?;
    // A later search may copy the retained samples again as well as the new batch
    let retained_samples = retained.into_iter().flat_map(|cohort| &cohort.samples);
    for sample in samples.iter().chain(retained_samples) {
        let bytes = std::mem::size_of::<StoredSample>()
            .checked_add(sample.context.source.capacity())?
            .checked_add(sample.context.scope.capacity())?
            .checked_mul(SAMPLE_COPIES)?
            .checked_add(INDEX_BYTES_PER_ITEM)?;
        total = total.checked_add(bytes)?;
    }
    Some(total)
}

fn try_clone_cohort_key(
    key: &RelationalCohortKey,
) -> Result<RelationalCohortKey, std::collections::TryReserveError> {
    Ok(RelationalCohortKey {
        source_id: try_clone_string(&key.source_id)?,
        scope_json: try_clone_string(&key.scope_json)?,
        endpoints_json: try_clone_string(&key.endpoints_json)?,
        direction: key.direction,
        framing_rule_json: try_clone_string(&key.framing_rule_json)?,
        schema_json: try_clone_string(&key.schema_json)?,
    })
}

fn incremental_allocation_failed(error: &RecoveryExecutionError) -> bool {
    let mut cause = std::error::Error::source(error);
    while let Some(error) = cause {
        if error.is::<std::collections::TryReserveError>() {
            return true;
        }
        cause = error.source();
    }
    false
}

fn update_raw_coverage(
    cohort: &mut SampleCohort,
    source_eligibility_omissions: usize,
    incomplete_sessions: &BTreeSet<u64>,
    omitted_runs: usize,
) -> Result<(), RecoveryExecutionError> {
    cohort.input_coverage_complete &=
        source_eligibility_omissions == 0 && incomplete_sessions.is_empty();
    cohort.source_eligibility_omissions = cohort
        .source_eligibility_omissions
        .max(source_eligibility_omissions);
    cohort.omitted_samples = cohort
        .omitted_samples
        .checked_add(omitted_runs)
        .ok_or_else(|| invalid_policy("relational raw-run omission overflowed"))?;
    cohort.omitted_sessions = cohort
        .omitted_sessions
        .checked_add(incomplete_sessions.len())
        .ok_or_else(|| invalid_policy("relational raw-session omission overflowed"))?;
    cohort
        .incomplete_sessions
        .try_reserve(incomplete_sessions.len())
        .map_err(|source| operational("relational session omission allocation failed", source))?;
    cohort
        .incomplete_sessions
        .extend(incomplete_sessions.iter().copied());
    Ok(())
}

fn update_frame_coverage(cohort: &mut SampleCohort, complete: bool, omissions: usize) {
    cohort.input_coverage_complete &= complete;
    cohort.source_eligibility_omissions = cohort.source_eligibility_omissions.max(omissions);
}

fn uncovered_source_frames<'a>(
    case: &Case,
    origin: &RecordCohortOrigin,
    frames: &[&'a RecordFrameInput],
    native_http_plan: Option<&FramingDiscoveryPlan>,
) -> Result<Vec<&'a RecordFrameInput>, RecoveryExecutionError> {
    let mut eligible = Vec::new();
    eligible
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("relational frame admission allocation failed", source))?;
    for frame in frames {
        let covered = matches!(origin, RecordCohortOrigin::TcpMaterialized)
            && native_http_covered_frame(case, frame, native_http_plan).is_some();
        if !covered {
            eligible.push(*frame);
        }
    }
    Ok(eligible)
}

fn stored_frame_samples(
    case: &Case,
    frame_key: &RecordCohortKey,
    peer: &PeerCohort,
    frames: &[&RecordFrameInput],
) -> Result<Vec<StoredSample>, RecoveryExecutionError> {
    let mut incoming = Vec::new();
    incoming
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("relational framed input allocation failed", source))?;
    for frame in frames {
        let node = case
            .node(frame.node_id)
            .ok_or(RecoveryError::UnknownEvidenceNode {
                node_id: frame.node_id,
            })?;
        let blob_id = node
            .blob
            .as_deref()
            .ok_or(RecoveryError::InvariantFailure)?;
        case.blob(blob_id).ok_or(RecoveryError::InvariantFailure)?;
        incoming.push(StoredSample {
            node_id: frame.node_id,
            context: MessageContext {
                source: frame_key.source_id.clone(),
                scope: frame_key.scope_json.clone(),
                session: frame.session_node_id,
                direction: peer.direction,
            },
            session_order: frame.session_id,
            direction_node_id: frame.direction_node_id,
            episode_node_id: frame.episode_node_id,
            stream_offset: frame.stream_offset,
        });
    }
    incoming.sort_by_key(|sample| {
        (
            sample.session_order,
            sample.context.session,
            sample.stream_offset,
            sample.context.direction,
            sample.node_id,
        )
    });
    Ok(incoming)
}

fn group_by_peer<'a, T: 'a>(
    case: &Case,
    inputs: impl Iterator<Item = (u64, &'a T)>,
    direction: Direction,
) -> Result<BTreeMap<PeerCohort, Vec<&'a T>>, RecoveryExecutionError> {
    let mut groups = BTreeMap::<PeerCohort, Vec<&T>>::new();
    for (episode_node_id, input) in inputs {
        let episode = case
            .node(episode_node_id)
            .ok_or(RecoveryError::UnknownEvidenceNode {
                node_id: episode_node_id,
            })?;
        groups
            .entry(peer_cohort::for_episode(episode, direction)?)
            .or_default()
            .push(input);
    }
    Ok(groups)
}

struct CollectedRawSamples {
    incoming: Vec<StoredSample>,
    incomplete_sessions: BTreeSet<u64>,
    omitted_runs: usize,
}

fn collect_raw_samples(
    case: &Case,
    key: &RelationalCohortKey,
    runs: &[&RawRelationalRunInput],
    coverage_by_run: &HashMap<u64, NativeHttpCoverage>,
) -> Result<CollectedRawSamples, RecoveryExecutionError> {
    let mut by_session = BTreeMap::<u64, Vec<&RawRelationalRunInput>>::new();
    for run in runs {
        by_session.entry(run.episode_node_id).or_default().push(run);
    }
    let mut incoming = Vec::new();
    incoming
        .try_reserve_exact(runs.len())
        .map_err(|source| operational("relational raw-run allocation failed", source))?;
    let mut incomplete_sessions = BTreeSet::new();
    let mut omitted_runs = 0_usize;
    for (session, session_runs) in by_session {
        let Some(run) = session_runs.first().copied() else {
            continue;
        };
        // A whole-stream transform cannot silently bridge missing bytes or an unknown reset
        if session_runs.len() != 1 || !run.start_known {
            incomplete_sessions.insert(session);
            omitted_runs = omitted_runs
                .checked_add(session_runs.len())
                .ok_or_else(|| invalid_policy("relational raw-run omission overflowed"))?;
            continue;
        }
        let node = case
            .node(run.node_id)
            .ok_or(RecoveryError::UnknownEvidenceNode {
                node_id: run.node_id,
            })?;
        let blob_id = node
            .blob
            .as_deref()
            .ok_or(RecoveryError::InvariantFailure)?;
        let blob = case.blob(blob_id).ok_or(RecoveryError::InvariantFailure)?;
        let full_run = StreamRange {
            start: 0,
            end: blob.bytes.len(),
        };
        if coverage_by_run.get(&run.node_id).is_some_and(|coverage| {
            range_covered_by_native_messages(full_run, &coverage.message_ranges)
        }) {
            continue;
        }
        incoming.push(StoredSample {
            node_id: run.node_id,
            context: MessageContext {
                source: key.source_id.clone(),
                scope: key.scope_json.clone(),
                session,
                direction: key.direction,
            },
            session_order: run.session_order,
            direction_node_id: run.direction_node_id,
            episode_node_id: run.episode_node_id,
            stream_offset: run.stream_offset,
        });
    }
    incoming.sort_by_key(|sample| {
        (
            sample.session_order,
            sample.context.session,
            sample.stream_offset,
            sample.node_id,
        )
    });

    Ok(CollectedRawSamples {
        incoming,
        incomplete_sessions,
        omitted_runs,
    })
}

fn native_http_covered_frame(
    case: &Case,
    frame: &RecordFrameInput,
    plan: Option<&super::super::framing_discovery::FramingDiscoveryPlan>,
) -> Option<u64> {
    let input_node_id = case
        .node(frame.node_id)?
        .details
        .get("input_node")?
        .as_u64()?;
    let message_ranges = plan?.native_http_message_ranges(input_node_id)?;
    range_covered_by_native_messages(frame.stream_range, message_ranges).then_some(input_node_id)
}
