// Collect session-relative transform samples without erasing transport provenance

use super::super::framing_discovery::{
    FramingDiscoveryPlan, NativeHttpCoverage, range_covered_by_native_messages,
};
use super::super::peer_cohort::{self, PeerCohort};
use super::{
    Executor, RAW_RUN_FRAMING_RULE, RawRelationalRunInput, RecordCohortKey, RecordCohortOrigin,
    RecordFrameInput, RecoveryExecutionError, RelationalCohortKey, RelationalLane, SampleCohort,
    StoredSample, admit_sample_views, invalid_policy, operational,
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
        let normal_index =
            self.relational_cohort_index(key.clone(), runs.len(), RelationalLane::Normal)?;
        let incremental_index =
            self.relational_cohort_index(key, runs.len(), RelationalLane::Incremental)?;
        let mut normal = match normal_index {
            Some(index) => Some(
                self.relational_samples
                    .cohorts
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?,
            ),
            None => None,
        };
        let mut incremental = match incremental_index {
            Some(index) => Some(
                self.relational_samples
                    .incremental_cohorts
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?,
            ),
            None => None,
        };
        for cohort in normal.iter_mut().chain(incremental.iter_mut()) {
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
                .extend(incomplete_sessions.iter().copied());
        }
        admit_sample_views(
            self.case,
            normal,
            incremental.zip(incremental_limits),
            &incoming,
            normal_limits,
        )?;
        Ok(())
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

        let normal_index = self.relational_cohort_index(
            key.clone(),
            eligible_frames.len(),
            RelationalLane::Normal,
        )?;
        let incremental_index =
            self.relational_cohort_index(key, eligible_frames.len(), RelationalLane::Incremental)?;
        let mut normal = match normal_index {
            Some(index) => Some(
                self.relational_samples
                    .cohorts
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?,
            ),
            None => None,
        };
        let mut incremental = match incremental_index {
            Some(index) => Some(
                self.relational_samples
                    .incremental_cohorts
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?,
            ),
            None => None,
        };
        for cohort in normal.iter_mut().chain(incremental.iter_mut()) {
            cohort.input_coverage_complete &= source_coverage_complete;
            cohort.source_eligibility_omissions = cohort
                .source_eligibility_omissions
                .max(source_eligibility_omissions);
        }
        admit_sample_views(
            self.case,
            normal,
            incremental.zip(incremental_limits),
            &incoming,
            normal_limits,
        )?;
        Ok(())
    }
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
