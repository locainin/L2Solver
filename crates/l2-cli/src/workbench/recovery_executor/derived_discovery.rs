//! Carry validated TCP context through derived byte generations

use super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask,
    framing_discovery::{
        FramingCohortKey, FramingDiscoveryPlan, FramingInput, range_covered_by_native_messages,
    },
    record_discovery::{RecordCohortKey, RecordCohortOrigin, RecordFrameInput},
};
use l2_workbench::{
    derivation::Recipe,
    evidence::{Case, Node},
    protocol::{ByteRange as StreamRange, Direction, FramingKind, ProtocolLimits},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const ROOT_ANCESTRY: u64 = 0;

#[derive(Clone, Eq, PartialEq)]
enum AncestryStep {
    Transform(Recipe),
    Framing(FramingKind),
}

struct AncestryPath {
    id: u64,
    parent: u64,
    step: AncestryStep,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DerivedFramingCohortKey {
    tcp: FramingCohortKey,
    ancestry_id: u64,
}

#[derive(Clone)]
struct DerivedByteContext {
    cohort: FramingCohortKey,
    input: FramingInput,
    ancestry_id: u64,
}

struct PendingFramingInput {
    context: DerivedByteContext,
    parent: RecoveryCandidateId,
}

#[derive(Clone, Copy)]
pub(super) struct TransformOutputRegistration<'a> {
    input_node: u64,
    output_node: u64,
    receipt_node: u64,
    parent: RecoveryCandidateId,
    recipe: &'a Recipe,
    maximum_contexts: usize,
    limits: ProtocolLimits,
}

#[derive(Clone, Copy)]
pub(super) struct MaterializedFrameRegistration<'a> {
    pub(super) input_node: u64,
    pub(super) receipt_node: u64,
    pub(super) frame_node_ids: &'a [u64],
    pub(super) rule: &'a FramingKind,
    pub(super) parent: RecoveryCandidateId,
    pub(super) discover_records: bool,
    pub(super) maximum_contexts: usize,
}

pub(super) struct DerivedFramingCohort {
    pub(super) key: FramingCohortKey,
    pub(super) ancestry_id: String,
    pub(super) inputs: Vec<FramingInput>,
    pub(super) parents: Vec<RecoveryCandidateId>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DerivedGenerationId {
    node_id: u64,
    source_id: String,
    scope: String,
    session: u64,
    direction: Direction,
    ancestry_id: u64,
}

#[derive(Default)]
pub(super) struct DerivedDiscovery {
    contexts_by_node: HashMap<u64, DerivedByteContext>,
    generations: BTreeSet<DerivedGenerationId>,
    ancestry_paths: Vec<AncestryPath>,
    pending_framing: BTreeMap<DerivedFramingCohortKey, Vec<PendingFramingInput>>,
    pending_records: BTreeMap<RecordCohortKey, Vec<(RecoveryCandidateId, RecordFrameInput)>>,
    omission_counts: BTreeMap<String, BTreeMap<&'static str, usize>>,
}

impl DerivedDiscovery {
    pub(super) fn seed_tcp_contexts(
        &mut self,
        plan: &FramingDiscoveryPlan,
        maximum_contexts: usize,
    ) -> Result<(), RecoveryExecutionError> {
        for (cohort, input) in plan.cohort_inputs() {
            if self.contexts_by_node.contains_key(&input.node_id) {
                continue;
            }
            // A complete native message already accounts for every observed byte in this run
            let fully_covered =
                plan.native_http_message_ranges(input.node_id)
                    .is_some_and(|message_ranges| {
                        range_covered_by_native_messages(
                            StreamRange {
                                start: 0,
                                end: input.byte_length,
                            },
                            message_ranges,
                        )
                    });
            if fully_covered {
                continue;
            }
            if self.contexts_by_node.len() >= maximum_contexts {
                self.record_omission(&input.source_id, "derived_context_limit")?;
                continue;
            }
            let context = DerivedByteContext {
                cohort: cohort.clone(),
                input: input.clone(),
                ancestry_id: ROOT_ANCESTRY,
            };
            self.contexts_by_node.insert(input.node_id, context);
        }
        Ok(())
    }

    pub(super) fn has_context(&self, node_id: u64) -> bool {
        self.contexts_by_node.contains_key(&node_id)
    }

    pub(super) fn discard_pending_framing(&mut self) {
        self.pending_framing.clear();
    }

    pub(super) fn register_transform_output(
        &mut self,
        case: &Case,
        registration: TransformOutputRegistration<'_>,
    ) -> Result<bool, RecoveryExecutionError> {
        let TransformOutputRegistration {
            input_node,
            output_node,
            receipt_node,
            parent,
            recipe,
            maximum_contexts,
            limits,
        } = registration;
        let Some(parent_context) = self.contexts_by_node.get(&input_node).cloned() else {
            return Ok(false);
        };
        let (blob_id, byte_length) =
            contextual_transform_output(case, input_node, output_node, receipt_node)?;
        if byte_length == 0 {
            return Ok(false);
        }
        if byte_length > limits.max_run_bytes {
            self.record_omission(&parent_context.input.source_id, "run_too_large")?;
            return Ok(false);
        }
        let Some(ancestry_id) = self.extend_ancestry(
            parent_context.ancestry_id,
            AncestryStep::Transform(recipe.clone()),
            maximum_contexts,
        )?
        else {
            self.record_omission(&parent_context.input.source_id, "ancestry_limit")?;
            return Ok(false);
        };
        let mut input = parent_context.input.clone();
        input.node_id = output_node;
        input.blob_id = blob_id;
        input.byte_length = byte_length;
        // Decoded output has its own exact byte origin and begins at offset zero
        input.stream_offset = 0;
        let generation = generation_id(&input, ancestry_id);
        if !self.generations.insert(generation) {
            return Ok(false);
        }
        if self.contexts_by_node.len() >= maximum_contexts {
            self.record_omission(&parent_context.input.source_id, "derived_context_limit")?;
            return Ok(false);
        }
        let context = DerivedByteContext {
            cohort: parent_context.cohort.clone(),
            input,
            ancestry_id,
        };
        self.contexts_by_node.insert(output_node, context.clone());
        self.pending_framing
            .entry(DerivedFramingCohortKey {
                tcp: context.cohort.clone(),
                ancestry_id,
            })
            .or_default()
            .push(PendingFramingInput { context, parent });
        Ok(true)
    }

    pub(super) fn register_materialized_frames(
        &mut self,
        case: &Case,
        registration: MaterializedFrameRegistration<'_>,
    ) -> Result<(), RecoveryExecutionError> {
        let MaterializedFrameRegistration {
            input_node,
            receipt_node,
            frame_node_ids,
            rule,
            parent,
            discover_records,
            maximum_contexts,
        } = registration;
        let Some(parent_context) = self.contexts_by_node.get(&input_node).cloned() else {
            return Ok(());
        };
        let Some(ancestry_id) = self.extend_ancestry(
            parent_context.ancestry_id,
            AncestryStep::Framing(rule.clone()),
            maximum_contexts,
        )?
        else {
            for _ in frame_node_ids {
                self.record_omission(&parent_context.input.source_id, "ancestry_limit")?;
            }
            return Ok(());
        };
        let ancestry_label = ancestry_label(ancestry_id);
        let framing_rule_json = serde_json::to_string(rule).map_err(|source| {
            operational("derived framing ancestry serialization failed", source)
        })?;

        for frame_node_id in frame_node_ids {
            let frame = case.node(*frame_node_id).ok_or(
                l2_workbench::recovery::RecoveryError::UnknownEvidenceNode {
                    node_id: *frame_node_id,
                },
            )?;
            let Some(context) = Self::frame_context(case, &parent_context, frame, ancestry_id)?
            else {
                self.record_omission(&parent_context.input.source_id, "invalid_derived_frame")?;
                continue;
            };
            let generation = generation_id(&context.input, ancestry_id);
            if !self.generations.insert(generation) {
                continue;
            }
            if self.contexts_by_node.len() >= maximum_contexts {
                self.record_omission(&parent_context.input.source_id, "derived_context_limit")?;
                continue;
            }
            self.contexts_by_node
                .insert(*frame_node_id, context.clone());
            if !discover_records {
                continue;
            }
            let record_key = RecordCohortKey {
                source_id: context.cohort.source_id.clone(),
                scope_json: context.cohort.scope.clone(),
                endpoints_json: context.cohort.endpoint_pair.clone(),
                direction: context.cohort.direction,
                origin: RecordCohortOrigin::Transformed {
                    ancestry_id: ancestry_label.clone(),
                },
                framing_rule_json: framing_rule_json.clone(),
            };
            let frame_input = record_frame_input(frame, receipt_node, &context.input)?;
            self.pending_records
                .entry(record_key)
                .or_default()
                .push((parent, frame_input));
        }
        Ok(())
    }

    pub(super) fn take_framing_cohorts(
        &mut self,
        limits: ProtocolLimits,
    ) -> Result<Vec<DerivedFramingCohort>, RecoveryExecutionError> {
        let pending = std::mem::take(&mut self.pending_framing);
        let mut cohorts = Vec::new();
        cohorts
            .try_reserve_exact(pending.len())
            .map_err(|source| operational("derived framing cohort allocation failed", source))?;
        for (key, entries) in pending {
            if let Some(cohort) = self.collect_framing_cohort(key, entries, limits)? {
                cohorts.push(cohort);
            }
        }
        Ok(cohorts)
    }

    fn collect_framing_cohort(
        &mut self,
        key: DerivedFramingCohortKey,
        mut entries: Vec<PendingFramingInput>,
        limits: ProtocolLimits,
    ) -> Result<Option<DerivedFramingCohort>, RecoveryExecutionError> {
        sort_pending_framing_inputs(&mut entries);
        let input_capacity = entries.len().min(limits.max_samples);
        let mut inputs = Vec::new();
        let mut parents = Vec::new();
        inputs
            .try_reserve_exact(input_capacity)
            .map_err(|source| operational("derived framing input allocation failed", source))?;
        parents
            .try_reserve_exact(input_capacity)
            .map_err(|source| operational("derived framing parent allocation failed", source))?;
        let mut retained = 0_usize;
        let mut total_bytes = 0_usize;
        for entry in entries {
            let input = entry.context.input;
            if let Some(reason) = framing_input_omission(&input, retained, total_bytes, limits) {
                self.record_omission(&input.source_id, reason)?;
                continue;
            }
            if input.byte_length == 0 {
                continue;
            }
            total_bytes = total_bytes
                .checked_add(input.byte_length)
                .ok_or_else(|| invalid_work("derived framing input bytes overflowed"))?;
            retained = retained
                .checked_add(1)
                .ok_or_else(|| invalid_work("derived framing input count overflowed"))?;
            inputs.push(input);
            parents.push(entry.parent);
        }
        if inputs.is_empty() {
            return Ok(None);
        }
        Ok(Some(DerivedFramingCohort {
            key: key.tcp,
            ancestry_id: ancestry_label(key.ancestry_id),
            inputs,
            parents,
        }))
    }

    pub(super) fn take_record_cohorts(
        &mut self,
    ) -> BTreeMap<RecordCohortKey, Vec<(RecoveryCandidateId, RecordFrameInput)>> {
        std::mem::take(&mut self.pending_records)
    }

    pub(super) fn take_omissions(
        &mut self,
    ) -> Result<Vec<RecoveryOmission>, RecoveryExecutionError> {
        let pending = std::mem::take(&mut self.omission_counts);
        let mut omissions = Vec::new();
        omissions
            .try_reserve_exact(pending.len())
            .map_err(|source| operational("derived omission allocation failed", source))?;
        for (source_id, reason_counts) in pending {
            let omitted_runs = reason_counts
                .values()
                .try_fold(0_usize, |total, count| total.checked_add(*count));
            let omitted_runs =
                omitted_runs.ok_or_else(|| invalid_work("derived omission count overflowed"))?;
            omissions.push(RecoveryOmission::FramingDiscoveryInputs {
                source_id: Some(source_id),
                omitted_runs,
                reason_counts,
            });
        }
        Ok(omissions)
    }

    fn frame_context(
        case: &Case,
        parent: &DerivedByteContext,
        frame: &Node,
        ancestry_id: u64,
    ) -> Result<Option<DerivedByteContext>, RecoveryExecutionError> {
        if frame.kind != "custom_protocol_frame" {
            return Ok(None);
        }
        let Some(blob_id) = frame.blob.clone() else {
            return Ok(None);
        };
        let byte_length = frame
            .details
            .get("stream_range")
            .and_then(|value| value.get("end"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .zip(
                frame
                    .details
                    .get("stream_range")
                    .and_then(|value| value.get("start"))
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok()),
            )
            .and_then(|(end, start)| end.checked_sub(start))
            .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?;
        if case
            .blob(&blob_id)
            .is_none_or(|blob| blob.bytes.len() != byte_length)
        {
            return Err(l2_workbench::recovery::RecoveryError::InvariantFailure.into());
        }
        let mut input = parent.input.clone();
        input.node_id = frame.id;
        input.blob_id = blob_id;
        input.byte_length = byte_length;
        // The frame has a new local byte origin; offsets from prior transforms do not compose
        input.stream_offset = 0;
        Ok(Some(DerivedByteContext {
            cohort: parent.cohort.clone(),
            input,
            ancestry_id,
        }))
    }

    fn extend_ancestry(
        &mut self,
        parent: u64,
        step: AncestryStep,
        maximum_paths: usize,
    ) -> Result<Option<u64>, RecoveryExecutionError> {
        if let Some(path) = self
            .ancestry_paths
            .iter()
            .find(|path| path.parent == parent && path.step == step)
        {
            return Ok(Some(path.id));
        }
        if self.ancestry_paths.len() >= maximum_paths {
            return Ok(None);
        }
        self.ancestry_paths
            .try_reserve(1)
            .map_err(|source| operational("derived ancestry allocation failed", source))?;
        let id = u64::try_from(self.ancestry_paths.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| invalid_work("derived ancestry identifier overflowed"))?;
        self.ancestry_paths.push(AncestryPath { id, parent, step });
        Ok(Some(id))
    }

    fn record_omission(
        &mut self,
        source_id: &str,
        reason: &'static str,
    ) -> Result<(), RecoveryExecutionError> {
        let count = self
            .omission_counts
            .entry(source_id.to_owned())
            .or_default()
            .entry(reason)
            .or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| invalid_work("derived omission reason count overflowed"))?;
        Ok(())
    }
}

fn sort_pending_framing_inputs(entries: &mut [PendingFramingInput]) {
    entries.sort_by(|left, right| {
        left.context
            .input
            .session_order
            .cmp(&right.context.input.session_order)
            .then_with(|| {
                left.context
                    .input
                    .context
                    .session
                    .cmp(&right.context.input.context.session)
            })
            .then_with(|| {
                left.context
                    .input
                    .context
                    .direction
                    .cmp(&right.context.input.context.direction)
            })
            .then_with(|| {
                left.context
                    .input
                    .stream_offset
                    .cmp(&right.context.input.stream_offset)
            })
            .then_with(|| left.context.input.node_id.cmp(&right.context.input.node_id))
    });
}

fn contextual_transform_output(
    case: &Case,
    input_node: u64,
    output_node: u64,
    receipt_node: u64,
) -> Result<(String, usize), RecoveryExecutionError> {
    let output = case.node(output_node).ok_or(
        l2_workbench::recovery::RecoveryError::UnknownEvidenceNode {
            node_id: output_node,
        },
    )?;
    if output.kind != "decoding_output"
        || output
            .details
            .get("source_input_node")
            .and_then(Value::as_u64)
            != Some(input_node)
        || output
            .details
            .get("shared_transform_receipt")
            .and_then(Value::as_u64)
            != Some(receipt_node)
        || !output.ranges.is_empty()
    {
        return Err(l2_workbench::recovery::RecoveryError::InvariantFailure.into());
    }
    let blob_id =
        output
            .blob
            .clone()
            .ok_or(l2_workbench::recovery::RecoveryError::InputBlobMissing {
                node_id: output_node,
            })?;
    let byte_length = case
        .blob(&blob_id)
        .map(|blob| blob.bytes.len())
        .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?;
    Ok((blob_id, byte_length))
}

fn framing_input_omission(
    input: &FramingInput,
    retained: usize,
    total_bytes: usize,
    limits: ProtocolLimits,
) -> Option<&'static str> {
    if input.byte_length == 0 {
        None
    } else if input.byte_length > limits.max_run_bytes {
        Some("run_too_large")
    } else if retained >= limits.max_samples {
        Some("too_many_samples")
    } else if total_bytes
        .checked_add(input.byte_length)
        .is_none_or(|total| total > limits.max_total_bytes)
    {
        Some("total_bytes")
    } else {
        None
    }
}

fn generation_id(input: &FramingInput, ancestry_id: u64) -> DerivedGenerationId {
    DerivedGenerationId {
        node_id: input.node_id,
        source_id: input.source_id.clone(),
        scope: input.context.scope.clone(),
        session: input.context.session,
        direction: input.context.direction,
        ancestry_id,
    }
}

fn ancestry_label(ancestry_id: u64) -> String {
    format!("derived-{ancestry_id}")
}

fn record_frame_input(
    frame: &Node,
    receipt_node_id: u64,
    context: &FramingInput,
) -> Result<RecordFrameInput, RecoveryExecutionError> {
    let frame_index = frame
        .details
        .get("frame_index")
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?;
    let stream_range = frame
        .details
        .get("stream_range")
        .cloned()
        .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)
        .and_then(|range| {
            serde_json::from_value(range)
                .map_err(|_| l2_workbench::recovery::RecoveryError::InvariantFailure)
        })?;
    let blob_id = frame
        .blob
        .clone()
        .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?;
    Ok(RecordFrameInput {
        node_id: frame.id,
        blob_id,
        receipt_node_id,
        session_node_id: context.episode_node_id,
        direction_node_id: context.direction_node_id,
        episode_node_id: context.episode_node_id,
        session_id: context.context.session,
        frame_index,
        stream_range,
        stream_offset: stream_range.start,
        byte_length: stream_range
            .end
            .checked_sub(stream_range.start)
            .ok_or(l2_workbench::recovery::RecoveryError::InvariantFailure)?,
    })
}

fn operational(
    message: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: RecoveryStage::FramingDiscovery,
        source: format!("{message}: {source}").into(),
    }
}

fn invalid_work(message: &'static str) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(message.to_owned())
}

impl Executor<'_> {
    pub(super) fn flush_derived_discovery(&mut self) -> Result<bool, RecoveryExecutionError> {
        if self.flush_derived_framing_discovery()? {
            return Ok(true);
        }
        self.flush_derived_record_discovery()
    }

    pub(super) fn flush_derived_framing_discovery(
        &mut self,
    ) -> Result<bool, RecoveryExecutionError> {
        if !self.plan.discover_framing {
            self.derived_discovery.discard_pending_framing();
            return Ok(false);
        }
        let cohorts = self
            .derived_discovery
            .take_framing_cohorts(ProtocolLimits::default())?;
        let scheduled = !cohorts.is_empty();
        for cohort in cohorts {
            self.enqueue_derived_framing_discovery(cohort)?;
        }
        self.omissions
            .extend(self.derived_discovery.take_omissions()?);
        Ok(scheduled)
    }

    pub(super) fn flush_derived_record_discovery(
        &mut self,
    ) -> Result<bool, RecoveryExecutionError> {
        if !self.plan.discover_records {
            self.derived_discovery.take_record_cohorts();
            self.omissions
                .extend(self.derived_discovery.take_omissions()?);
            return Ok(false);
        }
        let cohorts = self.derived_discovery.take_record_cohorts();
        let scheduled = !cohorts.is_empty();
        for (key, frames) in cohorts {
            self.enqueue_derived_record_discovery(key, frames)?;
        }
        self.omissions
            .extend(self.derived_discovery.take_omissions()?);
        Ok(scheduled)
    }

    pub(super) fn seed_derived_tcp_contexts(
        &mut self,
        plan: &FramingDiscoveryPlan,
    ) -> Result<(), RecoveryExecutionError> {
        let transform_candidates_enabled = self.plan.discover_transforms
            || (self.plan.discover_framing && !self.plan.recipes.is_empty());
        if transform_candidates_enabled {
            self.derived_discovery
                .seed_tcp_contexts(plan, self.policy.resources.max_context_aliases)?;
            self.omissions
                .extend(self.derived_discovery.take_omissions()?);
        }
        Ok(())
    }

    pub(super) fn register_derived_transform_output(
        &mut self,
        input_node: u64,
        output_node: u64,
        receipt_node: u64,
        parent: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(parent)
            .ok_or(l2_workbench::recovery::RecoveryError::UnknownCandidate { id: parent })?;
        let RecoveryTask::Transform(recipe) = candidate.task() else {
            return Err(l2_workbench::recovery::RecoveryError::InvariantFailure.into());
        };
        self.derived_discovery.register_transform_output(
            self.case,
            TransformOutputRegistration {
                input_node,
                output_node,
                receipt_node,
                parent,
                recipe,
                maximum_contexts: self.policy.resources.max_context_aliases,
                limits: ProtocolLimits::default(),
            },
        )?;
        self.omissions
            .extend(self.derived_discovery.take_omissions()?);
        Ok(())
    }
}
