//! Capture executor state only between committed scheduler operations

mod buffer;
pub(in crate::workbench::recovery_executor) mod collections;
mod memory;
mod state;
mod validate;

use super::execution_state::SchedulerCursor;
use super::{
    Case, CaseIndex, Executor, RecoveryExecutionError, RecoveryExecutionPolicy, RecoveryPlan,
};
use l2_workbench::{
    job::{MemoryBudget, MemoryLease},
    recovery::{RecoveryCoordinator, RecoveryError},
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    sync::Arc,
};

// Older snapshots lack the receipts needed to resume an inner search safely
const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CheckpointUnavailable {
    SizeLimit,
}

impl fmt::Display for CheckpointUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeLimit => formatter.write_str("executor checkpoint exceeds its byte limit"),
        }
    }
}

impl Error for CheckpointUnavailable {}

pub(super) fn unavailable(reason: CheckpointUnavailable) -> RecoveryExecutionError {
    operational(reason)
}

pub(super) fn unavailable_reason(error: &RecoveryExecutionError) -> Option<CheckpointUnavailable> {
    crate::memory_error::find_map(error, |cause| {
        cause.downcast_ref::<CheckpointUnavailable>().copied()
    })
}

#[derive(Serialize)]
struct SavedRef<'a> {
    version: u32,
    plan: &'a RecoveryPlan,
    policy: &'a RecoveryExecutionPolicy,
    cursor: &'a SchedulerCursor,
    index: super::CaseIndexCursor,
    coordinator: &'a RawValue,
    state: state::StateRef<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved<'checkpoint> {
    version: u32,
    plan: RecoveryPlan,
    policy: RecoveryExecutionPolicy,
    cursor: SchedulerCursor,
    index: super::CaseIndexCursor,
    #[serde(borrow)]
    coordinator: &'checkpoint RawValue,
    state: state::State,
}

#[cfg(test)]
pub(super) fn write(
    executor: &Executor<'_>,
    cursor: &SchedulerCursor,
    output: &mut impl Write,
    max_bytes: usize,
) -> Result<(), RecoveryExecutionError> {
    write_with_memory(
        executor,
        cursor,
        output,
        max_bytes,
        executor.memory.as_ref(),
    )
}

pub(super) fn write_with_memory(
    executor: &Executor<'_>,
    cursor: &SchedulerCursor,
    output: &mut impl Write,
    max_bytes: usize,
    memory: Option<&MemoryBudget>,
) -> Result<(), RecoveryExecutionError> {
    // Supplied recipes may not have reached the frontier at this boundary
    for recipe in &executor.plan.recipes {
        RecoveryCoordinator::validate_checkpoint_recipe(recipe)?;
    }
    for cohort in &executor.transform_cohorts {
        if let l2_workbench::recovery::RecoveryTask::Transform(recipe) = &cohort.task {
            RecoveryCoordinator::validate_checkpoint_recipe(recipe)?;
        }
    }
    executor.derived_discovery.validate_checkpoint_recipes()?;
    let mut buffer = buffer::Buffer::new(max_bytes, memory)?;
    if let Err(error) = executor
        .coordinator
        .write_checkpoint(executor.case, &mut buffer, max_bytes)
    {
        return Err(buffer.failure.take().unwrap_or_else(|| error.into()));
    }
    let buffer::Buffer {
        bytes: coordinator,
        memory: _memory,
        ..
    } = buffer;
    let coordinator = RawValue::from_string(
        String::from_utf8(coordinator).map_err(|_| RecoveryError::InvalidCheckpoint)?,
    )
    .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    let value = SavedRef {
        version: VERSION,
        plan: executor.plan,
        policy: &executor.policy,
        cursor,
        index: executor.case_index.checkpoint_cursor(),
        coordinator: &coordinator,
        state: state::StateRef::capture(executor)?,
    };
    let mut output = LimitedWriter {
        output,
        remaining: max_bytes,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut output, &value);
    if output.exceeded {
        return Err(unavailable(CheckpointUnavailable::SizeLimit));
    }
    result.map_err(operational)
}

pub(super) fn encode<T: Serialize + ?Sized>(
    value: &T,
    max_bytes: usize,
    memory: Option<&MemoryBudget>,
) -> Result<(Vec<u8>, Option<MemoryLease>), RecoveryExecutionError> {
    let mut buffer = buffer::Buffer::new(max_bytes, memory)?;
    let (result, exceeded) = {
        let mut output = LimitedWriter {
            output: &mut buffer,
            remaining: max_bytes,
            exceeded: false,
        };
        let result = serde_json::to_writer(&mut output, value);
        (result, output.exceeded)
    };
    if let Some(error) = buffer.failure.take() {
        return Err(error);
    }
    if exceeded {
        return Err(unavailable(CheckpointUnavailable::SizeLimit));
    }
    result.map_err(operational)?;
    Ok((buffer.bytes, buffer.memory))
}

pub(super) fn measure<T: Serialize + ?Sized>(
    value: &T,
    max_bytes: usize,
) -> Result<(), RecoveryExecutionError> {
    let mut sink = io::sink();
    let mut output = LimitedWriter {
        output: &mut sink,
        remaining: max_bytes,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut output, value);
    if output.exceeded {
        return Err(unavailable(CheckpointUnavailable::SizeLimit));
    }
    result.map_err(operational)
}

pub(super) fn read<'a>(
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    expected: &RecoveryExecutionPolicy,
    bytes: &[u8],
    max_bytes: usize,
    memory: Option<&MemoryBudget>,
) -> Result<(Executor<'a>, SchedulerCursor), RecoveryExecutionError> {
    if bytes.len() > max_bytes {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let metadata_admission = memory::admit(bytes, memory)?;
    // The decoded value is dropped before its earlier admission on every error path
    let mut saved: Saved<'_> =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    if saved.version != VERSION
        || saved.plan != *plan
        || policy_configuration(&saved.policy)? != policy_configuration(expected)?
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    saved.policy.bind_restored_case(case)?;
    let coordinator = RecoveryCoordinator::restore(
        case,
        expected.resources,
        saved.coordinator.get().as_bytes(),
        max_bytes,
    )?;
    let index = CaseIndex::restore_from_checkpoint(case, saved.index, memory)?;
    let mut executor = saved
        .state
        .restore(case, plan, saved.policy, coordinator, index, memory)?;
    // The coordinator is parsed and indexed after the outer JSON has been decoded
    // The cursor and executor can outlive each other, but share one admission
    let metadata_memory = metadata_admission
        .map(l2_workbench::job::JsonMemoryAdmission::into_retained)
        .map(Arc::new);
    saved.cursor.checkpoint_memory.clone_from(&metadata_memory);
    executor.checkpoint_memory = metadata_memory;
    validate::executor(&executor)?;
    saved.cursor.validate(&executor)?;
    Ok((executor, saved.cursor))
}

fn policy_configuration(
    policy: &RecoveryExecutionPolicy,
) -> Result<Vec<u8>, RecoveryExecutionError> {
    #[derive(Serialize)]
    struct Configuration<'a> {
        resources: &'a l2_workbench::recovery::RecoveryResourcePolicy,
        derivation: &'a l2_workbench::derivation::DerivationLimits,
        decode: &'a super::DecodeBatchLimits,
        records: &'a l2_workbench::protocol::RecordLimits,
        expansion: &'a super::ExpansionLimits,
        embedded: &'a l2_workbench::artifact::EmbeddedDiscoveryLimits,
        validation: &'a l2_workbench::artifact::ArtifactValidationPolicy,
        transforms: &'a super::model::TransformExplorationBudget,
        schemas: &'a l2_workbench::protocol::RecordSchemaProposalLimits,
        relational: &'a l2_workbench::protocol::RelationalTransformPlan,
        incremental: &'a Option<l2_workbench::protocol::RelationalTransformPlan>,
        record_work: usize,
    }
    serde_json::to_vec(&Configuration {
        resources: &policy.resources,
        derivation: &policy.derivation_limits,
        decode: &policy.decode_batch_limits,
        records: &policy.record_limits,
        expansion: &policy.expansion_limits,
        embedded: &policy.embedded_limits,
        validation: &policy.artifact_validation_policy,
        transforms: &policy.transform_exploration,
        schemas: &policy.record_schema_proposal_limits,
        relational: &policy.relational_transform_plan,
        incremental: &policy.relational_incremental_plan,
        record_work: policy.record_phase_work_limit,
    })
    .map_err(operational)
}

fn operational(error: impl std::error::Error + 'static) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: l2_workbench::recovery::RecoveryStage::TransformDiscovery,
        source: Box::new(error),
    }
}

struct LimitedWriter<'a, W> {
    output: &'a mut W,
    remaining: usize,
    exceeded: bool,
}
impl<W: Write> Write for LimitedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "executor checkpoint exceeds its byte limit",
            ));
        }
        let count = self.output.write(bytes)?;
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
