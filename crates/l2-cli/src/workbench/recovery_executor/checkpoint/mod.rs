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
    io::{self, Write},
    sync::Arc,
};

const VERSION: u32 = 1;

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

struct AdmittedSaved<'checkpoint> {
    // Drop decoded data before releasing its admission, including on failed restoration
    saved: Saved<'checkpoint>,
    memory: Option<MemoryLease>,
}

pub(super) fn write(
    executor: &Executor<'_>,
    cursor: &SchedulerCursor,
    output: &mut impl Write,
    max_bytes: usize,
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
    let mut buffer = buffer::Buffer::new(max_bytes, executor.memory.as_ref())?;
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
    };
    serde_json::to_writer(&mut output, &value).map_err(operational)
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
    let mut decoded = AdmittedSaved {
        saved: serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        memory: metadata_admission.map(l2_workbench::job::JsonMemoryAdmission::into_retained),
    };
    if decoded.saved.version != VERSION
        || decoded.saved.plan != *plan
        || policy_configuration(&decoded.saved.policy)? != policy_configuration(expected)?
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    decoded.saved.policy.bind_restored_case(case)?;
    let coordinator = RecoveryCoordinator::restore(
        case,
        expected.resources,
        decoded.saved.coordinator.get().as_bytes(),
        max_bytes,
    )?;
    let index = CaseIndex::restore_from_checkpoint(case, decoded.saved.index)?;
    let mut executor = decoded.saved.state.restore(
        case,
        plan,
        decoded.saved.policy,
        coordinator,
        index,
        memory,
    )?;
    // The cursor and executor can outlive each other, but share one admission
    let metadata_memory = decoded.memory.take().map(Arc::new);
    decoded
        .saved
        .cursor
        .checkpoint_memory
        .clone_from(&metadata_memory);
    executor.checkpoint_memory = metadata_memory;
    validate::executor(&executor)?;
    decoded.saved.cursor.validate(&executor)?;
    Ok((executor, decoded.saved.cursor))
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
}
impl<W: Write> Write for LimitedWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
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
