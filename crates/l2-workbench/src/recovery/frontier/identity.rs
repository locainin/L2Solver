//! Compare canonical task and recipe identities for candidate deduplication

use super::super::case_refs;
use super::super::{RecoveryInput, RecoveryTask};
use super::RecoveryError;
use crate::{derivation::OperationIdentity, sha256};
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};

pub(super) struct CandidateIdentity {
    pub(super) key: (String, String, usize),
    pub(super) task_identity_bytes: usize,
}

struct TaskIdentityEncoding {
    canonical_bytes: Vec<u8>,
    retained_bytes: usize,
}

pub(super) fn candidate_identity(
    inputs: &[RecoveryInput],
    task: &RecoveryTask,
    depth: usize,
) -> Result<CandidateIdentity, RecoveryError> {
    let input_key = case_refs::input_key(inputs, task_has_origin_context(task))?;
    let task_identity = task_identity_bytes(task)?;
    let task_key = sha256(&task_identity.canonical_bytes);
    Ok(CandidateIdentity {
        key: (input_key, task_key, depth),
        task_identity_bytes: task_identity.retained_bytes,
    })
}

pub(super) fn candidate_work_identity(
    inputs: &[RecoveryInput],
    task: &RecoveryTask,
) -> Result<(String, String), RecoveryError> {
    let input_key = case_refs::input_key(inputs, task_has_origin_context(task))?;
    let task_bytes = task_identity_bytes(task)?;
    Ok((input_key, sha256(&task_bytes.canonical_bytes)))
}

fn task_identity_bytes(task: &RecoveryTask) -> Result<TaskIdentityEncoding, RecoveryError> {
    validate_task_identity(task)?;
    let (canonical_bytes, retained_bytes) = if let RecoveryTask::Transform(_) = task {
        let retained_bytes = serde_json::to_vec(task)
            .map_err(|_| RecoveryError::IdentityEncoding)?
            .len();
        let canonical_bytes =
            serde_json::to_vec(&TaskIdentity(task)).map_err(|_| RecoveryError::IdentityEncoding)?;
        (canonical_bytes, retained_bytes)
    } else {
        let canonical_bytes =
            serde_json::to_vec(&TaskIdentity(task)).map_err(|_| RecoveryError::IdentityEncoding)?;
        let retained_bytes = canonical_bytes.len();
        (canonical_bytes, retained_bytes)
    };
    Ok(TaskIdentityEncoding {
        canonical_bytes,
        retained_bytes,
    })
}

pub(super) fn canonical_recipe_identity_bytes(
    recipe: &crate::derivation::Recipe,
) -> Result<Vec<u8>, RecoveryError> {
    crate::derivation::validate_recipe_identity(recipe)
        .map_err(RecoveryError::InvalidTaskIdentity)?;
    serde_json::to_vec(&TransformTaskIdentity(recipe)).map_err(|_| RecoveryError::IdentityEncoding)
}

fn validate_task_identity(task: &RecoveryTask) -> Result<(), RecoveryError> {
    if let RecoveryTask::Transform(recipe) = task {
        crate::derivation::validate_recipe_identity(recipe)
            .map_err(RecoveryError::InvalidTaskIdentity)?;
    }
    Ok(())
}

pub(super) fn same_task_identity(left: &RecoveryTask, right: &RecoveryTask) -> bool {
    TaskIdentity(left) == TaskIdentity(right)
}

// Identity sees execution equivalence while the retained task keeps its supplied recipe
struct TaskIdentity<'a>(&'a RecoveryTask);

impl PartialEq for TaskIdentity<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self.0, other.0) {
            (RecoveryTask::Transform(left), RecoveryTask::Transform(right)) => {
                left.constraints == right.constraints
                    && left.steps.len() == right.steps.len()
                    && left.steps.iter().zip(&right.steps).all(|(left, right)| {
                        OperationIdentity::new(left) == OperationIdentity::new(right)
                    })
            }
            (left, right) => left == right,
        }
    }
}

impl Eq for TaskIdentity<'_> {}

impl Serialize for TaskIdentity<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            RecoveryTask::Transform(recipe) => TransformTaskIdentity(recipe).serialize(serializer),
            task => task.serialize(serializer),
        }
    }
}

struct TransformTaskIdentity<'a>(&'a crate::derivation::Recipe);

impl Serialize for TransformTaskIdentity<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RecoveryTask", 2)?;
        state.serialize_field("task", "transform")?;
        state.serialize_field(
            "operation",
            &TransformRecipeIdentity {
                steps: OperationIdentities(&self.0.steps),
                constraints: &self.0.constraints,
            },
        )?;
        state.end()
    }
}

#[derive(Serialize)]
struct TransformRecipeIdentity<'a> {
    steps: OperationIdentities<'a>,
    constraints: &'a [crate::derivation::Constraint],
}

struct OperationIdentities<'a>(&'a [crate::derivation::Operation]);

impl Serialize for OperationIdentities<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for operation in self.0 {
            sequence.serialize_element(&OperationIdentity::new(operation))?;
        }
        sequence.end()
    }
}

pub(super) fn task_has_origin_context(task: &RecoveryTask) -> bool {
    // These stages retain groupings or byte mappings tied to exact source nodes
    matches!(
        task,
        RecoveryTask::TransformDiscovery
            | RecoveryTask::FramingDiscovery
            | RecoveryTask::MaterializeFraming(_)
            | RecoveryTask::RecordDiscovery
            | RecoveryTask::RelationalTransformDiscovery
            | RecoveryTask::RelationalTransformDiscoveryIncremental
            | RecoveryTask::AssembleRecords(_)
    ) || matches!(task, RecoveryTask::Transform(recipe) if crate::derivation::has_selected_input_reference(recipe))
}
