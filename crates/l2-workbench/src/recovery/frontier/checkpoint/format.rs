//! Versioned checkpoint records and allocation-free count checks

use super::super::super::{
    RecoveryCandidateId, RecoveryCandidateState, RecoveryResourcePolicy, RecoveryTask,
};
use super::super::RecoveryError;
use serde::{
    Deserialize, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{fmt, marker::PhantomData};

pub(super) const VERSION: u32 = 1;

#[derive(Serialize)]
pub(super) struct CheckpointRef<'a> {
    pub(super) version: u32,
    pub(super) case_sha256: String,
    pub(super) resources: RecoveryResourcePolicy,
    pub(super) candidates: Vec<CandidateRef<'a>>,
    pub(super) frontier: &'a std::collections::VecDeque<RecoveryCandidateId>,
    pub(super) work_bytes: usize,
    pub(super) lineage_work: usize,
    pub(super) associations: Vec<AssociationRef<'a>>,
}

#[derive(Serialize)]
pub(super) struct CandidateRef<'a> {
    pub(super) inputs: Vec<InputRef<'a>>,
    pub(super) task: &'a RecoveryTask,
    pub(super) depth: usize,
    pub(super) parent_ids: &'a [RecoveryCandidateId],
    pub(super) pending_origin_node_ids: &'a [u64],
    pub(super) completion_priority: bool,
    pub(super) state: &'a RecoveryCandidateState,
}

#[derive(Serialize)]
pub(super) struct InputRef<'a> {
    pub(super) blob_id: &'a str,
    pub(super) origin_node_ids: &'a [u64],
}

#[derive(Serialize)]
pub(super) struct AssociationRef<'a> {
    pub(super) report_node_id: u64,
    pub(super) identity: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checkpoint {
    pub(super) version: u32,
    pub(super) case_sha256: String,
    pub(super) resources: RecoveryResourcePolicy,
    pub(super) candidates: Vec<Candidate>,
    pub(super) frontier: Vec<RecoveryCandidateId>,
    pub(super) work_bytes: usize,
    pub(super) lineage_work: usize,
    pub(super) associations: Vec<Association>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Candidate {
    pub(super) inputs: Vec<Input>,
    pub(super) task: RecoveryTask,
    pub(super) depth: usize,
    pub(super) parent_ids: Vec<RecoveryCandidateId>,
    pub(super) pending_origin_node_ids: Vec<u64>,
    pub(super) completion_priority: bool,
    pub(super) state: RecoveryCandidateState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) blob_id: String,
    pub(super) origin_node_ids: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Association {
    pub(super) report_node_id: u64,
    pub(super) identity: Box<RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preflight<'a> {
    version: u32,
    case_sha256: &'a str,
    resources: RecoveryResourcePolicy,
    #[serde(borrow)]
    candidates: &'a RawValue,
    #[serde(borrow)]
    frontier: &'a RawValue,
    work_bytes: usize,
    lineage_work: usize,
    #[serde(borrow)]
    associations: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightCandidate<'a> {
    #[serde(borrow)]
    inputs: &'a RawValue,
    #[serde(borrow)]
    task: &'a RawValue,
    depth: usize,
    #[serde(borrow)]
    parent_ids: &'a RawValue,
    #[serde(borrow)]
    pending_origin_node_ids: &'a RawValue,
    completion_priority: bool,
    state: IgnoredAny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightInput<'a> {
    blob_id: IgnoredAny,
    #[serde(borrow)]
    origin_node_ids: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightAssociation<'a> {
    report_node_id: u64,
    #[serde(borrow)]
    identity: &'a RawValue,
}

/// Check every retained collection before allocating the owned checkpoint records
pub(super) fn preflight(
    bytes: &[u8],
    expected: RecoveryResourcePolicy,
) -> Result<(), RecoveryError> {
    let raw: Preflight<'_> =
        serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    if raw.version != VERSION
        || raw.resources != expected
        || raw.case_sha256.len() != 64
        || raw.work_bytes > expected.max_work_bytes
        || raw.lineage_work > expected.max_lineage_work
    {
        return Err(RecoveryError::InvalidCheckpoint);
    }
    visit_array(raw.frontier, expected.max_frontier, |_| Ok(()))?;
    let mut parents = 0_usize;
    let mut aliases = 0_usize;
    let mut pending = 0_usize;
    let mut task_bytes = 0_usize;
    visit_array(raw.candidates, expected.max_candidates, |item| {
        let candidate: PreflightCandidate<'_> =
            serde_json::from_str(item.get()).map_err(|_| RecoveryError::InvalidCheckpoint)?;
        let _ = (
            candidate.depth,
            candidate.completion_priority,
            &candidate.state,
        );
        add_with_limit(
            &mut task_bytes,
            candidate.task.get().len(),
            expected.max_candidate_task_identity_bytes,
        )?;
        visit_array(candidate.parent_ids, expected.max_parent_links, |_| {
            add_with_limit(&mut parents, 1, expected.max_parent_links)
        })?;
        visit_array(
            candidate.pending_origin_node_ids,
            expected.max_pending_origin_links,
            |_| add_with_limit(&mut pending, 1, expected.max_pending_origin_links),
        )?;
        visit_array(
            candidate.inputs,
            expected.max_inputs_per_candidate,
            |input| {
                let input: PreflightInput<'_> = serde_json::from_str(input.get())
                    .map_err(|_| RecoveryError::InvalidCheckpoint)?;
                let _ = &input.blob_id;
                visit_array(
                    input.origin_node_ids,
                    expected.max_origins_per_candidate,
                    |_| add_with_limit(&mut aliases, 1, expected.max_context_aliases),
                )
            },
        )
    })?;
    let mut identity_bytes = 0_usize;
    visit_array(
        raw.associations,
        expected.max_transform_proposal_associations,
        |item| {
            let association: PreflightAssociation<'_> =
                serde_json::from_str(item.get()).map_err(|_| RecoveryError::InvalidCheckpoint)?;
            let _ = association.report_node_id;
            add_with_limit(
                &mut identity_bytes,
                association.identity.get().len(),
                expected.max_transform_proposal_identity_bytes,
            )
        },
    )
}

fn add_with_limit(total: &mut usize, amount: usize, limit: usize) -> Result<(), RecoveryError> {
    *total = total
        .checked_add(amount)
        .filter(|value| *value <= limit)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    Ok(())
}

fn visit_array<'de>(
    raw: &'de RawValue,
    maximum: usize,
    visit: impl FnMut(&'de RawValue) -> Result<(), RecoveryError>,
) -> Result<(), RecoveryError> {
    struct ArrayVisitor<F> {
        maximum: usize,
        visit: F,
        marker: PhantomData<fn()>,
    }
    impl<'de, F> Visitor<'de> for ArrayVisitor<F>
    where
        F: FnMut(&'de RawValue) -> Result<(), RecoveryError>,
    {
        type Value = ();
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array within the recovery resource budget")
        }
        fn visit_seq<A>(mut self, mut sequence: A) -> Result<(), A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut count = 0_usize;
            while let Some(item) = sequence.next_element::<&'de RawValue>()? {
                if count >= self.maximum {
                    return Err(serde::de::Error::custom(
                        "checkpoint collection exceeds its budget",
                    ));
                }
                count += 1;
                (self.visit)(item).map_err(serde::de::Error::custom)?;
            }
            Ok(())
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    serde::de::Deserializer::deserialize_seq(
        &mut deserializer,
        ArrayVisitor {
            maximum,
            visit,
            marker: PhantomData,
        },
    )
    .map_err(|_| RecoveryError::InvalidCheckpoint)?;
    deserializer
        .end()
        .map_err(|_| RecoveryError::InvalidCheckpoint)
}
