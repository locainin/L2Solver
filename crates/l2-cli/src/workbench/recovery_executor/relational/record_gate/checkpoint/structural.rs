//! Recheck frozen structural schemas and their exact family memberships

use super::SchemaCacheRestoreContext;
use crate::workbench::recovery_executor::{
    RecoveryExecutionError,
    relational::{
        DecodedFrameOutput, operational,
        record_gate::{SchemaPlan, screen},
    },
};
use l2_workbench::{
    job::{Job, MemoryBudget, MemoryClass, MemoryLease},
    protocol::{ByteRange, RecordSchema},
    recovery::RecoveryError,
};
use std::sync::Arc;

const MAX_SELECTORS: usize = 8;
const MAX_VALUES: usize = 4;
const MAX_SELECTOR_WIDTH: usize = 4;
const MAX_WITNESSES: usize = 2 + MAX_SELECTORS * MAX_VALUES * 2;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workbench::recovery_executor::relational) struct StructuralWitness {
    pub(in crate::workbench::recovery_executor::relational) schema: RecordSchema,
    pub(in crate::workbench::recovery_executor::relational) frame_indices: Arc<[usize]>,
    #[serde(default)]
    pub(in crate::workbench::recovery_executor::relational) family: bool,
    #[serde(skip)]
    capture_memory: Option<Arc<MemoryLease>>,
}

#[cfg_attr(test, derive(Clone))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workbench::recovery_executor::relational) struct FamilySelector {
    pub(in crate::workbench::recovery_executor::relational) range: ByteRange,
    pub(in crate::workbench::recovery_executor::relational) values: Vec<Vec<u8>>,
}

#[cfg_attr(test, derive(Clone))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workbench::recovery_executor::relational) struct StructuralEvidence {
    pub(in crate::workbench::recovery_executor::relational) witnesses: Vec<StructuralWitness>,
    pub(in crate::workbench::recovery_executor::relational) family_selectors: Vec<FamilySelector>,
    #[serde(skip)]
    capture_memory: Option<Arc<MemoryLease>>,
}

impl StructuralEvidence {
    pub(in crate::workbench::recovery_executor::relational) fn release_capture_admission(
        &mut self,
    ) {
        // The completed cohort admission now covers these same retained allocations
        self.capture_memory = None;
        for witness in &mut self.witnesses {
            witness.capture_memory = None;
        }
    }
}

pub(in crate::workbench::recovery_executor::relational) fn capture_witness(
    schema: &RecordSchema,
    indices: &[usize],
    memory: Option<&MemoryBudget>,
    maximum: usize,
) -> Result<Option<StructuralWitness>, RecoveryExecutionError> {
    let Some(memory) = memory else {
        return Ok(None);
    };
    let retained = indices
        .len()
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| {
            bytes.checked_add(size_of::<StructuralWitness>() + size_of::<RecordSchema>() + 64)
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if retained > maximum {
        return Ok(None);
    }
    // The temporary vector overlaps the immutable shared slice during construction
    let temporary = retained
        .checked_add(
            indices
                .len()
                .checked_mul(size_of::<usize>())
                .ok_or(RecoveryError::InvalidCheckpoint)?,
        )
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let mut lease = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(temporary).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("structural witness admission failed", error))?;
    let mut frame_indices = Vec::new();
    frame_indices
        .try_reserve_exact(indices.len())
        .map_err(|error| operational("structural witness allocation failed", error))?;
    frame_indices.extend_from_slice(indices);
    let frame_indices: Arc<[usize]> = Arc::from(frame_indices);
    lease
        .try_resize(u64::try_from(retained).map_err(|_| RecoveryError::InvalidCheckpoint)?)
        .map_err(|error| operational("structural witness admission failed", error))?;
    Ok(Some(StructuralWitness {
        schema: schema.clone(),
        frame_indices,
        family: false,
        capture_memory: Some(Arc::new(lease)),
    }))
}

pub(in crate::workbench::recovery_executor::relational) fn capture_evidence(
    frames: &[DecodedFrameOutput],
    plan: &SchemaPlan,
    witnesses: &[StructuralWitness],
    job: Option<&Job>,
    memory: Option<&MemoryBudget>,
    maximum: usize,
) -> Result<Option<StructuralEvidence>, RecoveryExecutionError> {
    let Some(memory) = memory else {
        return Ok(None);
    };
    if witnesses.len() > MAX_WITNESSES {
        return Ok(None);
    }
    if witnesses.is_empty() {
        return Ok(None);
    }
    let has_family = witnesses.iter().any(|witness| witness.family);
    let wrapper_bytes = witnesses
        .len()
        .checked_mul(size_of::<StructuralWitness>())
        .and_then(|bytes| bytes.checked_add(size_of::<StructuralEvidence>() + 64))
        .and_then(|bytes| {
            bytes.checked_add(if has_family {
                MAX_SELECTORS
                    * (size_of::<FamilySelector>()
                        + MAX_VALUES * (size_of::<Vec<u8>>() + MAX_SELECTOR_WIDTH))
            } else {
                0
            })
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let total_bytes = witnesses
        .iter()
        .try_fold(wrapper_bytes, |total, witness| {
            witness
                .frame_indices
                .len()
                .checked_mul(size_of::<usize>())
                .and_then(|bytes| total.checked_add(bytes))
                .and_then(|bytes| bytes.checked_add(size_of::<RecordSchema>()))
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if total_bytes > maximum {
        return Ok(None);
    }
    let lease = memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(wrapper_bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("structural evidence admission failed", error))?;
    let has_uniform = witnesses
        .iter()
        .any(|witness| !witness.family && covers_all(witness, frames.len()));
    if !has_family {
        if witnesses
            .iter()
            .any(|witness| !covers_all(witness, frames.len()))
        {
            return Ok(None);
        }
        return Ok(Some(StructuralEvidence {
            witnesses: witnesses.to_vec(),
            family_selectors: Vec::new(),
            capture_memory: Some(Arc::new(lease)),
        }));
    }
    if !has_uniform && (plan.has_unassigned_family_messages || !plan.family_search_complete) {
        return Ok(None);
    }
    let Some(family_selectors) = capture_family_selectors(plan, frames, job)? else {
        return Ok(None);
    };
    let evidence = StructuralEvidence {
        witnesses: witnesses.to_vec(),
        family_selectors,
        capture_memory: Some(Arc::new(lease)),
    };
    if !family_coverage(&evidence, frames, job, !has_uniform)? {
        return Ok(None);
    }
    Ok(Some(evidence))
}

fn capture_family_selectors(
    plan: &SchemaPlan,
    frames: &[DecodedFrameOutput],
    job: Option<&Job>,
) -> Result<Option<Vec<FamilySelector>>, RecoveryExecutionError> {
    let Some(selectors) = plan
        .details
        .pointer("/family/family_analysis/selectors")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    if selectors.is_empty() || selectors.len() > MAX_SELECTORS {
        return Ok(None);
    }
    let mut family_selectors = Vec::new();
    family_selectors
        .try_reserve_exact(selectors.len())
        .map_err(|error| operational("family witness allocation failed", error))?;
    for selector in selectors {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let Some(start) = selector
            .pointer("/range/start")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return Ok(None);
        };
        let Some(end) = selector
            .pointer("/range/end")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
        else {
            return Ok(None);
        };
        let range = ByteRange { start, end };
        if !valid_range(range) {
            return Ok(None);
        }
        let Some(families) = selector
            .get("families")
            .and_then(serde_json::Value::as_array)
        else {
            return Ok(None);
        };
        if families.is_empty() || families.len() > MAX_VALUES {
            return Ok(None);
        }
        let Some(values) = capture_family_values(families, frames, range, job)? else {
            return Ok(None);
        };
        family_selectors.push(FamilySelector { range, values });
    }
    Ok(Some(family_selectors))
}

fn capture_family_values(
    families: &[serde_json::Value],
    frames: &[DecodedFrameOutput],
    range: ByteRange,
    job: Option<&Job>,
) -> Result<Option<Vec<Vec<u8>>>, RecoveryExecutionError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(families.len())
        .map_err(|error| operational("family value allocation failed", error))?;
    for family in families {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let Some(sample) = family
            .get("training_samples")
            .and_then(serde_json::Value::as_array)
            .and_then(|samples| samples.first())
            .and_then(serde_json::Value::as_u64)
        else {
            return Ok(None);
        };
        let mut found = None;
        for frame in frames {
            if let Some(job) = job {
                job.check_cancelled()?;
            }
            if frame.input_node_id == sample {
                found = Some(frame);
                break;
            }
        }
        let Some(frame) = found else {
            return Ok(None);
        };
        let Some(value) = frame.bytes.get(range.start..range.end) else {
            return Ok(None);
        };
        if values
            .iter()
            .any(|saved: &Vec<u8>| saved.as_slice() == value)
        {
            return Ok(None);
        }
        values.push(value.to_vec());
    }
    Ok(Some(values))
}

pub(in crate::workbench::recovery_executor::relational) fn verify(
    evidence: &StructuralEvidence,
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    if evidence.witnesses.is_empty()
        || evidence.witnesses.len() > MAX_WITNESSES
        || frames.is_empty()
        || evidence.family_selectors.len() > MAX_SELECTORS
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let checks = membership_work(evidence, frames, context)?;
    if !context.work.try_charge_verification(checks) {
        return Err(operational("structural membership work limit reached",
            l2_workbench::protocol::RelationalCursorError::<std::convert::Infallible>::RestoreWorkLimit));
    }
    for frame in frames {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let belongs = |session: &l2_workbench::protocol::RelationalSessionId| {
            session.source == frame.context.source
                && session.scope == frame.context.scope
                && session.session == frame.context.session
        };
        let discovery = context.report.discovery_sessions.iter().any(belongs);
        let heldout = context.report.heldout_sessions.iter().any(belongs);
        if discovery == heldout {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    if evidence.family_selectors.is_empty() {
        if evidence
            .witnesses
            .iter()
            .any(|witness| witness.family || !covers_all(witness, frames.len()))
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    } else {
        let has_uniform = evidence
            .witnesses
            .iter()
            .any(|witness| !witness.family && covers_all(witness, frames.len()));
        if evidence
            .family_selectors
            .iter()
            .any(|selector| selector.range.start > context.schema_limits.max_field_offset)
            || !family_coverage(evidence, frames, context.job, !has_uniform)?
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        verify_training_families(evidence, frames, context)?;
    }
    for witness in &evidence.witnesses {
        verify_witness(witness, frames, context)?;
    }
    Ok(())
}

pub(in crate::workbench::recovery_executor::relational) fn verify_witness(
    witness: &StructuralWitness,
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    if witness.frame_indices.is_empty() || witness.frame_indices.len() > frames.len() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let index_work = witness
        .frame_indices
        .len()
        .checked_mul(2 * size_of::<usize>())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if !context.work.try_charge_verification(index_work) {
        return Err(operational("structural index work limit reached",
            l2_workbench::protocol::RelationalCursorError::<std::convert::Infallible>::RestoreWorkLimit));
    }
    let mut previous = None;
    for index in witness.frame_indices.iter().copied() {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        if index >= frames.len() || previous.is_some_and(|prior| prior >= index) {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        previous = Some(index);
    }
    screen::verify_checkpoint_schema(witness, frames, context)
}

fn covers_all(witness: &StructuralWitness, length: usize) -> bool {
    witness.frame_indices.iter().copied().eq(0..length)
}

const fn valid_range(range: ByteRange) -> bool {
    range.start <= 15 && range.end > range.start && range.end - range.start <= MAX_SELECTOR_WIDTH
}

fn membership_work(
    evidence: &StructuralEvidence,
    frames: &[DecodedFrameOutput],
    context: &SchemaCacheRestoreContext<'_, '_>,
) -> Result<usize, RecoveryExecutionError> {
    let sessions = context
        .report
        .discovery_sessions
        .iter()
        .chain(&context.report.heldout_sessions);
    let mut session_count = 0_usize;
    let mut session_bytes = 0_usize;
    for session in sessions {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        session_count = session_count
            .checked_add(1)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        session_bytes = session_bytes
            .checked_add(session.source.len())
            .and_then(|bytes| bytes.checked_add(session.scope.len()))
            .and_then(|bytes| bytes.checked_add(size_of::<u64>()))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
    }
    let mut frame_bytes = 0_usize;
    for frame in frames {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        frame_bytes = frame_bytes
            .checked_add(frame.context.source.len())
            .and_then(|bytes| bytes.checked_add(frame.context.scope.len()))
            .and_then(|bytes| bytes.checked_add(size_of::<u64>()))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
    }
    let identities = frame_bytes
        .checked_mul(session_count)
        .and_then(|bytes| {
            session_bytes
                .checked_mul(frames.len())
                .and_then(|other| bytes.checked_add(other))
        })
        .and_then(|bytes| {
            evidence
                .family_selectors
                .len()
                .checked_mul(MAX_VALUES)
                .and_then(|count| count.checked_add(1))
                .and_then(|count| bytes.checked_mul(count))
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let family = frames
        .len()
        .checked_mul(evidence.family_selectors.len())
        .and_then(|count| count.checked_mul(MAX_VALUES))
        .and_then(|count| count.checked_mul(evidence.witnesses.len().checked_add(2)?))
        .and_then(|count| {
            count.checked_mul(MAX_SELECTOR_WIDTH + size_of::<usize>() + session_count)
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let indices = frames
        .len()
        .checked_mul(evidence.witnesses.len())
        .and_then(|count| count.checked_mul(2 * size_of::<usize>()))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    identities
        .checked_add(family)
        .and_then(|total| total.checked_add(indices))
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}

fn verify_training_families(
    evidence: &StructuralEvidence,
    frames: &[DecodedFrameOutput],
    context: &SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    for selector in &evidence.family_selectors {
        for value in &selector.values {
            let mut first = None;
            let mut independent = false;
            for frame in frames {
                if let Some(job) = context.job {
                    job.check_cancelled()?;
                }
                if frame.bytes.get(selector.range.start..selector.range.end)
                    != Some(value.as_slice())
                {
                    continue;
                }
                let is_discovery = context.report.discovery_sessions.iter().any(|session| {
                    session.source == frame.context.source
                        && session.scope == frame.context.scope
                        && session.session == frame.context.session
                });
                if !is_discovery {
                    continue;
                }
                let identity = (
                    &frame.context.source,
                    &frame.context.scope,
                    frame.context.session,
                );
                if first.is_some_and(|previous| previous != identity) {
                    independent = true;
                    break;
                }
                first = Some(identity);
            }
            if !independent {
                return Err(RecoveryError::InvalidCheckpoint.into());
            }
        }
    }
    Ok(())
}

fn family_coverage(
    evidence: &StructuralEvidence,
    frames: &[DecodedFrameOutput],
    job: Option<&Job>,
    require_coverage: bool,
) -> Result<bool, RecoveryExecutionError> {
    if evidence.family_selectors.is_empty() {
        return Ok(false);
    }
    for selector in &evidence.family_selectors {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        if !valid_range(selector.range)
            || selector.values.is_empty()
            || selector.values.len() > MAX_VALUES
            || selector
                .values
                .iter()
                .any(|value| value.len() != selector.range.end - selector.range.start)
            || selector.values.iter().enumerate().any(|(index, value)| {
                selector
                    .values
                    .iter()
                    .take(index)
                    .any(|prior| prior == value)
            })
        {
            return Ok(false);
        }
        if require_coverage {
            for frame in frames {
                if let Some(job) = job {
                    job.check_cancelled()?;
                }
                if frame
                    .bytes
                    .get(selector.range.start..selector.range.end)
                    .is_none_or(|value| !selector.values.iter().any(|saved| saved == value))
                {
                    return Ok(false);
                }
            }
        }
    }
    for witness in &evidence.witnesses {
        if !witness.family {
            if !covers_all(witness, frames.len()) {
                return Ok(false);
            }
            continue;
        }
        let mut matched = false;
        for selector in &evidence.family_selectors {
            for value in &selector.values {
                let mut expected = witness.frame_indices.iter();
                let mut equal = true;
                for (index, frame) in frames.iter().enumerate() {
                    if let Some(job) = job {
                        job.check_cancelled()?;
                    }
                    if frame.bytes.get(selector.range.start..selector.range.end)
                        == Some(value.as_slice())
                        && expected.next().copied() != Some(index)
                    {
                        equal = false;
                        break;
                    }
                }
                if equal && expected.next().is_none() {
                    matched = true;
                    break;
                }
            }
            if matched {
                break;
            }
        }
        if !matched {
            return Ok(false);
        }
    }
    Ok(true)
}
