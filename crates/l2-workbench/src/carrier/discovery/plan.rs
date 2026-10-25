//! Validation, sample partitioning, ordering, and work estimates

use super::model::{
    DiscoveryError, DiscoveryIdentity, DiscoveryMapping, DiscoveryPlan, DiscoverySample, ResetMode,
    SampleOrder,
};
use crate::{
    carrier::Ambiguity,
    derivation::{self, BitRemainder, Constraint, ConstraintStatus, Recipe},
};
use std::collections::{BTreeSet, HashMap, HashSet};

pub(super) struct ValidatedPlan {
    pub(super) widths: Vec<u8>,
    pub(super) phases: Vec<u8>,
    pub(super) start_offsets: Vec<usize>,
    pub(super) reset_modes: Vec<ResetMode>,
    pub(super) sample_orders: Vec<SampleOrder>,
    pub(super) remainder: BitRemainder,
    pub(super) constraints: Vec<Constraint>,
    pub(super) max_input_bytes: usize,
    pub(super) max_work_bytes: usize,
    pub(super) max_candidates: usize,
    pub(super) minimum_printable_run_bytes: usize,
    pub(super) max_report_bytes: usize,
    pub(super) parameter_space_size: usize,
}

pub(super) struct WorkUnit {
    pub(super) sample_indexes: Vec<usize>,
    pub(super) input_length: usize,
}
pub(super) fn validate_plan(plan: &DiscoveryPlan) -> Result<ValidatedPlan, DiscoveryError> {
    validate_axes(plan)?;
    let mut widths = plan.widths.clone();
    let mut phases = plan.phases.clone();
    let mut start_offsets = plan.start_offsets.clone();
    let mut reset_modes = plan.reset_modes.clone();
    let mut sample_orders = plan.sample_orders.clone();
    widths.sort_unstable();
    phases.sort_unstable();
    start_offsets.sort_unstable();
    reset_modes.sort_unstable();
    sample_orders.sort_unstable();
    let parameter_space_size = widths
        .len()
        .checked_mul(phases.len())
        .and_then(|count| count.checked_mul(start_offsets.len()))
        .and_then(|count| count.checked_mul(reset_modes.len()))
        .and_then(|count| count.checked_mul(sample_orders.len()))
        .ok_or(DiscoveryError::InvalidPlan(
            "parameter space size overflowed",
        ))?;
    validate_constraints(&plan.constraints)?;
    Ok(ValidatedPlan {
        widths,
        phases,
        start_offsets,
        reset_modes,
        sample_orders,
        remainder: plan.remainder,
        constraints: plan.constraints.clone(),
        max_input_bytes: plan.max_input_bytes,
        max_work_bytes: plan.max_work_bytes,
        max_candidates: plan.max_candidates,
        minimum_printable_run_bytes: plan.minimum_printable_run_bytes,
        max_report_bytes: plan.max_report_bytes,
        parameter_space_size,
    })
}

fn validate_axes(plan: &DiscoveryPlan) -> Result<(), DiscoveryError> {
    if plan.widths.is_empty()
        || plan.phases.is_empty()
        || plan.start_offsets.is_empty()
        || plan.reset_modes.is_empty()
        || plan.sample_orders.is_empty()
        || plan.max_input_bytes == 0
        || plan.max_work_bytes == 0
        || plan.max_candidates == 0
        || plan.minimum_printable_run_bytes == 0
        || plan.max_report_bytes == 0
        || plan.widths.iter().any(|width| !(1..=8).contains(width))
        || plan.phases.iter().any(|phase| *phase > 7)
        || plan
            .start_offsets
            .iter()
            .any(|offset| *offset >= plan.max_input_bytes || offset.checked_mul(8).is_none())
        || plan.constraints.len() > derivation::MAX_CONSTRAINTS
    {
        return Err(DiscoveryError::InvalidPlan(
            "an axis is empty or contains an unsupported value",
        ));
    }
    if has_duplicates(&plan.widths)
        || has_duplicates(&plan.phases)
        || has_duplicates(&plan.start_offsets)
        || has_duplicates(&plan.reset_modes)
        || has_duplicates(&plan.sample_orders)
    {
        return Err(DiscoveryError::InvalidPlan(
            "hypothesis values must be distinct",
        ));
    }
    Ok(())
}
fn validate_constraints(constraints: &[Constraint]) -> Result<(), DiscoveryError> {
    let baseline = derivation::run(
        &[],
        &Recipe {
            steps: Vec::new(),
            constraints: constraints.to_vec(),
        },
    )?;
    if baseline
        .constraints
        .iter()
        .zip(constraints)
        .any(|(result, request)| {
            matches!(result.status, ConstraintStatus::Invalid { .. })
                && !matches!(request, Constraint::Crc32 { .. })
        })
        || constraints.iter().any(|constraint| match constraint {
            Constraint::Crc32 {
                data_offset,
                data_length,
                checksum_offset,
                ..
            } => !valid_crc_ranges(*data_offset, *data_length, *checksum_offset),
            _ => false,
        })
    {
        return Err(DiscoveryError::InvalidPlan(
            "one or more validation checks are invalid",
        ));
    }
    Ok(())
}

const fn valid_crc_ranges(data_offset: usize, data_length: usize, checksum_offset: usize) -> bool {
    let Some(data_end) = data_offset.checked_add(data_length) else {
        return false;
    };
    let Some(checksum_end) = checksum_offset.checked_add(4) else {
        return false;
    };
    data_offset >= checksum_end || checksum_offset >= data_end
}

pub(super) fn validate_samples(
    samples: &[DiscoverySample<'_>],
    max_input_bytes: usize,
    cohort_identity: Option<&super::model::DiscoveryIdentity>,
) -> Result<(DiscoveryIdentity, usize), DiscoveryError> {
    if samples.is_empty() {
        return Err(DiscoveryError::InvalidSelection);
    }
    let mut ids = HashSet::new();
    ids.try_reserve(samples.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let mut total_bytes = 0_usize;
    let first = samples.first().ok_or(DiscoveryError::InvalidSelection)?;
    let identity = cohort_identity
        .cloned()
        .unwrap_or_else(|| DiscoveryIdentity {
            source_scope: first.source_scope.clone(),
            direction: first.direction.clone(),
            local_identity: first.local_identity.clone(),
        });
    if !valid_identity(&identity) {
        return Err(DiscoveryError::MixedIdentity);
    }
    if identity.source_scope != first.source_scope {
        return Err(DiscoveryError::MixedIdentity);
    }
    for sample in samples {
        if sample.id == 0 || sample.session_id == 0 || !ids.insert(sample.id) {
            return Err(DiscoveryError::InvalidSelection);
        }
        if !valid_identity_parts(
            &sample.source_scope,
            &sample.direction,
            &sample.local_identity,
        ) || sample.source_scope != identity.source_scope
            || (cohort_identity.is_none()
                && (sample.direction != identity.direction
                    || sample.local_identity != identity.local_identity))
        {
            return Err(DiscoveryError::MixedIdentity);
        }
        if sample.ambiguity != Ambiguity::None {
            return Err(DiscoveryError::AmbiguousSample {
                sample_id: sample.id,
            });
        }
        if sample.bytes.is_empty() {
            return Err(DiscoveryError::InvalidMapping {
                sample_id: sample.id,
            });
        }
        total_bytes = total_bytes
            .checked_add(sample.bytes.len())
            .ok_or(DiscoveryError::InvalidSelection)?;
        if total_bytes > max_input_bytes {
            return Err(DiscoveryError::InputBudgetExceeded {
                observed: total_bytes,
                limit: max_input_bytes,
            });
        }
        validate_mappings(sample.id, sample.bytes.len(), &sample.mappings)?;
    }
    Ok((identity, total_bytes))
}

fn valid_identity(identity: &DiscoveryIdentity) -> bool {
    valid_identity_parts(
        &identity.source_scope,
        &identity.direction,
        &identity.local_identity,
    )
}

fn valid_identity_parts(source_scope: &str, direction: &str, local_identity: &str) -> bool {
    [source_scope, direction, local_identity]
        .into_iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= crate::evidence::MAX_NODE_DETAILS_BYTES
                && !value.chars().any(char::is_control)
        })
}

pub(super) fn validate_mappings(
    sample_id: u64,
    byte_length: usize,
    mappings: &[DiscoveryMapping],
) -> Result<(), DiscoveryError> {
    if mappings.is_empty() {
        return Err(DiscoveryError::InvalidMapping { sample_id });
    }
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(mappings.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    ordered.extend(mappings.iter());
    ordered.sort_unstable_by_key(|mapping| mapping.offset);
    let mut cursor = 0_usize;
    for mapping in ordered {
        let range_length = usize::try_from(mapping.range.length)
            .map_err(|_| DiscoveryError::InvalidMapping { sample_id })?;
        mapping
            .range
            .offset
            .checked_add(mapping.range.length)
            .ok_or(DiscoveryError::InvalidMapping { sample_id })?;
        if mapping.offset != cursor
            || range_length == 0
            || !mapping
                .range
                .source
                .strip_prefix("sha256:")
                .is_some_and(crate::hashing::is_sha256_digest)
        {
            return Err(DiscoveryError::InvalidMapping { sample_id });
        }
        cursor = cursor
            .checked_add(range_length)
            .ok_or(DiscoveryError::InvalidMapping { sample_id })?;
    }
    if cursor != byte_length {
        return Err(DiscoveryError::InvalidMapping { sample_id });
    }
    Ok(())
}

pub(super) struct Partitions {
    pub(super) discovery: Vec<usize>,
    pub(super) control: Vec<usize>,
}

pub(super) fn partition_samples(samples: &[DiscoverySample<'_>]) -> Partitions {
    let mut indexes: Vec<_> = (0..samples.len()).collect();
    indexes.sort_unstable_by_key(|index| {
        samples
            .get(*index)
            .map(|sample| (sample.sequence, sample.id))
    });
    if indexes.len() == 1 {
        return Partitions {
            discovery: indexes,
            control: Vec::new(),
        };
    }
    let mut sessions: Vec<_> = indexes
        .iter()
        .filter_map(|index| samples.get(*index).map(|sample| sample.session_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if sessions.len() > 1 {
        let discovery_sessions = sessions.len().div_ceil(2);
        sessions.truncate(discovery_sessions);
        let selected: HashSet<_> = sessions.into_iter().collect();
        let (discovery, control): (Vec<_>, Vec<_>) = indexes.into_iter().partition(|index| {
            samples
                .get(*index)
                .is_some_and(|sample| selected.contains(&sample.session_id))
        });
        Partitions { discovery, control }
    } else {
        let discovery_count = indexes.len().div_ceil(2);
        let control = indexes.split_off(discovery_count);
        Partitions {
            discovery: indexes,
            control,
        }
    }
}

pub(super) fn make_units(
    samples: &[DiscoverySample<'_>],
    indexes: &[usize],
    reset_mode: ResetMode,
    order: SampleOrder,
) -> Result<Vec<WorkUnit>, DiscoveryError> {
    let mut ordered = indexes.to_vec();
    ordered.sort_unstable_by(|left, right| {
        if order == SampleOrder::InputOrder {
            return left.cmp(right);
        }
        let left_key = samples
            .get(*left)
            .map(|sample| (sample.sequence, sample.id));
        let right_key = samples
            .get(*right)
            .map(|sample| (sample.sequence, sample.id));
        match order {
            SampleOrder::InputOrder => left.cmp(right),
            SampleOrder::SequenceAscending => left_key.cmp(&right_key),
            SampleOrder::SequenceDescending => left_key
                .zip(right_key)
                .map_or(std::cmp::Ordering::Equal, |(left, right)| {
                    right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
                }),
        }
    });
    let groups: Vec<Vec<usize>> = match reset_mode {
        ResetMode::PerSample => ordered.into_iter().map(|index| vec![index]).collect(),
        ResetMode::PerSession => {
            let mut units: Vec<(u64, Vec<usize>)> = Vec::new();
            let mut positions: HashMap<u64, usize> = HashMap::new();
            for index in ordered {
                let Some(sample) = samples.get(index) else {
                    continue;
                };
                if let Some(position) = positions.get(&sample.session_id).copied() {
                    if let Some((_, members)) = units.get_mut(position) {
                        members.push(index);
                    }
                } else {
                    positions.insert(sample.session_id, units.len());
                    units.push((sample.session_id, vec![index]));
                }
            }
            units.into_iter().map(|(_, members)| members).collect()
        }
        ResetMode::Continuous => vec![ordered],
    };
    groups
        .into_iter()
        .map(|sample_indexes| {
            let input_length = sample_indexes.iter().try_fold(0_usize, |total, index| {
                let sample = samples
                    .get(*index)
                    .ok_or(DiscoveryError::InvalidSelection)?;
                total
                    .checked_add(sample.bytes.len())
                    .ok_or(DiscoveryError::InvalidSelection)
            })?;
            Ok(WorkUnit {
                sample_indexes,
                input_length,
            })
        })
        .collect()
}

pub(super) fn units_work(
    units: &[WorkUnit],
    width: u8,
    start_offset: usize,
    remainder: BitRemainder,
    constraint_count: usize,
) -> Result<usize, DiscoveryError> {
    units.iter().try_fold(0_usize, |total, unit| {
        let selected_bits = unit.input_length.saturating_sub(start_offset);
        let group_width = usize::from(width);
        let full_groups = selected_bits / group_width;
        let has_remainder = !selected_bits.is_multiple_of(group_width);
        let output_length = match (remainder, has_remainder) {
            (BitRemainder::Reject, true) => 0,
            (BitRemainder::Drop | BitRemainder::Reject, false) | (BitRemainder::Drop, true) => {
                full_groups
            }
            (BitRemainder::ZeroFill | BitRemainder::OneFill, true) => full_groups + 1,
            (BitRemainder::ZeroFill | BitRemainder::OneFill, false) => full_groups,
        };
        // Charge the transform and one full output pass per declared check, plus summary hashing
        let output_passes = constraint_count
            .checked_add(2)
            .ok_or(DiscoveryError::InvalidPlan("work estimate overflowed"))?;
        let output_work = output_length
            .checked_mul(output_passes)
            .ok_or(DiscoveryError::InvalidPlan("work estimate overflowed"))?;
        total
            .checked_add(unit.input_length)
            .and_then(|next| next.checked_add(output_work))
            .ok_or(DiscoveryError::InvalidPlan("work estimate overflowed"))
    })
}

fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        values
            .get(..index)
            .is_some_and(|prior| prior.contains(value))
    })
}
