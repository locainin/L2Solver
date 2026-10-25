use super::{HoldoutBasis, MessageSample, ProtocolError, ProtocolLimits};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SessionKey {
    source: String,
    scope: String,
    session: u64,
}

/// Sample indices and split provenance shared by all protocol analyses
pub(super) struct SampleSplit {
    pub discovery: Vec<usize>,
    pub holdout: Vec<usize>,
    pub basis: HoldoutBasis,
}

/// Read a checked field slice without overflowing its end offset
pub(super) fn field(bytes: &[u8], offset: usize, width: usize) -> Option<&[u8]> {
    let end = offset.checked_add(width)?;
    bytes.get(offset..end)
}

/// Resolve selected sample indices in order and fail when any index is out of bounds
pub(super) fn sample_refs<'a, 'b>(
    samples: &'a [MessageSample<'b>],
    indices: &[usize],
) -> Result<Vec<&'a MessageSample<'b>>, ProtocolError> {
    indices
        .iter()
        .map(|index| {
            samples
                .get(*index)
                .ok_or(ProtocolError::InsufficientSamples {
                    count: samples.len(),
                })
        })
        .collect()
}

/// Validate positive operator-selected protocol budgets
pub(super) const fn validate_limits(limits: ProtocolLimits) -> Result<(), ProtocolError> {
    if limits.max_samples == 0
        || limits.max_message_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_run_bytes == 0
        || limits.max_candidates == 0
        || limits.max_retained_frames == 0
        || limits.max_report_bytes == 0
    {
        return Err(ProtocolError::InvalidLimits);
    }
    Ok(())
}

/// Check sample IDs, context completeness, and configured byte/count budgets
pub(super) fn validate_samples(
    samples: &[MessageSample<'_>],
    minimum: usize,
    limits: ProtocolLimits,
) -> Result<bool, ProtocolError> {
    validate_limits(limits)?;
    if samples.len() < minimum {
        return Err(ProtocolError::InsufficientSamples {
            count: samples.len(),
        });
    }
    if samples.len() > limits.max_samples {
        return Err(ProtocolError::TooManySamples {
            count: samples.len(),
            maximum: limits.max_samples,
        });
    }

    let mut ids = std::collections::BTreeSet::new();
    let mut total = 0_usize;
    let has_context = samples.iter().any(|sample| sample.context.is_some());
    for sample in samples {
        if sample.sample == 0 || !ids.insert(sample.sample) {
            return Err(ProtocolError::InvalidSampleId {
                sample: sample.sample,
            });
        }
        if sample.bytes.len() > limits.max_message_bytes {
            return Err(ProtocolError::MessageTooLarge {
                sample: sample.sample,
                length: sample.bytes.len(),
                maximum: limits.max_message_bytes,
            });
        }
        total = total
            .checked_add(sample.bytes.len())
            .ok_or(ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: limits.max_total_bytes,
            })?;
        if total > limits.max_total_bytes {
            return Err(ProtocolError::TotalBytesTooLarge {
                total,
                maximum: limits.max_total_bytes,
            });
        }
        if has_context {
            let Some(context) = sample.context.as_ref() else {
                return Err(ProtocolError::IncompleteContext {
                    sample: sample.sample,
                });
            };
            if context.source.is_empty() || context.scope.is_empty() || context.session == 0 {
                return Err(ProtocolError::InvalidContext {
                    sample: sample.sample,
                });
            }
        }
    }
    Ok(has_context)
}

/// Split complete context groups together and retain caller order inside each side
pub(super) fn split_indices(
    samples: &[MessageSample<'_>],
    contextual: bool,
) -> Result<SampleSplit, ProtocolError> {
    if !contextual {
        let split = samples.len() / 2;
        return Ok(SampleSplit {
            discovery: (0..split).collect(),
            holdout: (split..samples.len()).collect(),
            basis: HoldoutBasis::SampleOrder,
        });
    }

    let mut group_indexes = BTreeMap::<SessionKey, usize>::new();
    let mut groups = Vec::<Vec<usize>>::new();
    for (index, sample) in samples.iter().enumerate() {
        let context = sample
            .context
            .as_ref()
            .ok_or(ProtocolError::IncompleteContext {
                sample: sample.sample,
            })?;
        let key = SessionKey {
            source: context.source.clone(),
            scope: context.scope.clone(),
            session: context.session,
        };
        let group_index = match group_indexes.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let group_index = groups.len();
                groups.push(Vec::new());
                entry.insert(group_index);
                group_index
            }
        };
        groups
            .get_mut(group_index)
            .ok_or(ProtocolError::InvalidContext {
                sample: sample.sample,
            })?
            .push(index);
    }
    if groups.len() < 2 {
        return Err(ProtocolError::InsufficientSessionGroups {
            count: groups.len(),
        });
    }

    let discovery_group_end = groups.len() / 2;
    let mut discovery = Vec::new();
    let mut holdout = Vec::new();
    for (group_index, group) in groups.into_iter().enumerate() {
        let target = if group_index < discovery_group_end {
            &mut discovery
        } else {
            &mut holdout
        };
        target.extend(group);
    }
    discovery.sort_unstable();
    holdout.sort_unstable();
    Ok(SampleSplit {
        discovery,
        holdout,
        basis: HoldoutBasis::CompleteSessions,
    })
}

/// Regroup indices into complete sessions, or a single unscoped cohort
pub(super) fn groups_for_indices(
    samples: &[MessageSample<'_>],
    indices: &[usize],
    contextual: bool,
) -> Result<Vec<Vec<usize>>, ProtocolError> {
    if !contextual {
        return Ok(vec![indices.to_vec()]);
    }
    let mut positions = BTreeMap::<SessionKey, usize>::new();
    let mut groups = Vec::<Vec<usize>>::new();
    for index in indices {
        let sample = samples
            .get(*index)
            .ok_or(ProtocolError::InsufficientSamples {
                count: indices.len(),
            })?;
        let context = sample
            .context
            .as_ref()
            .ok_or(ProtocolError::IncompleteContext {
                sample: sample.sample,
            })?;
        let key = SessionKey {
            source: context.source.clone(),
            scope: context.scope.clone(),
            session: context.session,
        };
        let group_index = match positions.entry(key) {
            std::collections::btree_map::Entry::Occupied(entry) => *entry.get(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let group_index = groups.len();
                groups.push(Vec::new());
                entry.insert(group_index);
                group_index
            }
        };
        groups
            .get_mut(group_index)
            .ok_or(ProtocolError::InvalidContext {
                sample: sample.sample,
            })?
            .push(*index);
    }
    Ok(groups)
}
