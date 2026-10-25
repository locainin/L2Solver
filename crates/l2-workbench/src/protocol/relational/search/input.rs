use super::super::model::{
    RelationalRecordSample, RelationalSessionId, RelationalTransformError,
    RelationalTransformLimits, RelationalTransformPlan, Selector,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct SessionGroup {
    pub(super) id: RelationalSessionId,
    pub(super) session_order: u64,
    pub(super) sample_indices: Vec<usize>,
}

pub(super) type SelectorIndex = BTreeMap<Selector, Vec<usize>>;

pub(super) fn group_sessions(
    samples: &[RelationalRecordSample<'_>],
    limits: RelationalTransformLimits,
) -> Result<Vec<SessionGroup>, RelationalTransformError> {
    if samples.is_empty() {
        return Err(RelationalTransformError::InvalidInput(
            "relational input must contain messages",
        ));
    }
    let mut grouped_samples = GroupedSamples::default();
    for (index, sample) in samples.iter().enumerate() {
        grouped_samples.add(index, sample, limits)?;
    }
    grouped_samples.into_groups(limits)
}

#[derive(Default)]
struct GroupedSamples {
    sample_ids: BTreeSet<u64>,
    session_indices: BTreeMap<RelationalSessionId, Vec<usize>>,
    session_orders: BTreeMap<RelationalSessionId, u64>,
    total_bytes: usize,
}

impl GroupedSamples {
    fn add(
        &mut self,
        index: usize,
        sample: &RelationalRecordSample<'_>,
        limits: RelationalTransformLimits,
    ) -> Result<(), RelationalTransformError> {
        self.validate_sample(sample, limits)?;
        self.add_sample_bytes(sample.bytes.len(), limits)?;
        self.add_to_session(index, sample, limits)
    }

    fn validate_sample(
        &mut self,
        sample: &RelationalRecordSample<'_>,
        limits: RelationalTransformLimits,
    ) -> Result<(), RelationalTransformError> {
        if sample.sample == 0 || !self.sample_ids.insert(sample.sample) {
            return Err(RelationalTransformError::InvalidInput(
                "relational sample identifiers must be unique and nonzero",
            ));
        }
        if sample.context.source.is_empty()
            || sample.context.scope.is_empty()
            || sample.context.session == 0
            || sample.session_order == 0
        {
            return Err(RelationalTransformError::InvalidInput(
                "relational message context must identify a source, scope, session, and capture order",
            ));
        }
        if sample.bytes.is_empty() {
            return Err(RelationalTransformError::InvalidInput(
                "relational messages must contain bytes",
            ));
        }
        if sample.bytes.len() > limits.max_record_bytes {
            return Err(RelationalTransformError::RecordTooLarge {
                sample: sample.sample,
                length: sample.bytes.len(),
                maximum: limits.max_record_bytes,
            });
        }
        Ok(())
    }

    fn add_sample_bytes(
        &mut self,
        sample_length: usize,
        limits: RelationalTransformLimits,
    ) -> Result<(), RelationalTransformError> {
        self.total_bytes = self.total_bytes.checked_add(sample_length).ok_or(
            RelationalTransformError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: limits.max_total_bytes,
            },
        )?;
        if self.total_bytes > limits.max_total_bytes {
            return Err(RelationalTransformError::TotalBytesTooLarge {
                total: self.total_bytes,
                maximum: limits.max_total_bytes,
            });
        }
        Ok(())
    }

    fn add_to_session(
        &mut self,
        index: usize,
        sample: &RelationalRecordSample<'_>,
        limits: RelationalTransformLimits,
    ) -> Result<(), RelationalTransformError> {
        let id = session_id(&sample.context);
        if let Some(existing_order) = self.session_orders.get(&id) {
            if *existing_order != sample.session_order {
                return Err(RelationalTransformError::InvalidInput(
                    "samples in one session must share a capture-order key",
                ));
            }
        } else {
            self.session_orders.insert(id.clone(), sample.session_order);
        }
        let indices = self.session_indices.entry(id).or_default();
        if indices.len() == limits.max_records_per_session {
            return Err(RelationalTransformError::TooManyRecords {
                session: sample.context.session,
                count: indices.len() + 1,
                maximum: limits.max_records_per_session,
            });
        }
        indices
            .try_reserve(1)
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        indices.push(index);
        Ok(())
    }

    fn into_groups(
        self,
        limits: RelationalTransformLimits,
    ) -> Result<Vec<SessionGroup>, RelationalTransformError> {
        if self.session_indices.len() > limits.max_sessions {
            return Err(RelationalTransformError::TooManySessions {
                count: self.session_indices.len(),
                maximum: limits.max_sessions,
            });
        }
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(self.session_indices.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        for (id, sample_indices) in self.session_indices {
            let session_order = self.session_orders.get(&id).copied().ok_or(
                RelationalTransformError::InvalidInput(
                    "relational session capture order is missing",
                ),
            )?;
            groups.push(SessionGroup {
                id,
                session_order,
                sample_indices,
            });
        }
        groups.sort_by(|left, right| {
            left.session_order
                .cmp(&right.session_order)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(groups)
    }
}

pub(super) fn validate_plan(
    plan: &RelationalTransformPlan,
) -> Result<(), RelationalTransformError> {
    let limits = plan.limits;
    if limits.max_cohorts == 0
        || limits.max_sessions == 0
        || limits.max_records_per_session == 0
        || limits.max_record_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_marker_bytes == 0
        || limits.max_seed_bytes == 0
        || limits.max_locator_candidates == 0
        || limits.max_candidates == 0
        || limits.max_retained_candidates == 0
        || limits.max_work_bytes == 0
    {
        return Err(RelationalTransformError::InvalidPlan(
            "relational discovery limits must be positive",
        ));
    }
    if plan.parser_formats.is_empty()
        || plan.counter_widths.is_empty()
        || plan.counter_byte_orders.is_empty()
        || plan.seed_orders.is_empty()
        || plan.initial_counters.is_empty()
        || plan.counter_resets.is_empty()
    {
        return Err(RelationalTransformError::InvalidPlan(
            "relational transform and parser domains must be nonempty",
        ));
    }
    if has_duplicates(&plan.parser_formats)
        || has_duplicates(&plan.counter_widths)
        || has_duplicates(&plan.counter_byte_orders)
        || has_duplicates(&plan.seed_orders)
        || has_duplicates(&plan.initial_counters)
        || has_duplicates(&plan.counter_resets)
    {
        return Err(RelationalTransformError::InvalidPlan(
            "relational search domains must not contain duplicate values",
        ));
    }
    if plan.initial_counters.iter().all(|counter| {
        plan.counter_widths
            .iter()
            .all(|width| *counter > width.maximum_counter())
    }) {
        return Err(RelationalTransformError::InvalidPlan(
            "no initial counter fits a selected counter width",
        ));
    }
    Ok(())
}

fn has_duplicates<T: Eq>(items: &[T]) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items
            .get(index + 1..)
            .is_some_and(|tail| tail.contains(item))
    })
}

fn session_id(context: &crate::protocol::MessageContext) -> RelationalSessionId {
    RelationalSessionId {
        source: context.source.clone(),
        scope: context.scope.clone(),
        session: context.session,
    }
}

pub(super) fn build_selector_indexes(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    limits: RelationalTransformLimits,
) -> Result<Vec<SelectorIndex>, RelationalTransformError> {
    let mut indexes = Vec::new();
    indexes
        .try_reserve_exact(groups.len())
        .map_err(|_| RelationalTransformError::AllocationFailed)?;
    for group in groups {
        let mut index = SelectorIndex::new();
        for sample_index in &group.sample_indices {
            let sample =
                samples
                    .get(*sample_index)
                    .ok_or(RelationalTransformError::InvalidInput(
                        "relational session index is invalid",
                    ))?;
            let last_offset = limits.max_marker_offset.min(sample.bytes.len() - 1);
            for marker_offset in 0..=last_offset {
                for marker_length in 1..=limits.max_marker_bytes {
                    let Some(marker_end) = marker_offset.checked_add(marker_length) else {
                        break;
                    };
                    let Some(marker) = sample.bytes.get(marker_offset..marker_end) else {
                        break;
                    };
                    let selector = Selector {
                        direction: sample.context.direction,
                        marker_offset,
                        marker: marker.to_vec(),
                    };
                    let matching = index.entry(selector).or_default();
                    matching
                        .try_reserve(1)
                        .map_err(|_| RelationalTransformError::AllocationFailed)?;
                    matching.push(*sample_index);
                }
            }
        }
        indexes.push(index);
    }
    Ok(indexes)
}

pub(super) fn shared_selectors(
    indexes: &[SelectorIndex],
) -> Result<Vec<Selector>, RelationalTransformError> {
    let Some(first) = indexes.first() else {
        return Ok(Vec::new());
    };
    let mut selectors = Vec::new();
    for selector in first
        .keys()
        .filter(|selector| indexes.iter().all(|index| index.contains_key(*selector)))
    {
        selectors
            .try_reserve(1)
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        selectors.push(selector.clone());
    }
    Ok(selectors)
}
