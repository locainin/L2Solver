use super::super::model::{RelationalSha256CounterXor, RelationalTransformError};
use super::probe::PrefixProbeScore;
use crate::derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder};
use std::{collections::HashMap, mem::size_of};

#[cfg(test)]
#[path = "../../../../tests/protocol/relational/search/prefix_cache.rs"]
mod tests;

// Each identity belongs to one immutable ranking pass and describes its ordered training inputs
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct PrefixSelectionIdentity(pub(super) Vec<PrefixSessionSelection>);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PrefixSessionSelection {
    pub(super) session_index: usize,
    pub(super) seed_sample_index: usize,
    pub(super) seed_start: usize,
    pub(super) seed_end: usize,
    pub(super) payload_sample_index: usize,
    pub(super) payload_start: usize,
    pub(super) payload_end: usize,
    pub(super) prefix_end: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PrefixProbeScoreKey {
    selection_id: usize,
    initial_counter: u64,
    counter_width_bytes: u8,
    counter_byte_order: u8,
    seed_order: u8,
}

// The cache is optional and keeps only scores with complete training observations
pub(super) struct PrefixProbeCache {
    selection_ids: HashMap<PrefixSelectionIdentity, usize>,
    scores: HashMap<PrefixProbeScoreKey, PrefixProbeScore>,
    retained_bytes: usize,
    maximum_bytes: usize,
}

impl PrefixProbeCache {
    pub(super) fn new(maximum_bytes: usize) -> Self {
        Self {
            selection_ids: HashMap::new(),
            scores: HashMap::new(),
            retained_bytes: 0,
            maximum_bytes,
        }
    }

    pub(super) fn score_or_compute<F>(
        &mut self,
        selection: Option<PrefixSelectionIdentity>,
        operation: RelationalSha256CounterXor,
        compute: F,
    ) -> Result<(Option<PrefixProbeScore>, bool), RelationalTransformError>
    where
        F: FnOnce() -> Result<Option<PrefixProbeScore>, RelationalTransformError>,
    {
        let key = selection
            .and_then(|selection| self.intern_selection(selection))
            .map(|selection_id| score_key(selection_id, operation));
        if let Some(score) = key.and_then(|key| self.score(key)) {
            return Ok((Some(score), true));
        }
        // A missing entry or full cache always takes the ordinary scoring path
        let score = compute()?;
        if let (Some(key), Some(score)) = (key, score) {
            self.retain_score(key, score);
        }
        Ok((score, false))
    }

    fn intern_selection(&mut self, selection: PrefixSelectionIdentity) -> Option<usize> {
        if let Some(selection_id) = self.selection_ids.get(&selection) {
            return Some(*selection_id);
        }
        let selection_bytes = selection
            .0
            .capacity()
            .checked_mul(size_of::<PrefixSessionSelection>())?;
        let entry_bytes =
            map_entry_budget::<(PrefixSelectionIdentity, usize)>()?.checked_add(selection_bytes)?;
        let retained_bytes = self.retained_bytes.checked_add(entry_bytes)?;
        if retained_bytes > self.maximum_bytes || self.selection_ids.try_reserve(1).is_err() {
            return None;
        }
        let selection_id = self.selection_ids.len();
        self.selection_ids.insert(selection, selection_id);
        self.retained_bytes = retained_bytes;
        Some(selection_id)
    }

    fn score(&self, key: PrefixProbeScoreKey) -> Option<PrefixProbeScore> {
        self.scores.get(&key).copied()
    }

    fn retain_score(&mut self, key: PrefixProbeScoreKey, score: PrefixProbeScore) {
        // A short work allowance must not become a reusable negative result
        if !score.complete || self.scores.contains_key(&key) {
            return;
        }
        let Some(retained_bytes) = map_entry_budget::<(PrefixProbeScoreKey, PrefixProbeScore)>()
            .and_then(|bytes| self.retained_bytes.checked_add(bytes))
        else {
            return;
        };
        if retained_bytes > self.maximum_bytes || self.scores.try_reserve(1).is_err() {
            return;
        }
        self.scores.insert(key, score);
        self.retained_bytes = retained_bytes;
    }
}

const fn score_key(
    selection_id: usize,
    operation: RelationalSha256CounterXor,
) -> PrefixProbeScoreKey {
    PrefixProbeScoreKey {
        selection_id,
        initial_counter: operation.initial_counter,
        counter_width_bytes: match operation.counter_width {
            CounterWidth::OneByte => 1,
            CounterWidth::TwoBytes => 2,
            CounterWidth::FourBytes => 4,
            CounterWidth::EightBytes => 8,
        },
        counter_byte_order: match operation.counter_byte_order {
            CounterByteOrder::BigEndian => 0,
            CounterByteOrder::LittleEndian => 1,
        },
        seed_order: match operation.seed_order {
            SeedCounterOrder::SeedThenCounter => 0,
            SeedCounterOrder::CounterThenSeed => 1,
        },
    }
}

// Leave room for spare hash buckets and their control bytes as well as stored values
fn map_entry_budget<T>() -> Option<usize> {
    size_of::<T>().checked_add(1)?.checked_mul(4)
}
