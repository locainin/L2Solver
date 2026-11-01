mod checkpoint;

use super::super::model::{
    RelationalByteRangeLocator, RelationalLengthField, RelationalOperationTemplate,
    RelationalSha256CounterXor, RelationalTransformLimits, RelationalTransformRule,
};
use sha2::{Digest, Sha256};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hash, Hasher},
    mem,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) enum ReplayDisposition {
    Rejected,
    Published,
}

#[derive(Debug)]
struct Entry {
    hash: u64,
    rule: RelationalTransformRule,
    disposition: ReplayDisposition,
}

/// Bounded exact replay results shared by searches of one immutable cohort
///
/// A history belongs to one exact set of input bytes, sample identities, metadata, order, and
/// discovery/held-out partition. Callers must use a separate history whenever any of those change.
/// Storage is limited by `max_bytes`, counting the entry array capacity and marker allocations.
/// Fixed struct size and allocator metadata are outside this heap-storage allowance.
/// Rejections are added by the search; successful rules are added only after publication.
#[derive(Debug)]
pub struct RelationalReplayHistory {
    max_bytes: usize,
    entries: Vec<Entry>,
    sorted_len: usize,
    marker_bytes: usize,
    complete: bool,
    limits: Option<(usize, usize)>,
    hash_builder: RandomState,
}

impl RelationalReplayHistory {
    /// Set the maximum heap storage retained for exact rule identities
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            entries: Vec::new(),
            sorted_len: 0,
            marker_bytes: 0,
            complete: true,
            limits: None,
            hash_builder: RandomState::new(),
        }
    }

    /// Register a rule only after its complete result was successfully published
    ///
    /// Returns false if bounded storage or allocation prevents recording this rule. The caller
    /// must ensure that the published rule belongs to this history's immutable cohort.
    pub fn register_published_rule(&mut self, rule: &RelationalTransformRule) -> bool {
        let hash = self.rule_hash(rule);
        // Search the sorted prefix before examining any identities added since the last search
        let index = self.sorted_index(hash, rule).or_else(|| {
            self.entries
                .get(self.sorted_len..)?
                .iter()
                .position(|entry| entry.hash == hash && entry.rule == *rule)
                .and_then(|index| self.sorted_len.checked_add(index))
        });
        if let Some(entry) = index.and_then(|index| self.entries.get_mut(index)) {
            entry.disposition = ReplayDisposition::Published;
            return true;
        }
        self.insert(rule, hash, ReplayDisposition::Published)
    }

    /// Whether every requested rejection and publication identity fit in the history
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Allocated entry and marker bytes charged against this history's bound
    #[must_use]
    pub const fn storage_bytes(&self) -> usize {
        self.entries.capacity() * mem::size_of::<Entry>() + self.marker_bytes
    }

    /// Maximum heap storage allowed for this history's exact rule identities
    #[must_use]
    pub const fn maximum_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Adjust the heap-storage ceiling without discarding previously recorded identities
    ///
    /// Returns false and leaves the ceiling unchanged if existing storage exceeds the new limit.
    /// Raising the ceiling does not restore completeness after a previously declined identity.
    pub const fn set_max_bytes(&mut self, max_bytes: usize) -> bool {
        if max_bytes < self.storage_bytes() {
            return false;
        }
        self.max_bytes = max_bytes;
        true
    }

    pub(super) fn prepare(&mut self, limits: RelationalTransformLimits) {
        let current = (limits.max_seed_bytes, limits.max_total_bytes);
        if self
            .limits
            .is_some_and(|previous| current.0 < previous.0 || current.1 < previous.1)
        {
            // A tighter replay bound cannot inherit earlier evidence
            self.entries = Vec::new();
            self.sorted_len = 0;
            self.marker_bytes = 0;
            self.complete = false;
        }
        self.limits = Some(current);
        self.finish();
    }

    pub(super) fn lookup(&self, rule: &RelationalTransformRule) -> Option<ReplayDisposition> {
        let hash = self.rule_hash(rule);
        self.entries
            .get(self.sorted_index(hash, rule)?)
            .map(|entry| entry.disposition)
    }

    pub(super) fn finish(&mut self) {
        self.entries.sort_unstable_by_key(|entry| entry.hash);
        self.sorted_len = self.entries.len();
    }

    // Ignore randomized hash buckets while binding the lookup prefix and capacity
    pub(super) fn checkpoint_scratch_bytes(&self) -> Option<u64> {
        self.entries
            .len()
            .checked_mul(size_of::<[u8; 32]>())
            .and_then(|bytes| u64::try_from(bytes).ok())
    }

    pub(super) fn checkpoint_identity(
        &self,
        job: Option<&crate::job::Job>,
    ) -> Result<[u8; 32], super::super::model::RelationalTransformError> {
        use super::super::model::RelationalTransformError;
        use std::io::{self, Write};

        struct DigestWriter(Sha256);
        impl Write for DigestWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| RelationalTransformError::AllocationFailed)?;
        for (index, entry) in self.entries.iter().enumerate() {
            if index.is_multiple_of(256)
                && let Some(job) = job
            {
                job.check_cancelled()?;
            }
            let mut writer = DigestWriter(Sha256::new());
            serde_json::to_writer(&mut writer, &entry.rule).map_err(|_| {
                RelationalTransformError::InvalidPlan("history identity encoding failed")
            })?;
            writer.0.update([u8::from(index < self.sorted_len)]);
            writer.0.update([match entry.disposition {
                ReplayDisposition::Rejected => 0,
                ReplayDisposition::Published => 1,
            }]);
            entries.push(<[u8; 32]>::from(writer.0.finalize()));
        }
        entries.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(b"l2-relational-history-v1");
        for value in [self.max_bytes, self.entries.capacity(), self.sorted_len] {
            digest.update(value.to_le_bytes());
        }
        digest.update([u8::from(self.complete)]);
        if let Some((seed, total)) = self.limits {
            digest.update([1]);
            digest.update(seed.to_le_bytes());
            digest.update(total.to_le_bytes());
        } else {
            digest.update([0]);
        }
        for entry in entries {
            digest.update(entry);
        }
        Ok(digest.finalize().into())
    }

    fn sorted_index(&self, hash: u64, rule: &RelationalTransformRule) -> Option<usize> {
        let sorted = self.entries.get(..self.sorted_len)?;
        let start = sorted.partition_point(|entry| entry.hash < hash);
        sorted
            .get(start..)?
            .iter()
            .take_while(|entry| entry.hash == hash)
            .position(|entry| entry.rule == *rule)
            .and_then(|offset| start.checked_add(offset))
    }

    pub(super) fn record_rejection(&mut self, rule: &RelationalTransformRule) -> bool {
        let hash = self.rule_hash(rule);
        self.insert(rule, hash, ReplayDisposition::Rejected)
    }

    fn rule_hash(&self, rule: &RelationalTransformRule) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        let RelationalTransformRule {
            seed_locator,
            payload_locator,
            operation,
            counter_reset,
            parser_scope,
            parser_format,
        } = rule;
        hash_locator(seed_locator, &mut hasher);
        hash_locator(payload_locator, &mut hasher);
        mem::discriminant(operation).hash(&mut hasher);
        let RelationalOperationTemplate::Sha256CounterXor(parameters) = operation;
        let RelationalSha256CounterXor {
            initial_counter,
            counter_width,
            counter_byte_order,
            seed_order,
        } = parameters;
        initial_counter.hash(&mut hasher);
        mem::discriminant(counter_width).hash(&mut hasher);
        mem::discriminant(counter_byte_order).hash(&mut hasher);
        mem::discriminant(seed_order).hash(&mut hasher);
        mem::discriminant(counter_reset).hash(&mut hasher);
        mem::discriminant(parser_scope).hash(&mut hasher);
        mem::discriminant(parser_format).hash(&mut hasher);
        hasher.finish()
    }

    fn insert(
        &mut self,
        rule: &RelationalTransformRule,
        hash: u64,
        disposition: ReplayDisposition,
    ) -> bool {
        let marker_lengths = rule
            .seed_locator
            .marker
            .len()
            .checked_add(rule.payload_locator.marker.len());
        let Some(marker_lengths) =
            marker_lengths.and_then(|size| self.marker_bytes.checked_add(size))
        else {
            self.complete = false;
            return false;
        };
        let available_slots =
            self.max_bytes.saturating_sub(marker_lengths) / mem::size_of::<Entry>();
        if marker_lengths > self.max_bytes
            || self.entries.capacity() > available_slots
            || self.entries.len() >= available_slots
        {
            self.complete = false;
            return false;
        }
        if self.entries.len() == self.entries.capacity() {
            // Keep enough of the remaining budget for markers of newly reserved entries
            let marker_per_entry = marker_lengths - self.marker_bytes;
            let per_entry = mem::size_of::<Entry>().saturating_add(marker_per_entry);
            let future_entries = self.max_bytes.saturating_sub(self.storage_bytes()) / per_entry;
            let marker_aware_slots = self.entries.len().saturating_add(future_entries);
            let target = self
                .entries
                .capacity()
                .saturating_mul(2)
                .max(4)
                .min(available_slots)
                .min(marker_aware_slots);
            if self
                .entries
                .try_reserve_exact(target - self.entries.len())
                .is_err()
            {
                self.complete = false;
                return false;
            }
            // Some allocators can return a larger capacity than requested
            if self.entries.capacity() > available_slots {
                self.entries = Vec::new();
                self.sorted_len = 0;
                self.marker_bytes = 0;
                self.complete = false;
                return false;
            }
        }
        let Some(rule) = copy_rule(rule) else {
            self.complete = false;
            return false;
        };
        let Some(marker_bytes) = self
            .marker_bytes
            .checked_add(rule.seed_locator.marker.capacity())
            .and_then(|bytes| bytes.checked_add(rule.payload_locator.marker.capacity()))
        else {
            self.complete = false;
            return false;
        };
        if self
            .entries
            .capacity()
            .saturating_mul(mem::size_of::<Entry>())
            .saturating_add(marker_bytes)
            > self.max_bytes
        {
            self.complete = false;
            return false;
        }
        self.marker_bytes = marker_bytes;
        self.entries.push(Entry {
            hash,
            rule,
            disposition,
        });
        true
    }
}

fn hash_locator(locator: &RelationalByteRangeLocator, hasher: &mut impl Hasher) {
    let RelationalByteRangeLocator {
        coordinate_basis,
        direction,
        marker_offset,
        marker,
        value_offset,
        value_length,
        declared_length,
    } = locator;
    mem::discriminant(coordinate_basis).hash(hasher);
    mem::discriminant(direction).hash(hasher);
    marker_offset.hash(hasher);
    marker.hash(hasher);
    value_offset.hash(hasher);
    value_length.hash(hasher);
    mem::discriminant(declared_length).hash(hasher);
    if let Some(RelationalLengthField {
        offset,
        width,
        byte_order,
    }) = declared_length
    {
        offset.hash(hasher);
        mem::discriminant(width).hash(hasher);
        mem::discriminant(byte_order).hash(hasher);
    }
}

fn copy_rule(rule: &RelationalTransformRule) -> Option<RelationalTransformRule> {
    Some(RelationalTransformRule {
        seed_locator: copy_locator(&rule.seed_locator)?,
        payload_locator: copy_locator(&rule.payload_locator)?,
        operation: rule.operation,
        counter_reset: rule.counter_reset,
        parser_scope: rule.parser_scope,
        parser_format: rule.parser_format,
    })
}

fn copy_locator(locator: &RelationalByteRangeLocator) -> Option<RelationalByteRangeLocator> {
    let mut marker = Vec::new();
    marker.try_reserve_exact(locator.marker.len()).ok()?;
    marker.extend_from_slice(&locator.marker);
    Some(RelationalByteRangeLocator {
        coordinate_basis: locator.coordinate_basis,
        direction: locator.direction,
        marker_offset: locator.marker_offset,
        marker,
        value_offset: locator.value_offset,
        value_length: locator.value_length,
        declared_length: locator.declared_length,
    })
}
