//! Bound replay histories to one exact cohort and its ordered source records

use super::{
    HistorySampleIdentity, RelationalCohortKey, RelationalDiscoveryContext, RelationalLane,
    history_input_matches, history_input_signature,
};
use l2_workbench::protocol::RelationalReplayHistory;

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_relational/history.rs"]
mod tests;

#[derive(Default, serde::Serialize)]
pub(super) struct RelationalReplayHistories {
    slots: Vec<HistorySlot>,
}

impl<'de> serde::Deserialize<'de> for RelationalReplayHistories {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            slots: Box<[HistorySlot]>,
        }
        let saved = Saved::deserialize(deserializer)?;
        // Restoring JSON must not add spare slots that consume the saved search allowance
        Ok(Self {
            slots: saved.slots.into_vec(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HistorySlot {
    key: RelationalCohortKey,
    signature: Box<[HistorySampleIdentity]>,
    history: RelationalReplayHistory,
}

impl RelationalReplayHistories {
    pub(super) fn take_for_context(
        &mut self,
        context: &RelationalDiscoveryContext,
        maximum_slots: usize,
        total_bytes: usize,
    ) -> Option<RelationalReplayHistory> {
        self.for_context(context, maximum_slots, total_bytes)
            .map(|history| std::mem::replace(history, RelationalReplayHistory::new(0)))
    }

    pub(super) fn take_restored_context(
        &mut self,
        context: &RelationalDiscoveryContext,
        total_bytes: usize,
        history: RelationalReplayHistory,
    ) -> Result<RelationalReplayHistory, l2_workbench::recovery::RecoveryError> {
        let slot = self
            .resume_context(context, total_bytes)
            .ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?;
        if slot.maximum_bytes() != 0 || slot.storage_bytes() != 0 {
            return Err(l2_workbench::recovery::RecoveryError::InvalidCheckpoint);
        }
        *slot = history;
        let slot = self
            .resume_context(context, total_bytes)
            .ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?;
        Ok(std::mem::replace(slot, RelationalReplayHistory::new(0)))
    }

    pub(super) fn return_context(
        &mut self,
        context: &RelationalDiscoveryContext,
        history: RelationalReplayHistory,
    ) -> Result<(), l2_workbench::recovery::RecoveryError> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| {
                slot.key == context.key
                    && history_input_matches(&context.key, &context.samples, &slot.signature)
            })
            .ok_or(l2_workbench::recovery::RecoveryError::InvalidCheckpoint)?;
        if slot.history.maximum_bytes() != 0 || slot.history.storage_bytes() != 0 {
            return Err(l2_workbench::recovery::RecoveryError::InvalidCheckpoint);
        }
        slot.history = history;
        Ok(())
    }

    pub(super) fn for_context(
        &mut self,
        context: &RelationalDiscoveryContext,
        maximum_slots: usize,
        total_bytes: usize,
    ) -> Option<&mut RelationalReplayHistory> {
        let index = self.slots.iter().position(|slot| slot.key == context.key);
        if context.lane == RelationalLane::Incremental {
            let index = index?;
            let slot = self.slots.get(index)?;
            if !history_input_matches(&context.key, &context.samples, &slot.signature) {
                return None;
            }
            return self.limit_slot(index, total_bytes);
        }
        // A new normal snapshot replaces earlier results for the same cohort
        if let Some(index) = index {
            self.slots.swap_remove(index);
        }
        if self.slots.len() >= maximum_slots {
            return None;
        }
        let next_slot_bytes = std::mem::size_of::<HistorySlot>().checked_mul(2)?;
        let used = self.retained_bytes()?;
        if self.slots.len() == self.slots.capacity()
            && used.checked_add(next_slot_bytes)? > total_bytes
        {
            return None;
        }
        self.slots.try_reserve_exact(1).ok()?;
        let used = self.retained_bytes()?;
        let key_bytes = context
            .key
            .source_id
            .len()
            .checked_add(context.key.scope_json.len())?
            .checked_add(context.key.endpoints_json.len())?
            .checked_add(context.key.framing_rule_json.len())?
            .checked_add(context.key.schema_json.len())?;
        // Leave space for owned key buffers and allocator bookkeeping
        let overhead = std::mem::size_of::<HistorySlot>().checked_add(key_bytes.checked_mul(2)?)?;
        let signature_limit = total_bytes.checked_sub(used)?.checked_sub(overhead)?;
        let signature = history_input_signature(&context.key, &context.samples, signature_limit)?;
        let slot = HistorySlot {
            key: context.key.clone(),
            signature: signature.into_boxed_slice(),
            history: RelationalReplayHistory::new(0),
        };
        let index = self.slots.len();
        self.slots.push(slot);
        if self.retained_bytes().is_none_or(|used| used > total_bytes) {
            self.slots.pop();
            return None;
        }
        self.limit_slot(index, total_bytes)
    }

    pub(super) fn published_history(
        &mut self,
        context: &RelationalDiscoveryContext,
        total_bytes: usize,
    ) -> Option<&mut RelationalReplayHistory> {
        let index = self.slots.iter().position(|slot| slot.key == context.key)?;
        let slot = self.slots.get(index)?;
        if !history_input_matches(&context.key, &context.samples, &slot.signature) {
            return None;
        }
        self.limit_slot(index, total_bytes)
    }

    pub(super) fn resume_context(
        &mut self,
        context: &RelationalDiscoveryContext,
        total_bytes: usize,
    ) -> Option<&mut RelationalReplayHistory> {
        let index = self.slots.iter().position(|slot| slot.key == context.key)?;
        let slot = self.slots.get(index)?;
        if !history_input_matches(&context.key, &context.samples, &slot.signature) {
            return None;
        }
        let current = slot.history.storage_bytes();
        let other = self
            .retained_bytes()?
            .checked_sub(current.checked_add(current / 4)?)?;
        let maximum = slot.history.maximum_bytes();
        let reserved = maximum.checked_add(maximum / 4)?;
        if other.checked_add(reserved)? > total_bytes {
            return None;
        }
        // Keep the saved ceiling: changing it changes later replay-history omissions
        Some(&mut self.slots.get_mut(index)?.history)
    }

    pub(super) fn discard_context(&mut self, context: &RelationalDiscoveryContext) {
        if let Some(index) = self.slots.iter().position(|slot| {
            if slot.key != context.key {
                return false;
            }
            history_input_matches(&context.key, &context.samples, &slot.signature)
        }) {
            self.slots.swap_remove(index);
        }
    }

    fn limit_slot(
        &mut self,
        index: usize,
        total_bytes: usize,
    ) -> Option<&mut RelationalReplayHistory> {
        let available = total_bytes.checked_sub(self.retained_bytes()?)?;
        let history = &mut self.slots.get_mut(index)?.history;
        // A quarter of retained heap storage covers small-allocation overhead
        let extra = available.checked_div(5)?.checked_mul(4)?;
        let limit = history.storage_bytes().checked_add(extra)?;
        history.set_max_bytes(limit).then_some(history)
    }

    fn retained_bytes(&self) -> Option<usize> {
        let slots = self
            .slots
            .capacity()
            .checked_mul(std::mem::size_of::<HistorySlot>())?
            .checked_mul(2)?;
        self.slots.iter().try_fold(slots, |total, slot| {
            let keys = slot
                .key
                .source_id
                .capacity()
                .checked_add(slot.key.scope_json.capacity())?
                .checked_add(slot.key.endpoints_json.capacity())?
                .checked_add(slot.key.framing_rule_json.capacity())?
                .checked_add(slot.key.schema_json.capacity())?
                .checked_mul(2)?;
            let signature = slot
                .signature
                .len()
                .checked_mul(std::mem::size_of::<HistorySampleIdentity>())?;
            let history = slot.history.storage_bytes();
            total
                .checked_add(keys)?
                .checked_add(signature)?
                .checked_add(signature / 4)?
                .checked_add(history)?
                .checked_add(history / 4)
        })
    }
}
