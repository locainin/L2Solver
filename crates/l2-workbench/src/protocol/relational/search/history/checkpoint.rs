//! Save rule identities while rebuilding randomized lookup hashes after restore

use super::{Entry, RelationalReplayHistory, ReplayDisposition, copy_rule};
use crate::protocol::RelationalTransformRule;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::mem;

const VERSION: u32 = 1;

#[derive(Serialize)]
struct SnapshotRef<'a> {
    version: u32,
    max_bytes: usize,
    entry_capacity: usize,
    entries: Entries<'a>,
    complete: bool,
    limits: Option<(usize, usize)>,
}

struct Entries<'a>(&'a [Entry]);
impl Serialize for Entries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut entries = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            entries.serialize_element(&(&entry.rule, entry.disposition))?;
        }
        entries.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    max_bytes: usize,
    entry_capacity: usize,
    entries: Vec<(RelationalTransformRule, ReplayDisposition)>,
    complete: bool,
    limits: Option<(usize, usize)>,
}

impl Serialize for RelationalReplayHistory {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SnapshotRef {
            version: VERSION,
            max_bytes: self.max_bytes,
            entry_capacity: self.entries.capacity(),
            entries: Entries(&self.entries),
            complete: self.complete,
            limits: self.limits,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelationalReplayHistory {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let saved = Snapshot::deserialize(deserializer)?;
        if saved.version != VERSION
            || saved.entry_capacity < saved.entries.len()
            || saved
                .entry_capacity
                .checked_mul(mem::size_of::<Entry>())
                .is_none_or(|bytes| bytes > saved.max_bytes)
        {
            return Err(serde::de::Error::custom(
                "invalid replay history checkpoint",
            ));
        }
        let mut history = Self::new(saved.max_bytes);
        history
            .entries
            .try_reserve_exact(saved.entry_capacity)
            .map_err(serde::de::Error::custom)?;
        history.complete = saved.complete;
        history.limits = saved.limits;
        for (rule, disposition) in saved.entries {
            let rule = copy_rule(&rule)
                .ok_or_else(|| serde::de::Error::custom("replay history allocation failed"))?;
            let hash = history.rule_hash(&rule);
            history.marker_bytes = history
                .marker_bytes
                .checked_add(rule.seed_locator.marker.capacity())
                .and_then(|bytes| bytes.checked_add(rule.payload_locator.marker.capacity()))
                .ok_or_else(|| serde::de::Error::custom("replay history size overflow"))?;
            history.entries.push(Entry {
                hash,
                rule,
                disposition,
            });
            if history.storage_bytes() > history.max_bytes {
                return Err(serde::de::Error::custom(
                    "replay history exceeds its storage limit",
                ));
            }
        }
        // Hash seeds belong to the new process, so stored bucket values are never reused
        history.finish();
        for group in history
            .entries
            .chunk_by(|left, right| left.hash == right.hash)
        {
            for (index, entry) in group.iter().enumerate() {
                if group
                    .iter()
                    .take(index)
                    .any(|prior| prior.rule == entry.rule)
                {
                    return Err(serde::de::Error::custom("repeated replay history rule"));
                }
            }
        }
        Ok(history)
    }
}
