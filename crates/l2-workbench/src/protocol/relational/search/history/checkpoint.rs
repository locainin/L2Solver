//! Save rule identities while rebuilding randomized lookup hashes after restore

use super::{Entry, RelationalReplayHistory, ReplayDisposition, copy_rule};
use crate::protocol::RelationalTransformRule;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::mem;

const VERSION: u32 = 2;

#[derive(Serialize)]
struct SnapshotRef<'a> {
    version: u32,
    max_bytes: usize,
    entry_capacity: usize,
    sorted_len: usize,
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
    #[serde(default)]
    sorted_len: Option<usize>,
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
            sorted_len: self.sorted_len,
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
        // Published rules may be registered before a search, but rejections need replay limits
        let sorted_len = match (saved.version, saved.sorted_len) {
            (1, None) => saved.entries.len(),
            (VERSION, Some(length)) => length,
            _ => {
                return Err(serde::de::Error::custom(
                    "unsupported replay history checkpoint",
                ));
            }
        };
        if sorted_len > saved.entries.len()
            || saved.entry_capacity < saved.entries.len()
            || saved
                .limits
                .is_some_and(|(seed, total)| seed == 0 || total == 0)
            || (saved.limits.is_none()
                && saved
                    .entries
                    .iter()
                    .any(|(_, disposition)| *disposition == ReplayDisposition::Rejected))
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
        // Preserve which entries were visible to lookup when the search began
        history
            .entries
            .get_mut(..sorted_len)
            .ok_or_else(|| serde::de::Error::custom("invalid replay history prefix"))?
            .sort_unstable_by_key(|entry| entry.hash);
        history.sorted_len = sorted_len;
        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(history.entries.len())
            .map_err(serde::de::Error::custom)?;
        ordered.extend(history.entries.iter());
        ordered.sort_unstable_by_key(|entry| entry.hash);
        for group in ordered.chunk_by(|left, right| left.hash == right.hash) {
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
