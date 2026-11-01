//! Bound optional diagnostic details in one durable work snapshot

use super::{Counter, Phase, WorkSnapshot};
use crate::job::recovery_transition::checkpoint::{MAX_DIAGNOSTIC_BYTES, encoded_fits};
use serde::{Serialize, Serializer};
use std::collections::BTreeMap;

pub(super) struct View<'a> {
    snapshot: &'a WorkSnapshot,
    mode: Mode,
}

#[derive(Clone, Copy)]
enum Mode {
    Full,
    Compact,
    Omitted,
}

impl<'a> View<'a> {
    pub(super) fn new(snapshot: &'a WorkSnapshot, maximum: usize) -> Self {
        let maximum = maximum.min(MAX_DIAGNOSTIC_BYTES);
        let summary = &snapshot.counts.recovery_transitions;
        // Freeze the choice before the outer checkpoint counts and writes its metadata
        let mode = if encoded_fits(summary, maximum) {
            Mode::Full
        } else if encoded_fits(&summary.checkpoint_view(true), maximum) {
            Mode::Compact
        } else {
            Mode::Omitted
        };
        Self { snapshot, mode }
    }
}

#[derive(Serialize)]
struct WorkRef<'a, T> {
    schema_version: u32,
    scope_id: &'a str,
    counts: CountsRef<'a, T>,
}

#[derive(Serialize)]
struct CountsRef<'a, T> {
    counters: &'a BTreeMap<Counter, u64>,
    phase_work: &'a BTreeMap<Phase, u64>,
    recovery_transitions: T,
}

impl Serialize for View<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let summary = &self.snapshot.counts.recovery_transitions;
        if matches!(self.mode, Mode::Full) {
            return self.snapshot.serialize(serializer);
        }
        let work = WorkRef {
            schema_version: self.snapshot.schema_version,
            scope_id: &self.snapshot.scope_id,
            counts: CountsRef {
                counters: &self.snapshot.counts.counters,
                phase_work: &self.snapshot.counts.phase_work,
                recovery_transitions: summary.checkpoint_view(matches!(self.mode, Mode::Compact)),
            },
        };
        work.serialize(serializer)
    }
}
