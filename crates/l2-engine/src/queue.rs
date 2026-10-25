//! Time-ordered bounded event storage

use crate::{Event, MonoTime};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug)]
pub struct EventQueue {
    by_time: BTreeMap<MonoTime, VecDeque<Event>>,
    length: usize,
}

impl EventQueue {
    pub(super) const fn new() -> Self {
        Self {
            by_time: BTreeMap::new(),
            length: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.length
    }

    pub(super) fn first_time(&self) -> Option<MonoTime> {
        self.by_time.keys().next().copied()
    }

    pub(super) fn push(&mut self, at: MonoTime, event: Event) {
        self.by_time.entry(at).or_default().push_back(event);
        self.length += 1;
    }

    pub(super) fn pop_at(&mut self, at: MonoTime) -> Option<Event> {
        let mut pending = self.by_time.remove(&at)?;
        let event = pending.pop_front()?;
        if !pending.is_empty() {
            self.by_time.insert(at, pending);
        }
        self.length -= 1;
        Some(event)
    }

    pub(super) fn clear(&mut self) {
        self.by_time.clear();
        self.length = 0;
    }
}
