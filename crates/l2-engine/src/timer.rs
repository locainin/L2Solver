//! Time-ordered timer storage

use crate::{MonoTime, TimerId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct TimerQueue {
    by_time: BTreeMap<MonoTime, BTreeSet<TimerId>>,
    length: usize,
}

impl TimerQueue {
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

    pub(super) fn insert(&mut self, deadline: MonoTime, timer: TimerId) {
        self.by_time.entry(deadline).or_default().insert(timer);
        self.length += 1;
    }

    pub(super) fn cancel(&mut self, timer: TimerId) -> bool {
        let Some(deadline) = self
            .by_time
            .iter()
            .find_map(|(deadline, timers)| timers.contains(&timer).then_some(*deadline))
        else {
            return false;
        };
        self.remove(deadline, timer)
    }

    pub(super) fn pop_at(&mut self, deadline: MonoTime) -> Option<TimerId> {
        let timer = self.by_time.get(&deadline)?.first().copied()?;
        self.remove(deadline, timer).then_some(timer)
    }

    pub(super) fn clear(&mut self) {
        self.by_time.clear();
        self.length = 0;
    }

    fn remove(&mut self, deadline: MonoTime, timer: TimerId) -> bool {
        let Some(timers) = self.by_time.get_mut(&deadline) else {
            return false;
        };
        if !timers.remove(&timer) {
            return false;
        }
        let empty = timers.is_empty();
        if empty {
            self.by_time.remove(&deadline);
        }
        self.length -= 1;
        true
    }
}
