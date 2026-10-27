//! Operation-wide reservation for source and manifest reads

use super::invalid_input;
use l2_workbench::job::{Counter, Job, cache::SourceFingerprint};
use std::{cell::Cell, error::Error};

pub(super) struct SourceReadBudget {
    maximum: u64,
    remaining: Cell<u64>,
}

impl SourceReadBudget {
    pub(super) const fn new(maximum: u64) -> Self {
        Self {
            maximum,
            remaining: Cell::new(maximum),
        }
    }

    pub(super) const fn maximum(&self) -> u64 {
        self.maximum
    }

    pub(super) const fn remaining(&self) -> u64 {
        self.remaining.get()
    }

    pub(super) fn charge(&self, bytes: u64, job: &Job) -> Result<(), Box<dyn Error>> {
        let remaining = self
            .remaining
            .get()
            .checked_sub(bytes)
            .ok_or_else(|| invalid_input("source read limit is exhausted"))?;
        self.remaining.set(remaining);
        job.increment(Counter::SourceReadBytes, bytes)?;
        Ok(())
    }
}

pub(super) fn analysis_reservation(length: u64) -> Option<u64> {
    // One full read and three fingerprints cover admission and both rechecks
    length
        .checked_add(1)?
        .checked_add(SourceFingerprint::sample_read_bytes(length).checked_mul(3)?)
}
