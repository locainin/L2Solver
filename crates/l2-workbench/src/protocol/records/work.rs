//! One shared logical-byte meter for canonical record proposal and parsing
//!
//! Charges from failed attempts remain consumed so budget stops stay incomplete evidence

use super::RecordError;

/// A bounded counter for logical record-analysis work bytes
///
/// Work bytes account for data read by record-field checks, first-time input hashing, and
/// logical record metadata created by parsing. Allocator bookkeeping and time spent inside
/// external artifact parsers are accounted for by their own limits
#[derive(Debug, Eq, PartialEq)]
pub struct RecordWorkBudget {
    limit: usize,
    consumed: usize,
}

impl RecordWorkBudget {
    /// Create a budget that permits at most `limit` logical work bytes
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { limit, consumed: 0 }
    }

    /// Return the logical work bytes consumed so far
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Return the remaining logical work-byte allowance
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.limit - self.consumed
    }

    pub(super) const fn charge(&mut self, amount: usize) -> Result<(), RecordError> {
        let Some(next) = self.consumed.checked_add(amount) else {
            return Err(self.exhausted(amount));
        };
        if next > self.limit {
            return Err(self.exhausted(amount));
        }
        self.consumed = next;
        Ok(())
    }

    pub(super) const fn try_charge(&mut self, amount: usize) -> bool {
        self.charge(amount).is_ok()
    }

    const fn exhausted(&self, requested: usize) -> RecordError {
        RecordError::WorkLimitExceeded {
            limit: self.limit,
            consumed: self.consumed,
            requested,
        }
    }
}
