//! Bound retained findings before allocating their report text

use crate::{Finding, ResourceLimit, ResourceLimitStatus, planner::MAX_FINDINGS};

#[derive(Default)]
pub struct Findings {
    pub entries: Vec<Finding>,
    pub limits: ResourceLimitStatus,
}

impl Findings {
    pub(super) fn push(&mut self, make: impl FnOnce() -> Finding) {
        if self.entries.len() == MAX_FINDINGS {
            // A full list is complete until another supported violation is found
            self.limits.mark(ResourceLimit::Findings);
        } else {
            self.entries.push(make());
        }
    }
}
