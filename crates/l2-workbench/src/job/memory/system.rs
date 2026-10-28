//! OS observations kept separate from explicitly charged allocations

use super::{MemoryBudget, MemoryError};
use serde::Serialize;
use std::time::Instant;

/// Resident process memory and the containing Linux memory cgroup
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SystemMemorySnapshot {
    /// Current process resident pages reported by the kernel
    pub process_rss_bytes: u64,
    /// Largest process resident set observed by the kernel
    pub process_peak_rss_bytes: u64,
    /// Unified memory-controller observations, when that controller is available
    pub cgroup: Option<CgroupMemorySnapshot>,
}

/// Leaf usage, inherited limits, and remaining shared capacity in a cgroup hierarchy
///
/// Cgroup usage includes descendants and charged file pages; it is not process RSS
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CgroupMemorySnapshot {
    /// Memory charged to the leaf and its descendants
    pub current_bytes: u64,
    /// Leaf high-water usage since cgroup creation or a kernel counter reset
    pub peak_bytes: Option<u64>,
    /// Leaf anonymous-memory charge
    pub anonymous_bytes: Option<u64>,
    /// Leaf file-cache charge, including shared memory
    pub file_bytes: Option<u64>,
    /// Leaf aggregate kernel charge, excluding any double counting of its subfields
    pub kernel_bytes: Option<u64>,
    /// Shared-memory pages, also included in file bytes
    pub shared_bytes: Option<u64>,
    /// Dirty file pages, also included in file bytes
    pub dirty_file_bytes: Option<u64>,
    /// File pages under writeback, also included in file bytes
    pub writeback_file_bytes: Option<u64>,
    /// Inactive file pages, also included in file bytes
    pub inactive_file_bytes: Option<u64>,
    /// Smallest finite memory.max across the visible hierarchy
    pub effective_max_bytes: Option<u64>,
    /// Smallest finite memory.high across the visible hierarchy
    pub effective_high_bytes: Option<u64>,
    /// Smallest memory.max minus current usage at any finite ancestor limit
    pub max_headroom_bytes: Option<u64>,
    /// Smallest memory.high minus current usage at any finite ancestor limit
    pub high_headroom_bytes: Option<u64>,
    /// Cumulative leaf events, including descendant events under the kernel's mount policy
    pub events: CgroupMemoryEvents,
}

/// Memory-controller events reported by the kernel, without invented per-job attribution
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CgroupMemoryEvents {
    /// Charges throttled at memory.high
    pub high: u64,
    /// Attempts to exceed memory.max
    pub max: u64,
    /// Allocations that reached an out-of-memory condition
    pub oom: u64,
    /// Processes killed by a memory-cgroup OOM killer
    pub oom_kill: u64,
}

impl MemoryBudget {
    /// Replace the current invocation's OS observation without changing allocation charges
    ///
    /// A missing sample records a failed observation and clears stale pressure data
    ///
    /// # Errors
    /// Returns an error if the admission state was poisoned
    pub fn observe_system_memory(
        &self,
        sample: Option<SystemMemorySnapshot>,
    ) -> Result<(), MemoryError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        if sample.is_none() {
            state.system_observation_failures = state.system_observation_failures.saturating_add(1);
        }
        state.system_memory = sample.map(|sample| (sample, Instant::now()));
        drop(state);
        Ok(())
    }
}
