//! OS observations kept separate from explicitly charged allocations

use super::{MemoryBudget, MemoryError};
use serde::Serialize;
use std::{io, sync::TryLockError, time::Instant};

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
    /// A missing sample records a failed observation and clears the current pressure view
    ///
    /// # Errors
    /// Returns an error if another observation is active or the admission state was poisoned
    pub fn observe_system_memory(
        &self,
        sample: Option<SystemMemorySnapshot>,
    ) -> Result<(), MemoryError> {
        self.try_observe_system_memory_with(|| {
            sample.ok_or_else(|| io::Error::other("system memory sample is missing"))
        })
    }

    /// Read and record an OS sample without waiting for another active observer
    ///
    /// Provider errors are recorded in the snapshot and clear its current sample. Sampling
    /// begins before the provider runs, so a slow read cannot appear newer than its start
    ///
    /// # Errors
    /// Returns an error if another observation is active or the admission state was poisoned
    pub fn try_observe_system_memory_with(
        &self,
        read: impl FnOnce() -> io::Result<SystemMemorySnapshot>,
    ) -> Result<(), MemoryError> {
        // Keep the read and its update together so an older result cannot overwrite a newer one
        let _observation = match self.shared.observation.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(MemoryError::SystemObservationBusy),
            Err(TryLockError::Poisoned(_)) => return Err(MemoryError::StatePoisoned),
        };
        let started = Instant::now();
        let observed = read();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        // Keep the last sample across errors so a lost cgroup cannot become an RSS-only success
        let last = state.system_observation.last_sample();
        let observed = match observed {
            Ok(sample)
                if last.is_some_and(|last| last.cgroup.is_some()) && sample.cgroup.is_none() =>
            {
                Err(MemoryError::SystemCgroupUnavailable)
            }
            Ok(sample) => Ok(sample),
            Err(error) => Err(MemoryError::SystemObservationUnavailable {
                kind: error.kind(),
                raw_os_error: error.raw_os_error(),
            }),
        };
        state.system_observation = match observed {
            Ok(sample) => ObservationState::Current { sample, started },
            Err(error) => {
                state.system_observation_failures =
                    state.system_observation_failures.saturating_add(1);
                ObservationState::Unavailable { last, error }
            }
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) enum ObservationState {
    #[default]
    Unobserved,
    Current {
        sample: SystemMemorySnapshot,
        started: Instant,
    },
    Unavailable {
        last: Option<SystemMemorySnapshot>,
        error: MemoryError,
    },
}

impl ObservationState {
    pub(super) const fn current(&self) -> Option<(SystemMemorySnapshot, Instant)> {
        match *self {
            Self::Current { sample, started } => Some((sample, started)),
            Self::Unobserved | Self::Unavailable { .. } => None,
        }
    }

    pub(super) const fn error(&self) -> Option<MemoryError> {
        match *self {
            Self::Unavailable { error, .. } => Some(error),
            Self::Unobserved | Self::Current { .. } => None,
        }
    }

    const fn last_sample(&self) -> Option<SystemMemorySnapshot> {
        match *self {
            Self::Current { sample, .. } => Some(sample),
            Self::Unavailable { last, .. } => last,
            Self::Unobserved => None,
        }
    }
}
