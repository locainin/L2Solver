//! Shared admission for explicitly charged live memory

mod buffering;
mod system;

pub use buffering::{BufferedCase, BufferedCaseSnapshot};
pub use system::{CgroupMemoryEvents, CgroupMemorySnapshot, SystemMemorySnapshot};

use super::Job;
use serde::Serialize;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

// A timed wait lets a job cancellation stop admission without coupling job and budget locks
const CANCELLATION_POLL: Duration = Duration::from_millis(50);

/// Class of live allocations represented by a memory lease
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryClass {
    /// Shared capture, index, and other job-wide data
    Base,
    /// Retained Case records and graph indexes
    Case,
    /// Active candidate, frontier, and expansion data
    Executor,
    /// Live cache input, decoding, and output buffers
    Cache,
    /// Data retained while publishing artifacts or evidence
    Publication,
}

/// Failure to reserve or inspect a shared live-memory budget
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// The requested growth cannot fit within the shared limit
    Limit {
        /// Selected aggregate byte limit
        limit: u64,
        /// Bytes charged to all live leases
        used: u64,
        /// Additional bytes requested
        requested: u64,
    },
    /// The job was cancelled before admission
    Cancelled,
    /// Capacity was still unavailable when the caller's deadline arrived
    TimedOut {
        /// Selected aggregate byte limit
        limit: u64,
        /// Bytes charged to all live leases at the deadline
        used: u64,
        /// Bytes requested for the new lease
        requested: u64,
    },
    /// Another thread panicked while updating the budget
    StatePoisoned,
    /// Buffered-result telemetry cannot represent another observation
    ObservationOverflow,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit {
                limit,
                used,
                requested,
            } => write!(
                formatter,
                "memory limit {limit} bytes cannot admit {requested} bytes with {used} bytes already charged"
            ),
            Self::Cancelled => formatter.write_str("memory admission was cancelled"),
            Self::TimedOut {
                limit,
                used,
                requested,
            } => write!(
                formatter,
                "memory admission timed out requesting {requested} bytes with {used} of {limit} bytes charged"
            ),
            Self::StatePoisoned => formatter.write_str("memory admission state was poisoned"),
            Self::ObservationOverflow => formatter.write_str("buffered Case observation overflow"),
        }
    }
}

impl Error for MemoryError {}

/// Atomic snapshot of explicitly charged live bytes
///
/// This reports the caller's charges, not allocator overhead or process RSS
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MemorySnapshot {
    /// Selected aggregate byte limit
    pub limit_bytes: u64,
    /// Bytes charged to all live leases
    pub used_bytes: u64,
    /// Largest aggregate live charge since the budget was created
    pub peak_bytes: u64,
    /// Number of requests immediately rejected by the limit
    pub rejected: u64,
    /// Number of fresh reservations currently waiting for capacity
    pub waiting: usize,
    /// Number of fresh reservations that reached their deadline
    pub timed_out: u64,
    /// Completed Cases waiting for ordered collection, already included in live charges
    pub buffered_cases: BufferedCaseSnapshot,
    /// Latest independently observed process and cgroup usage
    pub system: Option<SystemMemorySnapshot>,
    /// Age of the latest OS observation, which can be used to reject stale pressure data
    pub system_sample_age_ms: Option<u64>,
    /// Failed OS observations during this invocation
    pub system_observation_failures: u64,
    by_class: ClassCharges,
}

impl MemorySnapshot {
    /// Return the current live charge for one allocation class
    #[must_use]
    pub const fn used(&self, class: MemoryClass) -> u64 {
        *self.by_class.get(class)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
struct ClassCharges {
    base: u64,
    case: u64,
    executor: u64,
    cache: u64,
    publication: u64,
}

impl ClassCharges {
    const fn get(&self, class: MemoryClass) -> &u64 {
        match class {
            MemoryClass::Base => &self.base,
            MemoryClass::Case => &self.case,
            MemoryClass::Executor => &self.executor,
            MemoryClass::Cache => &self.cache,
            MemoryClass::Publication => &self.publication,
        }
    }

    const fn get_mut(&mut self, class: MemoryClass) -> &mut u64 {
        match class {
            MemoryClass::Base => &mut self.base,
            MemoryClass::Case => &mut self.case,
            MemoryClass::Executor => &mut self.executor,
            MemoryClass::Cache => &mut self.cache,
            MemoryClass::Publication => &mut self.publication,
        }
    }
}

#[derive(Debug)]
struct State {
    used: u64,
    peak: u64,
    rejected: u64,
    waiting: usize,
    timed_out: u64,
    by_class: ClassCharges,
    buffered_cases: BufferedCaseSnapshot,
    system_memory: Option<(SystemMemorySnapshot, Instant)>,
    system_observation_failures: u64,
}

#[derive(Debug)]
struct Shared {
    limit: u64,
    state: Mutex<State>,
    released: Condvar,
}

/// Cloneable admission budget shared by workers in one job
///
/// Callers must reserve a conservative charge before allocating and retain the lease for the
/// lifetime of the represented data. The budget accounts only for allocations callers charge
#[derive(Clone, Debug)]
pub struct MemoryBudget {
    shared: Arc<Shared>,
}

impl MemoryBudget {
    /// Create a budget with the supplied maximum live charge
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            shared: Arc::new(Shared {
                limit,
                state: Mutex::new(State {
                    used: 0,
                    peak: 0,
                    rejected: 0,
                    waiting: 0,
                    timed_out: 0,
                    by_class: ClassCharges::default(),
                    buffered_cases: BufferedCaseSnapshot::default(),
                    system_memory: None,
                    system_observation_failures: 0,
                }),
                released: Condvar::new(),
            }),
        }
    }

    /// Try to reserve a new live charge without waiting for other workers
    ///
    /// # Errors
    /// Returns a limit error when the request cannot fit or a poisoned-state error
    pub fn try_reserve(&self, class: MemoryClass, bytes: u64) -> Result<MemoryLease, MemoryError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        charge(&self.shared, &mut state, class, bytes)?;
        Ok(MemoryLease {
            budget: self.clone(),
            class,
            bytes,
        })
    }

    /// Wait for a fresh reservation until a deadline while checking cancellation
    ///
    /// Call only while holding no other leases: waiting while retaining a charge can deadlock
    /// Requests larger than the entire budget fail immediately
    ///
    /// # Errors
    /// Returns a limit, cancellation, timeout, or poisoned-state error
    pub fn wait_reserve(
        &self,
        class: MemoryClass,
        bytes: u64,
        job: Option<&Job>,
        deadline: Instant,
    ) -> Result<MemoryLease, MemoryError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        loop {
            if job.is_some_and(Job::is_cancelled) {
                return Err(MemoryError::Cancelled);
            }
            if bytes > self.shared.limit {
                state.rejected = state.rejected.saturating_add(1);
                return Err(MemoryError::Limit {
                    limit: self.shared.limit,
                    used: state.used,
                    requested: bytes,
                });
            }
            if bytes <= self.shared.limit - state.used {
                charge(&self.shared, &mut state, class, bytes)?;
                return Ok(MemoryLease {
                    budget: self.clone(),
                    class,
                    bytes,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.timed_out = state.timed_out.saturating_add(1);
                return Err(MemoryError::TimedOut {
                    limit: self.shared.limit,
                    used: state.used,
                    requested: bytes,
                });
            }
            // The predicate is checked again after wakeups, including spurious ones
            state.waiting += 1;
            state = self
                .shared
                .released
                .wait_timeout(state, remaining.min(CANCELLATION_POLL))
                .map_err(|_| MemoryError::StatePoisoned)?
                .0;
            state.waiting -= 1;
        }
    }

    /// Read all current charges and high-water telemetry under one lock
    ///
    /// # Errors
    /// Returns an error if another thread poisoned the budget state
    pub fn snapshot(&self) -> Result<MemorySnapshot, MemoryError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        Ok(MemorySnapshot {
            limit_bytes: self.shared.limit,
            used_bytes: state.used,
            peak_bytes: state.peak,
            rejected: state.rejected,
            waiting: state.waiting,
            timed_out: state.timed_out,
            by_class: state.by_class,
            buffered_cases: state.buffered_cases,
            system: state.system_memory.map(|(sample, _)| sample),
            system_sample_age_ms: state.system_memory.map(|(_, observed)| {
                u64::try_from(observed.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            system_observation_failures: state.system_observation_failures,
        })
    }
}

/// One live charge released when its owner is dropped
#[derive(Debug)]
pub struct MemoryLease {
    budget: MemoryBudget,
    class: MemoryClass,
    bytes: u64,
}

impl MemoryLease {
    pub(crate) fn try_duplicate(&self) -> Result<Self, MemoryError> {
        self.budget.try_reserve(self.class, self.bytes)
    }

    pub(crate) fn try_sibling(&self, bytes: u64) -> Result<Self, MemoryError> {
        self.budget.try_reserve(self.class, bytes)
    }

    pub(crate) fn absorb(&mut self, mut other: Self) {
        assert!(
            Arc::ptr_eq(&self.budget.shared, &other.budget.shared) && self.class == other.class,
            "memory charges must share one budget and class"
        );
        // Both charges are already included in the same bounded aggregate
        self.bytes += other.bytes;
        other.bytes = 0;
    }

    /// Return the bytes currently represented by this lease
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Resize the charge without waiting, retaining the previous charge on failure
    ///
    /// Reserve growth before allocating; release bytes only after the allocation is gone
    ///
    /// # Errors
    /// Returns a limit error when growth cannot fit or a poisoned-state error
    pub fn try_resize(&mut self, bytes: u64) -> Result<(), MemoryError> {
        let mut state = self
            .budget
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        if bytes > self.bytes {
            charge(
                &self.budget.shared,
                &mut state,
                self.class,
                bytes - self.bytes,
            )?;
        } else if bytes < self.bytes {
            release(&mut state, self.class, self.bytes - bytes);
            self.budget.shared.released.notify_all();
        }
        self.bytes = bytes;
        Ok(())
    }
}

impl Drop for MemoryLease {
    fn drop(&mut self) {
        // A poisoned budget is already unusable and must not trigger a second panic here
        if let Ok(mut state) = self.budget.shared.state.lock() {
            release(&mut state, self.class, self.bytes);
            self.budget.shared.released.notify_all();
        }
    }
}

fn charge(
    shared: &Shared,
    state: &mut State,
    class: MemoryClass,
    bytes: u64,
) -> Result<(), MemoryError> {
    if bytes > shared.limit - state.used {
        state.rejected = state.rejected.saturating_add(1);
        return Err(MemoryError::Limit {
            limit: shared.limit,
            used: state.used,
            requested: bytes,
        });
    }
    // Each class is a subset of the aggregate, so neither addition can overflow
    state.used += bytes;
    *state.by_class.get_mut(class) += bytes;
    state.peak = state.peak.max(state.used);
    Ok(())
}

const fn release(state: &mut State, class: MemoryClass, bytes: u64) {
    // A lease releases only bytes it previously charged to this same class
    state.used -= bytes;
    *state.by_class.get_mut(class) -= bytes;
}
