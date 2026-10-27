//! Shared admission for explicitly charged live memory

use super::Job;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

// A timed wait lets a job cancellation stop admission without coupling job and budget locks
const CANCELLATION_POLL: Duration = Duration::from_millis(50);
const CLASS_COUNT: usize = 5;

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

impl MemoryClass {
    const fn index(self) -> usize {
        match self {
            Self::Base => 0,
            Self::Case => 1,
            Self::Executor => 2,
            Self::Cache => 3,
            Self::Publication => 4,
        }
    }
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
    /// Another thread panicked while updating the budget
    StatePoisoned,
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
            Self::StatePoisoned => formatter.write_str("memory admission state was poisoned"),
        }
    }
}

impl Error for MemoryError {}

/// Atomic snapshot of explicitly charged live bytes
///
/// This reports the caller's charges, not allocator overhead or process RSS
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    by_class: [u64; CLASS_COUNT],
}

impl MemorySnapshot {
    /// Return the current live charge for one allocation class
    #[must_use]
    pub const fn used(&self, class: MemoryClass) -> u64 {
        self.by_class[class.index()]
    }
}

#[derive(Debug)]
struct State {
    used: u64,
    peak: u64,
    rejected: u64,
    waiting: usize,
    by_class: [u64; CLASS_COUNT],
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
                    by_class: [0; CLASS_COUNT],
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

    /// Wait for a fresh reservation while checking the optional job for cancellation
    ///
    /// Call only while holding no other leases: waiting while retaining a charge can deadlock
    /// Requests larger than the entire budget fail immediately
    ///
    /// # Errors
    /// Returns a limit, cancellation, or poisoned-state error
    pub fn wait_reserve(
        &self,
        class: MemoryClass,
        bytes: u64,
        job: Option<&Job>,
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
            // The predicate is checked again after wakeups, including spurious ones
            state.waiting += 1;
            state = self
                .shared
                .released
                .wait_timeout(state, CANCELLATION_POLL)
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
            by_class: state.by_class,
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
    state.by_class[class.index()] += bytes;
    state.peak = state.peak.max(state.used);
    Ok(())
}

fn release(state: &mut State, class: MemoryClass, bytes: u64) {
    // A lease releases only bytes it previously charged to this same class
    state.used -= bytes;
    state.by_class[class.index()] -= bytes;
}
