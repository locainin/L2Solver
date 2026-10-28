//! Keep admitted future growth and live allocation charges in one shared ledger

use super::{MemoryBudget, MemoryClass, MemoryError, MemoryLease, Shared, State, release};
use serde::Serialize;
use std::sync::Arc;

/// Admission measurements kept distinct from allocated bytes and kernel observations
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct WorkingSetSnapshot {
    /// Admitted Cases whose recovery worker has not released its reservation
    pub active_cases: usize,
    /// Largest simultaneous admitted Case count
    pub peak_active_cases: usize,
    /// Total successful Case admissions during this invocation
    pub admitted_cases: u64,
    /// Capacity held for future allocations, excluded from live `used_bytes`
    pub reserved_bytes: u64,
    /// Largest simultaneous future-capacity reservation
    pub peak_reserved_bytes: u64,
    /// Admission requests rejected by the aggregate limit
    pub admission_denials: u64,
}

#[derive(Debug)]
pub(super) struct ScopeState {
    maximum: u64,
    used: u64,
    reserved: u64,
    active: bool,
}

#[derive(Debug)]
pub(super) struct Scope {
    shared: Arc<Shared>,
    id: u64,
    metadata_bytes: u64,
}

/// Future growth reserved for one worker; returned bytes retain their own live charges
///
/// Dropping this guard releases unused capacity even if a completed Case remains queued
/// Leases made with its budget keep their allocation charges until their data is dropped
#[derive(Debug)]
pub struct MemoryWorkingSet {
    budget: MemoryBudget,
}

impl MemoryWorkingSet {
    /// Return the budget that turns this worker's future credit into live charges
    #[must_use]
    pub const fn budget(&self) -> &MemoryBudget {
        &self.budget
    }
}

impl MemoryBudget {
    /// Reserve expected additional growth before starting a Case worker
    ///
    /// Existing Case allocations can move into this scope without a second global charge
    /// The reservation is an admission allowance, not a measurement of allocated bytes
    ///
    /// # Errors
    /// Returns an error for a nested scope, exhausted capacity, overflow, or poisoned state
    pub fn try_working_set(&self, additional_bytes: u64) -> Result<MemoryWorkingSet, MemoryError> {
        if self.scope.is_some() {
            return Err(MemoryError::NestedWorkingSet);
        }
        // Charge a full map node per scope to cover spare slots and split allocations
        let metadata_bytes = crate::allocation::btree_node_bytes::<u64, ScopeState>()
            .and_then(|bytes| bytes.checked_add(size_of::<Scope>() + 2 * size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(MemoryError::ObservationOverflow)?;
        let requested = additional_bytes
            .checked_add(metadata_bytes)
            .ok_or(MemoryError::ObservationOverflow)?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        let committed = state.used + state.working_sets.reserved_bytes;
        if requested > self.shared.limit - committed {
            state.rejected = state.rejected.saturating_add(1);
            state.working_sets.admission_denials =
                state.working_sets.admission_denials.saturating_add(1);
            return Err(MemoryError::Limit {
                limit: self.shared.limit,
                used: committed,
                requested,
            });
        }
        let id = state.next_scope;
        let next = id.checked_add(1).ok_or(MemoryError::ObservationOverflow)?;
        let admitted = state
            .working_sets
            .admitted_cases
            .checked_add(1)
            .ok_or(MemoryError::ObservationOverflow)?;
        state.scopes.insert(
            id,
            ScopeState {
                maximum: additional_bytes,
                used: 0,
                reserved: additional_bytes,
                active: true,
            },
        );
        state.next_scope = next;
        state.used += metadata_bytes;
        *state.by_class.get_mut(MemoryClass::Executor) += metadata_bytes;
        state.peak = state.peak.max(state.used);
        state.working_sets.reserved_bytes += additional_bytes;
        state.working_sets.peak_reserved_bytes = state
            .working_sets
            .peak_reserved_bytes
            .max(state.working_sets.reserved_bytes);
        state.working_sets.admitted_cases = admitted;
        state.working_sets.active_cases += 1;
        state.working_sets.peak_active_cases = state
            .working_sets
            .peak_active_cases
            .max(state.working_sets.active_cases);
        drop(state);
        Ok(MemoryWorkingSet {
            budget: Self {
                shared: Arc::clone(&self.shared),
                scope: Some(Arc::new(Scope {
                    shared: Arc::clone(&self.shared),
                    id,
                    metadata_bytes,
                })),
            },
        })
    }

    pub(crate) fn root(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            scope: None,
        }
    }

    pub(super) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
            && match (&self.scope, &other.scope) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }
}

pub(super) fn committed_for(budget: &MemoryBudget, state: &State) -> Result<u64, MemoryError> {
    let owned = match &budget.scope {
        Some(scope) => {
            state
                .scopes
                .get(&scope.id)
                .ok_or(MemoryError::IncompatibleWorkingSet)?
                .reserved
        }
        None => 0,
    };
    Ok(state.used + state.working_sets.reserved_bytes - owned)
}

pub(super) fn charge_scope(
    budget: &MemoryBudget,
    state: &mut State,
    bytes: u64,
) -> Result<(), MemoryError> {
    if let Some(scope) = &budget.scope {
        let scope = state
            .scopes
            .get_mut(&scope.id)
            .ok_or(MemoryError::IncompatibleWorkingSet)?;
        let credit = bytes.min(scope.reserved);
        scope.used += bytes;
        scope.reserved -= credit;
        state.working_sets.reserved_bytes -= credit;
    }
    Ok(())
}

pub(super) fn release_scope(budget: &MemoryBudget, state: &mut State, bytes: u64) {
    if let Some(scope) = &budget.scope
        && let Some(scope) = state.scopes.get_mut(&scope.id)
    {
        scope.used -= bytes;
        let reserved = if scope.active {
            scope.maximum.saturating_sub(scope.used)
        } else {
            0
        };
        state.working_sets.reserved_bytes += reserved - scope.reserved;
        scope.reserved = reserved;
        state.working_sets.peak_reserved_bytes = state
            .working_sets
            .peak_reserved_bytes
            .max(state.working_sets.reserved_bytes);
    }
}

impl Drop for MemoryWorkingSet {
    fn drop(&mut self) {
        if let Some(scope) = &self.budget.scope
            && let Ok(mut state) = scope.shared.state.lock()
            && let Some(saved) = state.scopes.get_mut(&scope.id)
        {
            let reserved = saved.reserved;
            saved.active = false;
            saved.reserved = 0;
            state.working_sets.reserved_bytes -= reserved;
            state.working_sets.active_cases -= 1;
            scope.shared.released.notify_all();
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.scopes.remove(&self.id);
            if state.scopes.is_empty() {
                // An emptied BTreeMap can retain its root allocation
                state.scopes = std::collections::BTreeMap::new();
            }
            release(&mut state, MemoryClass::Executor, self.metadata_bytes);
            self.shared.released.notify_all();
        }
    }
}

impl MemoryLease {
    pub(crate) fn validate_working_set(&self, budget: &MemoryBudget) -> Result<(), MemoryError> {
        if !Arc::ptr_eq(&self.budget.shared, &budget.shared) || budget.scope.is_none() {
            return Err(MemoryError::IncompatibleWorkingSet);
        }
        if self.budget.same_owner(budget) {
            return Ok(());
        }
        let state = self
            .budget
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        if let Some(scope) = &self.budget.scope
            && state.scopes.get(&scope.id).is_none_or(|scope| scope.active)
        {
            return Err(MemoryError::IncompatibleWorkingSet);
        }
        drop(state);
        Ok(())
    }

    pub(crate) fn rebind_working_set(&mut self, budget: &MemoryBudget) -> Result<(), MemoryError> {
        self.validate_working_set(budget)?;
        if self.budget.same_owner(budget) {
            return Ok(());
        }
        let mut state = self
            .budget
            .shared
            .state
            .lock()
            .map_err(|_| MemoryError::StatePoisoned)?;
        if let Some(old) = &self.budget.scope {
            state
                .scopes
                .get_mut(&old.id)
                .ok_or(MemoryError::IncompatibleWorkingSet)?
                .used -= self.bytes;
        }
        let next = budget
            .scope
            .as_ref()
            .ok_or(MemoryError::IncompatibleWorkingSet)?;
        let next = state
            .scopes
            .get_mut(&next.id)
            .ok_or(MemoryError::IncompatibleWorkingSet)?;
        // These bytes were already charged globally before entering this worker
        next.used += self.bytes;
        next.maximum += self.bytes;
        drop(state);
        let previous = std::mem::replace(&mut self.budget, budget.clone());
        // A final old scope handle can take the same lock while it is dropped
        drop(previous);
        Ok(())
    }
}
