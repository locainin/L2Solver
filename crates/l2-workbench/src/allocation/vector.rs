//! Reserve a replacement vector while the old allocation remains live

use crate::job::{MemoryError, MemoryLease};
use std::{convert::Infallible, mem::size_of};

pub trait VectorAdmission {
    type Error;

    fn reserve_one<T>(&mut self, values: &mut Vec<T>) -> Result<(), Self::Error>;
}

pub struct Unrestricted;

impl VectorAdmission for Unrestricted {
    type Error = Infallible;

    fn reserve_one<T>(&mut self, _values: &mut Vec<T>) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct Metered<'a>(pub &'a mut MemoryLease);

impl VectorAdmission for Metered<'_> {
    type Error = VectorAllocationError;

    fn reserve_one<T>(&mut self, values: &mut Vec<T>) -> Result<(), Self::Error> {
        reserve_one_with_memory(values, self.0)
    }
}

#[derive(Debug)]
pub enum VectorAllocationError {
    Memory(MemoryError),
    Allocation,
}

impl From<MemoryError> for VectorAllocationError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

pub fn reserve_one_with_memory<T>(
    values: &mut Vec<T>,
    parent: &mut MemoryLease,
) -> Result<(), VectorAllocationError> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    let capacity = values
        .capacity()
        .checked_mul(2)
        .ok_or(VectorAllocationError::Allocation)?
        .max(4);
    let requested = capacity
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(VectorAllocationError::Allocation)?;
    let previous_bytes = values
        .capacity()
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(VectorAllocationError::Allocation)?;
    // The replacement receives its own charge while the old vector is still live
    let mut next_memory = parent.try_sibling(requested)?;
    let mut next = Vec::new();
    next.try_reserve_exact(capacity)
        .map_err(|_| VectorAllocationError::Allocation)?;
    let actual = next
        .capacity()
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(VectorAllocationError::Allocation)?;
    next_memory.try_resize(actual)?;
    next.append(values);
    let previous = std::mem::replace(values, next);
    drop(previous);
    parent.absorb(next_memory);
    let previous_memory = parent
        .split_off(previous_bytes)
        .ok_or(VectorAllocationError::Allocation)?;
    drop(previous_memory);
    Ok(())
}
