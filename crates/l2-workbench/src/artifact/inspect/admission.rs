//! Admit inspector-owned buffers before they grow

use std::{fmt::Write, mem::size_of};

use super::InspectMemoryError;
use crate::job::MemoryLease;

// The scratch lease represents all parser-owned buffers until the report is returned
pub(in crate::artifact) struct Admission {
    pub(super) scratch: Option<MemoryLease>,
}

impl Admission {
    pub(super) const fn unlimited() -> Self {
        Self { scratch: None }
    }

    pub(in crate::artifact) fn reserve(&mut self, bytes: usize) -> Result<(), InspectMemoryError> {
        if let Some(scratch) = &mut self.scratch {
            let amount = u64::try_from(bytes).map_err(|_| InspectMemoryError::Allocation)?;
            let total = scratch
                .bytes()
                .checked_add(amount)
                .ok_or(InspectMemoryError::Allocation)?;
            scratch
                .try_resize(total)
                .map_err(InspectMemoryError::Memory)?;
        }
        Ok(())
    }

    pub(in crate::artifact) fn release(&mut self, bytes: usize) -> Result<(), InspectMemoryError> {
        if let Some(scratch) = &mut self.scratch {
            let amount = u64::try_from(bytes).map_err(|_| InspectMemoryError::Allocation)?;
            let total = scratch
                .bytes()
                .checked_sub(amount)
                .ok_or(InspectMemoryError::Allocation)?;
            scratch
                .try_resize(total)
                .map_err(InspectMemoryError::Memory)?;
        }
        Ok(())
    }

    pub(in crate::artifact) fn vec<T>(
        &mut self,
        capacity: usize,
    ) -> Result<Vec<T>, InspectMemoryError> {
        let requested = array_bytes::<T>(capacity)?;
        self.reserve(requested)?;
        // Rust 1.96 records the exact request; reconcile if a later toolchain changes this
        let mut values = Vec::new();
        values
            .try_reserve_exact(capacity)
            .map_err(|_| InspectMemoryError::Allocation)?;
        self.reconcile(requested, array_bytes::<T>(values.capacity())?)?;
        Ok(values)
    }

    pub(in crate::artifact) fn grow_vec<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), InspectMemoryError> {
        let required = values
            .len()
            .checked_add(additional)
            .ok_or(InspectMemoryError::Allocation)?;
        if required <= values.capacity() {
            return Ok(());
        }
        let wanted = values.capacity().saturating_mul(2).max(4).max(required);
        let old_bytes = array_bytes::<T>(values.capacity())?;
        // Both buffers stay charged while their records move to the replacement
        let mut replacement = self.vec(wanted)?;
        replacement.append(values);
        *values = replacement;
        self.release(old_bytes)
    }

    pub(in crate::artifact) fn string(
        &mut self,
        capacity: usize,
    ) -> Result<String, InspectMemoryError> {
        self.reserve(capacity)?;
        let mut value = String::new();
        value
            .try_reserve_exact(capacity)
            .map_err(|_| InspectMemoryError::Allocation)?;
        self.reconcile(capacity, value.capacity())?;
        Ok(value)
    }

    pub(in crate::artifact) fn copy_str(
        &mut self,
        value: &str,
    ) -> Result<String, InspectMemoryError> {
        let mut copy = self.string(value.len())?;
        copy.push_str(value);
        Ok(copy)
    }

    pub(in crate::artifact) fn number_name(
        &mut self,
        prefix: &str,
        number: u64,
        suffix: &str,
    ) -> Result<String, InspectMemoryError> {
        // Decimal digits can be counted before formatting allocates their buffer
        let digits = if number == 0 {
            1
        } else {
            usize::try_from(number.ilog10() + 1).map_err(|_| InspectMemoryError::Allocation)?
        };
        let capacity = prefix
            .len()
            .checked_add(digits)
            .and_then(|length| length.checked_add(suffix.len()))
            .ok_or(InspectMemoryError::Allocation)?;
        let mut value = self.string(capacity)?;
        write!(&mut value, "{prefix}{number}{suffix}")
            .map_err(|_| InspectMemoryError::Allocation)?;
        Ok(value)
    }

    pub(in crate::artifact) fn lossy_string(
        &mut self,
        bytes: &[u8],
    ) -> Result<String, InspectMemoryError> {
        // Count replacement characters before creating the only owned copy
        let length = bytes.utf8_chunks().try_fold(0_usize, |total, chunk| {
            let replacement = if chunk.invalid().is_empty() {
                0
            } else {
                char::REPLACEMENT_CHARACTER.len_utf8()
            };
            total
                .checked_add(chunk.valid().len())
                .and_then(|value| value.checked_add(replacement))
                .ok_or(InspectMemoryError::Allocation)
        })?;
        let mut value = self.string(length)?;
        for chunk in bytes.utf8_chunks() {
            value.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                value.push(char::REPLACEMENT_CHARACTER);
            }
        }
        Ok(value)
    }

    fn reconcile(&mut self, requested: usize, actual: usize) -> Result<(), InspectMemoryError> {
        if actual > requested {
            self.reserve(actual - requested)
        } else {
            self.release(requested - actual)
        }
    }
}

pub(in crate::artifact) fn array_bytes<T>(capacity: usize) -> Result<usize, InspectMemoryError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(InspectMemoryError::Allocation)
}
