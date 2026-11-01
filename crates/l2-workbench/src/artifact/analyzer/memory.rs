//! Shared admission for analyzer-owned buffers and report metadata

use super::{AnalyzerError, RegionCueOrigin};
use crate::job::MemoryLease;
use std::fmt;

#[cfg(test)]
#[path = "../../../tests/artifact/analyzer_memory_internal.rs"]
mod tests;

pub(super) type Charge = Option<MemoryLease>;

pub(super) fn sibling(parent: &Charge, bytes: usize) -> Result<Charge, AnalyzerError> {
    let bytes = u64::try_from(bytes).map_err(|_| AnalyzerError::AllocationFailure)?;
    parent
        .as_ref()
        .map(|lease| lease.try_sibling(bytes))
        .transpose()
        .map_err(AnalyzerError::Memory)
}

pub(super) fn grow(lease: &mut Charge, bytes: usize) -> Result<(), AnalyzerError> {
    if let Some(lease) = lease {
        let total = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| lease.bytes().checked_add(bytes))
            .ok_or(AnalyzerError::AllocationFailure)?;
        lease.try_resize(total)?;
    }
    Ok(())
}

pub(super) fn resize(lease: &mut Charge, bytes: usize) -> Result<(), AnalyzerError> {
    if let Some(lease) = lease {
        lease.try_resize(u64::try_from(bytes).map_err(|_| AnalyzerError::AllocationFailure)?)?;
    }
    Ok(())
}

pub(super) fn split(lease: &mut Charge, bytes: usize) -> Result<Charge, AnalyzerError> {
    lease
        .as_mut()
        .map(|lease| {
            let bytes = u64::try_from(bytes).map_err(|_| AnalyzerError::AllocationFailure)?;
            lease
                .split_off(bytes)
                .ok_or(AnalyzerError::AllocationFailure)
        })
        .transpose()
}

pub(super) fn absorb(parent: &mut Charge, child: Charge) {
    if let (Some(parent), Some(child)) = (parent.as_mut(), child) {
        parent.absorb(child);
    }
}

pub(super) struct Bytes {
    pub bytes: Vec<u8>,
    pub memory: Charge,
}

pub(super) fn copy_bytes(source: &[u8], template: &Charge) -> Result<Bytes, AnalyzerError> {
    let mut memory = sibling(template, source.len())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    resize(&mut memory, bytes.capacity())?;
    bytes.extend_from_slice(source);
    Ok(Bytes { bytes, memory })
}

pub(super) fn copy_cues(
    source: &[RegionCueOrigin],
    template: &Charge,
) -> Result<(Vec<RegionCueOrigin>, Charge), AnalyzerError> {
    let size = std::mem::size_of::<RegionCueOrigin>();
    let requested = source
        .len()
        .checked_mul(size)
        .ok_or(AnalyzerError::AllocationFailure)?;
    let mut memory = sibling(template, requested)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(source.len())
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    let actual = values
        .capacity()
        .checked_mul(size)
        .ok_or(AnalyzerError::AllocationFailure)?;
    resize(&mut memory, actual)?;
    values.extend_from_slice(source);
    Ok((values, memory))
}

pub(super) fn copy_string(source: &str, parent: &mut Charge) -> Result<String, AnalyzerError> {
    let mut memory = sibling(parent, source.len())?;
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| AnalyzerError::AllocationFailure)?;
    resize(&mut memory, value.capacity())?;
    value.push_str(source);
    absorb(parent, memory);
    Ok(value)
}

pub(super) fn digest(source: &[u8], parent: &mut Charge) -> Result<String, AnalyzerError> {
    // A digest has 64 hexadecimal bytes and formatting can overlap growing buffers
    let mut memory = sibling(parent, 128)?;
    let value = crate::sha256(source);
    resize(&mut memory, value.capacity())?;
    absorb(parent, memory);
    Ok(value)
}

pub(super) fn format_message(
    arguments: fmt::Arguments<'_>,
    parent: &mut Charge,
) -> Result<String, AnalyzerError> {
    let mut text = BudgetedText {
        value: String::new(),
        memory: sibling(parent, 0)?,
        error: None,
    };
    if fmt::write(&mut text, arguments).is_err() {
        return Err(text
            .error
            .take()
            .unwrap_or(AnalyzerError::AllocationFailure));
    }
    let BudgetedText { value, memory, .. } = text;
    absorb(parent, memory);
    Ok(value)
}

struct BudgetedText {
    value: String,
    memory: Charge,
    error: Option<AnalyzerError>,
}

impl BudgetedText {
    fn append(&mut self, text: &str) -> Result<(), AnalyzerError> {
        let required = self
            .value
            .len()
            .checked_add(text.len())
            .ok_or(AnalyzerError::AllocationFailure)?;
        if required > self.value.capacity() {
            let capacity = self
                .value
                .capacity()
                .checked_mul(2)
                .ok_or(AnalyzerError::AllocationFailure)?
                .max(32)
                .max(required);
            let mut next_memory = sibling(&self.memory, capacity)?;
            let mut next = String::new();
            next.try_reserve_exact(capacity)
                .map_err(|_| AnalyzerError::AllocationFailure)?;
            resize(&mut next_memory, next.capacity())?;
            next.push_str(&self.value);
            let previous = std::mem::replace(&mut self.value, next);
            let previous_capacity = previous.capacity();
            drop(previous);
            absorb(&mut self.memory, next_memory);
            drop(split(&mut self.memory, previous_capacity)?);
        }
        self.value.push_str(text);
        Ok(())
    }
}

impl fmt::Write for BudgetedText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if let Err(error) = self.append(text) {
            self.error = Some(error);
            return Err(fmt::Error);
        }
        Ok(())
    }
}

pub(super) fn reserve_one<T>(
    values: &mut Vec<T>,
    parent: &mut Charge,
) -> Result<(), AnalyzerError> {
    if values.len() < values.capacity() {
        return Ok(());
    }
    if let Some(parent) = parent {
        crate::allocation::reserve_one_with_memory(values, parent).map_err(|error| match error {
            crate::allocation::VectorAllocationError::Memory(error) => AnalyzerError::Memory(error),
            crate::allocation::VectorAllocationError::Allocation => {
                AnalyzerError::AllocationFailure
            }
        })
    } else {
        values
            .try_reserve(1)
            .map_err(|_| AnalyzerError::AllocationFailure)
    }
}
