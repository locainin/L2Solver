//! Shared admission for bounded range-scanner buffers and retained output

use l2_workbench::{
    artifact::{AnalysisOmission, ArtifactAnalysisOptions},
    job::{MemoryBudget, MemoryClass, MemoryLease},
};
use std::{error::Error, fmt, io};

pub(super) use crate::retained_memory::{charge, copy_message, grow_vec, grow_vec_exact};

#[cfg(test)]
#[path = "../../tests/refine/formatted_memory.rs"]
mod tests;

const MAX_WINDOW_STEP_BYTES: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const PNG_READ_BUFFER_BYTES: usize = 16 * 1024;
const METADATA_BYTES_PER_ARTIFACT: usize = 256;

pub(super) fn charge_omission_payload(
    omission: &AnalysisOmission,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    let bytes = omission
        .owned_heap_bytes()
        .ok_or("omission payload size overflows")?;
    charge(memory, bytes)
}

pub(super) fn reserve_omission(
    omissions: &mut Vec<AnalysisOmission>,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    grow_vec(omissions, memory, 1)
}

pub(super) fn format_message(
    arguments: fmt::Arguments<'_>,
    memory: &mut MemoryLease,
) -> Result<String, Box<dyn Error>> {
    let before = memory.bytes();
    let mut message = BudgetedMessage {
        value: String::new(),
        memory,
        error: None,
    };
    if fmt::write(&mut message, arguments).is_err() {
        let error = message
            .error
            .take()
            .unwrap_or_else(|| "message formatting failed".into());
        // Release the buffer before returning its charge to the shared budget
        drop(message);
        memory.try_resize(before)?;
        return Err(error);
    }
    Ok(message.value)
}

struct BudgetedMessage<'a> {
    value: String,
    memory: &'a mut MemoryLease,
    error: Option<Box<dyn Error>>,
}

impl BudgetedMessage<'_> {
    fn append(&mut self, text: &str) -> Result<(), Box<dyn Error>> {
        let required = self
            .value
            .len()
            .checked_add(text.len())
            .ok_or("formatted message length overflows")?;
        if required > self.value.capacity() {
            let old = self.value.capacity();
            let wanted = old
                .checked_mul(2)
                .ok_or("formatted message capacity overflows")?
                .max(64)
                .max(required);
            let before = self.memory.bytes();
            // Both buffers must fit until the replacement is ready
            charge(self.memory, wanted)?;
            let mut next = String::new();
            if let Err(error) = next.try_reserve_exact(wanted) {
                drop(next);
                self.memory.try_resize(before)?;
                return Err(Box::new(error));
            }
            let admitted = u64::try_from(next.capacity())
                .ok()
                .and_then(|bytes| before.checked_add(bytes));
            let Some(admitted) = admitted else {
                drop(next);
                self.memory.try_resize(before)?;
                return Err("formatted message memory overflows".into());
            };
            if let Err(error) = self.memory.try_resize(admitted) {
                drop(next);
                self.memory.try_resize(before)?;
                return Err(Box::new(error));
            }
            next.push_str(&self.value);
            let previous = std::mem::replace(&mut self.value, next);
            drop(previous);
            let remaining = admitted
                .checked_sub(u64::try_from(old)?)
                .ok_or("formatted message charge is inconsistent")?;
            self.memory.try_resize(remaining)?;
        }
        self.value.push_str(text);
        Ok(())
    }
}

impl fmt::Write for BudgetedMessage<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if let Err(error) = self.append(text) {
            self.error = Some(error);
            return Err(fmt::Error);
        }
        Ok(())
    }
}

pub(super) fn charge_existing_omissions(
    omissions: &Vec<AnalysisOmission>,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    let bytes = omissions_owned_bytes(omissions)?;
    charge(memory, bytes)
}

pub(super) fn omissions_owned_bytes(
    omissions: &Vec<AnalysisOmission>,
) -> Result<usize, Box<dyn Error>> {
    let mut bytes = omissions
        .capacity()
        .checked_mul(std::mem::size_of::<AnalysisOmission>())
        .ok_or("analysis omission memory overflows")?;
    for omission in omissions {
        bytes = bytes
            .checked_add(
                omission
                    .owned_heap_bytes()
                    .ok_or("omission payload size overflows")?,
            )
            .ok_or("analysis omission memory overflows")?;
    }
    Ok(bytes)
}

pub(super) fn reserve(
    memory: &MemoryBudget,
    length: usize,
    options: ArtifactAnalysisOptions,
    is_png: bool,
) -> Result<(MemoryLease, MemoryLease), Box<dyn Error>> {
    let step = (options.limits.max_input_bytes / 2).clamp(1, MAX_WINDOW_STEP_BYTES);
    let window = length.min(step * 2);
    let stream = length.min(STREAM_BUFFER_BYTES);
    let lookahead = length.min(STREAM_BUFFER_BYTES + 21);
    let png_scratch = if is_png { PNG_READ_BUFFER_BYTES } else { 0 };
    let records = options
        .limits
        .max_artifacts
        .checked_add(64)
        .and_then(|count| count.checked_mul(METADATA_BYTES_PER_ARTIFACT))
        .ok_or_else(|| io::Error::other("range metadata allowance overflows"))?;
    let scratch_bytes = window
        .checked_add(stream)
        .and_then(|bytes| bytes.checked_add(lookahead))
        .and_then(|bytes| bytes.checked_add(png_scratch))
        .and_then(|bytes| bytes.checked_add(records))
        .ok_or_else(|| io::Error::other("range scratch allowance overflows"))?;
    // Retained bytes grow their lease as each result is admitted
    let retained = memory.try_reserve(MemoryClass::Executor, 0)?;
    let scratch = memory.try_reserve(MemoryClass::Executor, u64::try_from(scratch_bytes)?)?;
    Ok((scratch, retained))
}
