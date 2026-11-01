//! Shared admission for bounded range-scanner buffers and retained output

use l2_workbench::{
    artifact::{AnalysisOmission, ArtifactAnalysisOptions},
    job::{MemoryBudget, MemoryClass, MemoryLease},
};
use std::{error::Error, fmt, io};

const MAX_WINDOW_STEP_BYTES: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const PNG_READ_BUFFER_BYTES: usize = 16 * 1024;
const METADATA_BYTES_PER_ARTIFACT: usize = 256;

pub(super) fn charge(memory: &mut MemoryLease, bytes: usize) -> Result<(), Box<dyn Error>> {
    let total = memory
        .bytes()
        .checked_add(u64::try_from(bytes)?)
        .ok_or("analysis metadata memory overflows")?;
    memory.try_resize(total)?;
    Ok(())
}

pub(super) fn charge_omission_payload(
    omission: &AnalysisOmission,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    let bytes = match omission {
        AnalysisOmission::SourceRangeValidationLimit { reason, .. }
        | AnalysisOmission::SourceStreamTransform { reason, .. }
        | AnalysisOmission::ValidationLimit { reason, .. } => reason.capacity(),
        AnalysisOmission::TransformFailed { message, .. } => message.capacity(),
        AnalysisOmission::DerivedStreamRangeCoverage { output_sha256, .. } => {
            output_sha256.capacity()
        }
        _ => 0,
    };
    charge(memory, bytes)
}

pub(super) fn reserve_omission(
    omissions: &mut Vec<AnalysisOmission>,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    // Reserve geometric growth before allocating a larger omission vector
    let growth = if omissions.len() == omissions.capacity() {
        omissions.capacity().max(4)
    } else {
        0
    };
    let bytes = growth
        .checked_mul(std::mem::size_of::<AnalysisOmission>())
        .ok_or("analysis omission memory overflows")?;
    charge(memory, bytes)?;
    let previous_capacity = omissions.capacity();
    omissions.try_reserve_exact(growth)?;
    let extra = omissions.capacity() - previous_capacity - growth;
    charge(memory, extra * std::mem::size_of::<AnalysisOmission>())?;
    Ok(())
}

pub(super) fn copy_message(
    value: &str,
    memory: &mut MemoryLease,
) -> Result<String, Box<dyn Error>> {
    charge(memory, value.len())?;
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())?;
    charge(memory, copy.capacity() - value.len())?;
    copy.push_str(value);
    Ok(copy)
}

pub(super) fn format_message(
    arguments: fmt::Arguments<'_>,
    memory: &mut MemoryLease,
) -> Result<String, Box<dyn Error>> {
    let mut message = BudgetedMessage {
        value: String::new(),
        memory,
        error: None,
    };
    if fmt::write(&mut message, arguments).is_err() {
        return Err(message
            .error
            .take()
            .unwrap_or_else(|| "message formatting failed".into()));
    }
    Ok(message.value)
}

struct BudgetedMessage<'a> {
    value: String,
    memory: &'a mut MemoryLease,
    error: Option<Box<dyn Error>>,
}

impl fmt::Write for BudgetedMessage<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let available = self.value.capacity() - self.value.len();
        if text.len() > available {
            let additional = self.value.capacity().max(64).max(text.len());
            let required = self.value.len().checked_add(additional).ok_or(fmt::Error)?;
            let growth = required - self.value.capacity();
            if let Err(error) = charge(self.memory, growth) {
                self.error = Some(error);
                return Err(fmt::Error);
            }
            let previous = self.value.capacity();
            if let Err(error) = self.value.try_reserve_exact(additional) {
                self.error = Some(Box::new(error));
                return Err(fmt::Error);
            }
            let extra = self.value.capacity() - previous - growth;
            if let Err(error) = charge(self.memory, extra) {
                self.error = Some(error);
                return Err(fmt::Error);
            }
        }
        self.value.push_str(text);
        Ok(())
    }
}

pub(super) fn charge_existing_omissions(
    omissions: &Vec<AnalysisOmission>,
    memory: &mut MemoryLease,
) -> Result<(), Box<dyn Error>> {
    let bytes = omissions
        .capacity()
        .checked_mul(std::mem::size_of::<AnalysisOmission>())
        .ok_or("analysis omission memory overflows")?;
    charge(memory, bytes)?;
    for omission in omissions {
        charge_omission_payload(omission, memory)?;
    }
    Ok(())
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
