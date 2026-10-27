//! Shared admission for bounded range-scanner buffers and retained output

use l2_workbench::{
    artifact::ArtifactAnalysisOptions,
    job::{MemoryBudget, MemoryClass, MemoryLease},
};
use std::{error::Error, io};

const MAX_WINDOW_STEP_BYTES: usize = 4 * 1024 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const PNG_READ_BUFFER_BYTES: usize = 16 * 1024;
const METADATA_BYTES_PER_ARTIFACT: usize = 256;

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
