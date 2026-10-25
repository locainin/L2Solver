use super::super::StepFailure;
use super::{OutputBudget, check_output_size};
use flate2::bufread::{GzDecoder, ZlibDecoder};
use std::io::Read;

pub(super) fn gzip(input: &[u8], budget: OutputBudget) -> Result<Vec<u8>, StepFailure> {
    let mut decoder = GzDecoder::new(input);
    let output = read_bounded(&mut decoder, budget)?;
    if !decoder.into_inner().is_empty() {
        return Err(StepFailure::TrailingCompressedData);
    }
    Ok(output)
}

pub(super) fn zlib(input: &[u8], budget: OutputBudget) -> Result<Vec<u8>, StepFailure> {
    let mut decoder = ZlibDecoder::new(input);
    let output = read_bounded(&mut decoder, budget)?;
    if !decoder.into_inner().is_empty() {
        return Err(StepFailure::TrailingCompressedData);
    }
    Ok(output)
}

fn read_bounded<R: Read>(reader: &mut R, budget: OutputBudget) -> Result<Vec<u8>, StepFailure> {
    let output_limit = budget.max_output.min(budget.remaining_intermediate);
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = output_limit - output.len();
        // One extra byte distinguishes an exact limit from a stream that exceeds it
        let read_limit = buffer.len().min(remaining.saturating_add(1));
        let destination = buffer
            .get_mut(..read_limit)
            .ok_or(StepFailure::InvalidCompressedStream)?;
        let read = reader
            .read(destination)
            .map_err(|_| StepFailure::InvalidCompressedStream)?;
        if read == 0 {
            check_output_size(output.len(), budget)?;
            return Ok(output);
        }
        if read > remaining {
            return Err(if budget.remaining_intermediate < budget.max_output {
                StepFailure::IntermediateBudgetExceeded {
                    limit: budget.max_intermediate,
                }
            } else {
                StepFailure::OutputLimitExceeded {
                    limit: budget.max_output,
                }
            });
        }
        let source = buffer
            .get(..read)
            .ok_or(StepFailure::InvalidCompressedStream)?;
        output
            .try_reserve(read)
            .map_err(|_| StepFailure::AllocationFailed)?;
        output.extend_from_slice(source);
    }
}
