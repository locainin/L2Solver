use super::super::StepFailure;
use super::{Admission, Buffer, OutputBudget, TransformError, check_output_size};
use flate2::bufread::{GzDecoder, ZlibDecoder};
use std::io::Read;

pub(super) fn gzip<A: Admission>(
    input: &[u8],
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    // flate2 1.1.10 caps each gzip header field at 65,535 bytes
    // zlib-rs 0.6.8 uses one 32 KiB window and bounded decoding tables
    // Review the shared workspace allowance when these dependencies or backends change
    let _workspace = admission
        .reserve(super::super::STREAM_WORKSPACE_BYTES)
        .map_err(TransformError::Admission)?;
    let mut decoder = GzDecoder::new(input);
    let output = read_bounded(&mut decoder, budget, admission)?;
    if !decoder.into_inner().is_empty() {
        return Err(StepFailure::TrailingCompressedData.into());
    }
    Ok(output)
}

pub(super) fn zlib<A: Admission>(
    input: &[u8],
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    // Keep the decoder state charged until the reader and its scratch data are gone
    let _workspace = admission
        .reserve(super::super::STREAM_WORKSPACE_BYTES)
        .map_err(TransformError::Admission)?;
    let mut decoder = ZlibDecoder::new(input);
    let output = read_bounded(&mut decoder, budget, admission)?;
    if !decoder.into_inner().is_empty() {
        return Err(StepFailure::TrailingCompressedData.into());
    }
    Ok(output)
}

fn read_bounded<R: Read, A: Admission>(
    reader: &mut R,
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    let output_limit = budget.max_output.min(budget.remaining_intermediate);
    let mut output = Buffer::with_capacity(0, admission)?;
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = output_limit - output.bytes.len();
        // One extra byte distinguishes an exact limit from a stream that exceeds it
        let read_limit = buffer.len().min(remaining.saturating_add(1));
        let destination = buffer
            .get_mut(..read_limit)
            .ok_or(StepFailure::InvalidCompressedStream)?;
        let read = reader
            .read(destination)
            .map_err(|_| StepFailure::InvalidCompressedStream)?;
        if read == 0 {
            check_output_size(output.bytes.len(), budget)?;
            return Ok(output);
        }
        if read > remaining {
            return Err((if budget.remaining_intermediate < budget.max_output {
                StepFailure::IntermediateBudgetExceeded {
                    limit: budget.max_intermediate,
                }
            } else {
                StepFailure::OutputLimitExceeded {
                    limit: budget.max_output,
                }
            })
            .into());
        }
        let source = buffer
            .get(..read)
            .ok_or(StepFailure::InvalidCompressedStream)?;
        output.extend_bounded(source, output_limit, admission)?;
    }
}
