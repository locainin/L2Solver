use super::super::StepFailure;
use super::{Admission, Buffer, OutputBudget, TransformError, check_output_size};

pub(super) fn xor_repeat(
    input: &[u8],
    key: &[u8],
    offset: usize,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    if key.is_empty() {
        return Err(StepFailure::EmptyXorKey);
    }
    if key.len() > budget.max_key_bytes {
        return Err(StepFailure::XorKeyTooLong {
            length: key.len(),
            limit: budget.max_key_bytes,
        });
    }
    check_output_size(input.len(), budget)?;
    let key_length = key.len();
    // Reduce the caller offset before adding each input position
    let phase = offset % key_length;
    let mut output = Vec::with_capacity(input.len());
    for (position, byte) in input.iter().copied().enumerate() {
        let key_index = (phase + position % key_length) % key_length;
        let key_byte = key
            .get(key_index)
            .copied()
            .ok_or(StepFailure::EmptyXorKey)?;
        output.push(byte ^ key_byte);
    }
    Ok(output)
}

pub(super) fn byte_add(
    input: &[u8],
    value: u8,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    check_output_size(input.len(), budget)?;
    Ok(input.iter().map(|byte| byte.wrapping_add(value)).collect())
}

pub(super) fn rotate_bits(
    input: &[u8],
    count: u8,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    check_output_size(input.len(), budget)?;
    let shift = u32::from(count % 8);
    Ok(input.iter().map(|byte| byte.rotate_left(shift)).collect())
}

pub(super) fn slice<A: Admission>(
    input: &[u8],
    start: usize,
    length: Option<usize>,
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    let length = match length {
        Some(length) => length,
        None => input
            .len()
            .checked_sub(start)
            .ok_or(StepFailure::SliceOutOfBounds {
                start,
                length: 0,
                input_length: input.len(),
            })?,
    };
    check_output_size(length, budget)?;
    let end = start
        .checked_add(length)
        .ok_or(StepFailure::SliceOutOfBounds {
            start,
            length,
            input_length: input.len(),
        })?;
    let selected = input.get(start..end).ok_or(StepFailure::SliceOutOfBounds {
        start,
        length,
        input_length: input.len(),
    })?;
    let mut output = Buffer::with_capacity(selected.len(), admission)?;
    output.bytes.extend_from_slice(selected);
    Ok(output)
}

pub(super) fn select(
    input: &[u8],
    indices: &[usize],
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    check_output_size(indices.len(), budget)?;
    let mut output = Vec::with_capacity(indices.len());
    for index in indices {
        let byte = input
            .get(*index)
            .copied()
            .ok_or(StepFailure::SelectionOutOfBounds {
                index: *index,
                input_length: input.len(),
            })?;
        output.push(byte);
    }
    Ok(output)
}

pub(super) fn reverse(input: &[u8], budget: OutputBudget) -> Result<Vec<u8>, StepFailure> {
    check_output_size(input.len(), budget)?;
    Ok(input.iter().rev().copied().collect())
}

pub(super) fn permute(
    input: &[u8],
    indices: &[usize],
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    if indices.len() != input.len() {
        return Err(StepFailure::PermutationLengthMismatch {
            length: indices.len(),
            input_length: input.len(),
        });
    }
    check_output_size(input.len(), budget)?;
    let mut seen = vec![false; input.len()];
    let mut output = Vec::with_capacity(input.len());
    for index in indices {
        let Some(seen_position) = seen.get_mut(*index) else {
            return Err(StepFailure::PermutationIndexOutOfBounds {
                index: *index,
                input_length: input.len(),
            });
        };
        if *seen_position {
            return Err(StepFailure::DuplicatePermutationIndex { index: *index });
        }
        *seen_position = true;
        let byte = input
            .get(*index)
            .copied()
            .ok_or(StepFailure::PermutationIndexOutOfBounds {
                index: *index,
                input_length: input.len(),
            })?;
        output.push(byte);
    }
    Ok(output)
}
