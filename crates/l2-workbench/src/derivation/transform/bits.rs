use super::super::{BitRemainder, StepFailure};
use super::{OutputBudget, check_output_size};

pub(super) fn select_bits(
    input: &[u8],
    indices: &[usize],
    bits_per_byte: u8,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    pack_selected_bits(
        input,
        indices.iter().copied(),
        indices.len(),
        bits_per_byte,
        BitRemainder::Reject,
        budget,
    )
}

pub fn select_bit_plane_chunks<'a>(
    chunks: impl IntoIterator<Item = &'a [u8]>,
    phase: u8,
    bits_per_byte: u8,
    remainder: BitRemainder,
    remaining_budget: usize,
) -> Result<Vec<u8>, StepFailure> {
    if phase > 7 {
        return Err(StepFailure::InvalidBitPhase {
            phase: usize::from(phase),
            stride_bits: 8,
        });
    }
    let chunks: Vec<_> = chunks.into_iter().collect();
    let selected_bits = chunks.iter().try_fold(0_usize, |total, chunk| {
        total
            .checked_add(chunk.len())
            .ok_or(StepFailure::BitRangeOverflow)
    })?;
    let shift = 7 - phase;
    let values = chunks
        .iter()
        .flat_map(|chunk| chunk.iter().map(move |byte| (byte >> shift) & 1))
        .map(Ok);
    pack_selected_values(
        values,
        selected_bits,
        bits_per_byte,
        remainder,
        OutputBudget {
            remaining_intermediate: remaining_budget,
            max_output: super::super::MAX_OUTPUT_BYTES,
            max_intermediate: super::super::MAX_INTERMEDIATE_BYTES,
            max_key_bytes: super::super::MAX_INPUT_BYTES,
        },
    )
}

#[derive(Clone, Copy)]
pub(super) struct BitWindow {
    pub start_bit: usize,
    pub bit_count: usize,
    pub stride_bits: usize,
    pub phase: usize,
}

impl BitWindow {
    pub(super) const fn new(
        start_bit: usize,
        bit_count: usize,
        stride_bits: usize,
        phase: usize,
    ) -> Self {
        Self {
            start_bit,
            bit_count,
            stride_bits,
            phase,
        }
    }
}

pub(super) fn select_bit_range(
    input: &[u8],
    window: BitWindow,
    bits_per_byte: u8,
    remainder: BitRemainder,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    let BitWindow {
        start_bit,
        bit_count,
        stride_bits,
        phase,
    } = window;
    if stride_bits == 0 {
        return Err(StepFailure::InvalidBitStride { stride_bits });
    }
    if phase >= stride_bits {
        return Err(StepFailure::InvalidBitPhase { phase, stride_bits });
    }

    // Validate the complete requested window, including bits skipped by the phase
    let input_bits = input
        .len()
        .checked_mul(8)
        .ok_or(StepFailure::BitRangeOverflow)?;
    let end_bit = start_bit
        .checked_add(bit_count)
        .ok_or(StepFailure::BitRangeOverflow)?;
    if end_bit > input_bits {
        return Err(StepFailure::BitRangeOutOfBounds {
            start_bit,
            bit_count,
            input_bits,
        });
    }

    // A phase outside a short window selects no bits, while an in-window phase starts the stride
    let selected_bits = if phase >= bit_count {
        0
    } else {
        bit_count
            .checked_sub(1)
            .and_then(|last| last.checked_sub(phase))
            .and_then(|last| last.checked_div(stride_bits))
            .and_then(|count| count.checked_add(1))
            .ok_or(StepFailure::BitRangeOverflow)?
    };
    let first_bit = if selected_bits == 0 {
        None
    } else {
        Some(
            start_bit
                .checked_add(phase)
                .ok_or(StepFailure::BitRangeOverflow)?,
        )
    };
    let indices = first_bit.into_iter().flat_map(|first| {
        std::iter::successors(Some(first), move |index| index.checked_add(stride_bits))
            .take(selected_bits)
    });
    pack_selected_bits(
        input,
        indices,
        selected_bits,
        bits_per_byte,
        remainder,
        budget,
    )
}

fn pack_selected_bits(
    input: &[u8],
    indices: impl Iterator<Item = usize>,
    selected_bits: usize,
    bits_per_byte: u8,
    remainder: BitRemainder,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    let input_bits = input
        .len()
        .checked_mul(8)
        .ok_or(StepFailure::BitRangeOverflow)?;
    let values = indices.take(selected_bits).map(|index| {
        let source_byte = input
            .get(index / 8)
            .copied()
            .ok_or(StepFailure::BitSelectionOutOfBounds { index, input_bits })?;
        let source_shift = 7 - index % 8;
        Ok((source_byte >> source_shift) & 1)
    });
    pack_selected_values(values, selected_bits, bits_per_byte, remainder, budget)
}

fn pack_selected_values(
    values: impl Iterator<Item = Result<u8, StepFailure>>,
    selected_bits: usize,
    bits_per_byte: u8,
    remainder: BitRemainder,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    if !(1..=8).contains(&bits_per_byte) {
        return Err(StepFailure::InvalidBitsPerByte { bits_per_byte });
    }
    let group_width = usize::from(bits_per_byte);
    let trailing_bits = selected_bits % group_width;
    if trailing_bits != 0 && remainder == BitRemainder::Reject {
        return Err(StepFailure::IncompleteBitGroup {
            selected_bits,
            bits_per_byte,
        });
    }
    let retained_bits = if remainder == BitRemainder::Drop {
        selected_bits - trailing_bits
    } else {
        selected_bits
    };
    let output_length = (retained_bits / group_width)
        .checked_add(usize::from(
            trailing_bits != 0 && remainder != BitRemainder::Drop,
        ))
        .ok_or(StepFailure::OutputLimitExceeded {
            limit: budget.max_output,
        })?;
    check_output_size(output_length, budget)?;

    // One packing loop handles explicit indices, compact ranges, and chunked planes identically
    let mut output = Vec::with_capacity(output_length);
    let mut packed_byte = 0_u8;
    for (position, bit) in values.take(retained_bits).enumerate() {
        packed_byte = (packed_byte << 1) | bit?;
        if position % group_width == group_width - 1 {
            output.push(packed_byte);
            packed_byte = 0;
        }
    }

    if trailing_bits != 0 && remainder != BitRemainder::Drop {
        let padding_bit = u8::from(remainder == BitRemainder::OneFill);
        for _ in trailing_bits..group_width {
            packed_byte = (packed_byte << 1) | padding_bit;
        }
        output.push(packed_byte);
    }
    Ok(output)
}
