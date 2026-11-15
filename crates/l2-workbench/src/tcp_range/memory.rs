//! Admit range scratch and retained evidence before allocating either

use super::{MAX_DETAILED_SPANS, Observation, Span, spans};

pub fn range_memory_bound(
    length: usize,
    input_bytes: usize,
    observations: usize,
) -> Option<u64> {
    // Admit position maps, observation copies, span growth, and run references together
    let spans = length.min(MAX_DETAILED_SPANS + 1);
    let positions = length.checked_mul(std::mem::size_of::<spans::Position>())?;
    let omission_map = length.checked_div(8)?.checked_add(8)?;
    let span_storage = spans
        .checked_mul(2)?
        .max(4)
        .checked_mul(std::mem::size_of::<Span>())?;
    let span_values = length.checked_mul(2)?.checked_add(spans.checked_mul(8)?)?;
    let observation_storage = observations
        .checked_mul(2)?
        .max(4)
        .checked_mul(std::mem::size_of::<Observation>())?;
    let runs = spans.checked_mul(std::mem::size_of::<crate::reconstruction::ByteRun<'_>>())?;
    u64::try_from(
        positions
            .checked_add(omission_map)?
            .checked_add(span_storage)?
            .checked_add(span_values)?
            .checked_add(observation_storage)?
            .checked_add(input_bytes)?
            .checked_add(runs)?,
    )
    .ok()
}
