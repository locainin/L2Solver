use super::{
    model::{
        Ambiguity, CarrierError, MAX_EVENT_ID_BYTES, MAX_INPUT_BYTES, MAX_SAMPLE_BYTES,
        MAX_SAMPLE_RANGES, MAX_SAMPLES, MAX_SOURCES, MAX_TOTAL_RANGES, Sample,
    },
    source::SourceReader,
};
use crate::evidence::SourceRange;
use std::collections::BTreeMap;

pub(super) struct ResolvedSample {
    pub event_id: Option<String>,
    pub sequence: Option<u64>,
    pub bytes: Vec<u8>,
    pub ambiguity: Ambiguity,
}

#[derive(Clone, Copy)]
struct MappingSlot {
    source_index: usize,
    range_index: usize,
    output_offset: usize,
}

pub(super) fn resolve_samples(
    sources: &mut [SourceReader],
    samples: &[Sample<'_>],
) -> Result<Vec<ResolvedSample>, CarrierError> {
    validate_request_sizes(sources.len(), samples.len())?;
    let source_index = source_indexes(sources)?;
    let mut sample_ids = std::collections::HashSet::with_capacity(samples.len());
    let mut total_bytes = 0_usize;
    let mut total_mapped_bytes = 0_usize;
    let mut total_ranges = 0_usize;
    let mut source_ranges = (0..sources.len()).map(|_| Vec::new()).collect::<Vec<_>>();
    let mut sample_slots = Vec::new();
    sample_slots
        .try_reserve_exact(samples.len())
        .map_err(|_| CarrierError::RequestLimit)?;
    for sample in samples {
        validate_sample(sample, &mut sample_ids)?;
        total_bytes = add_with_limit(total_bytes, sample.length, MAX_INPUT_BYTES)?;
        total_ranges = add_with_limit(total_ranges, sample.mappings.len(), MAX_TOTAL_RANGES)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(sample.mappings.len())
            .map_err(|_| CarrierError::RequestLimit)?;
        for mapping in sample.mappings {
            let mapping_bytes =
                usize::try_from(mapping.range.length).map_err(|_| CarrierError::RangeTooLarge)?;
            total_mapped_bytes =
                add_with_limit(total_mapped_bytes, mapping_bytes, MAX_INPUT_BYTES)?;
            let output_end = mapping
                .offset
                .checked_add(mapping_bytes)
                .ok_or(CarrierError::InvalidSourceRange)?;
            if output_end > sample.length {
                return Err(CarrierError::InvalidSourceRange);
            }
            let source_index = source_index
                .get(&mapping.range.source)
                .copied()
                .ok_or(CarrierError::InvalidSourceRange)?;
            let requests = source_ranges
                .get_mut(source_index)
                .ok_or(CarrierError::InvalidSourceRange)?;
            let range_index = requests.len();
            requests.push(&mapping.range);
            slots.push(MappingSlot {
                source_index,
                range_index,
                output_offset: mapping.offset,
            });
        }
        sample_slots.push(slots);
    }
    let mut range_bytes = Vec::new();
    range_bytes
        .try_reserve_exact(sources.len())
        .map_err(|_| CarrierError::RequestLimit)?;
    for (source, ranges) in sources.iter_mut().zip(source_ranges) {
        range_bytes.push(source.read_ranges(&ranges)?);
    }
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(samples.len())
        .map_err(|_| CarrierError::RequestLimit)?;
    for (sample, slots) in samples.iter().zip(sample_slots) {
        let bytes = resolve_mapping(sample, &slots, &range_bytes)?;
        resolved.push(ResolvedSample {
            event_id: sample.event_id.map(str::to_owned),
            sequence: sample.sequence,
            bytes,
            ambiguity: sample.ambiguity,
        });
    }
    Ok(resolved)
}

const fn validate_request_sizes(
    source_count: usize,
    sample_count: usize,
) -> Result<(), CarrierError> {
    if source_count == 0
        || source_count > MAX_SOURCES
        || sample_count == 0
        || sample_count > MAX_SAMPLES
    {
        return Err(CarrierError::RequestLimit);
    }
    Ok(())
}

fn source_indexes(sources: &[SourceReader]) -> Result<BTreeMap<String, usize>, CarrierError> {
    let mut indexes = BTreeMap::new();
    for (index, source) in sources.iter().enumerate() {
        if indexes.insert(source.id().to_owned(), index).is_some() {
            return Err(CarrierError::InvalidSourceId);
        }
    }
    Ok(indexes)
}

fn validate_sample(
    sample: &Sample<'_>,
    sample_ids: &mut std::collections::HashSet<u64>,
) -> Result<(), CarrierError> {
    if sample.id == 0 || !sample_ids.insert(sample.id) {
        return Err(CarrierError::InvalidSampleId);
    }
    if sample.length == 0 || sample.length > MAX_SAMPLE_BYTES {
        return Err(CarrierError::InvalidSampleLength);
    }
    if sample.mappings.is_empty() || sample.mappings.len() > MAX_SAMPLE_RANGES {
        return Err(CarrierError::RequestLimit);
    }
    if sample.event_id.is_some_and(|event| {
        event.is_empty() || event.len() > MAX_EVENT_ID_BYTES || event.chars().any(char::is_control)
    }) {
        return Err(CarrierError::InvalidEventId);
    }
    Ok(())
}

fn add_with_limit(current: usize, amount: usize, limit: usize) -> Result<usize, CarrierError> {
    let next = current
        .checked_add(amount)
        .ok_or(CarrierError::RequestLimit)?;
    if next > limit {
        return Err(CarrierError::RequestLimit);
    }
    Ok(next)
}

fn resolve_mapping(
    sample: &Sample<'_>,
    slots: &[MappingSlot],
    range_bytes: &[Vec<Vec<u8>>],
) -> Result<Vec<u8>, CarrierError> {
    let mut bytes = vec![0_u8; sample.length];
    let mut covered = vec![false; sample.length];
    for slot in slots {
        let input = range_bytes
            .get(slot.source_index)
            .and_then(|source| source.get(slot.range_index))
            .ok_or(CarrierError::InvalidSourceRange)?;
        // Repeated source ranges are safe only when every shared byte agrees
        verify_mapping_bytes(&mut bytes, &mut covered, slot.output_offset, input)?;
    }
    if covered.iter().any(|seen| !seen) {
        return Err(CarrierError::IncompleteMapping);
    }
    Ok(bytes)
}

fn verify_mapping_bytes(
    output: &mut [u8],
    covered: &mut [bool],
    output_offset: usize,
    input: &[u8],
) -> Result<(), CarrierError> {
    for (index, byte) in input.iter().copied().enumerate() {
        let position = output_offset
            .checked_add(index)
            .ok_or(CarrierError::InvalidSourceRange)?;
        let target = output
            .get_mut(position)
            .ok_or(CarrierError::InvalidSourceRange)?;
        let present = covered
            .get_mut(position)
            .ok_or(CarrierError::InvalidSourceRange)?;
        if *present && *target != byte {
            return Err(CarrierError::ConflictingRanges);
        }
        *target = byte;
        *present = true;
    }
    Ok(())
}

pub(super) fn sample_ranges(
    sample: &Sample<'_>,
    start: usize,
    length: usize,
) -> Result<Vec<SourceRange>, CarrierError> {
    let end = start
        .checked_add(length)
        .ok_or(CarrierError::InvalidSourceRange)?;
    if end > sample.length {
        return Err(CarrierError::InvalidSourceRange);
    }
    let mut ranges = Vec::new();
    for mapping in sample.mappings {
        let mapping_length =
            usize::try_from(mapping.range.length).map_err(|_| CarrierError::RangeTooLarge)?;
        let mapping_end = mapping
            .offset
            .checked_add(mapping_length)
            .ok_or(CarrierError::InvalidSourceRange)?;
        let overlap_start = start.max(mapping.offset);
        let overlap_end = end.min(mapping_end);
        // Keep only the part of this mapping that supports the requested projection
        if overlap_start >= overlap_end {
            continue;
        }
        let source_delta = u64::try_from(overlap_start - mapping.offset)
            .map_err(|_| CarrierError::RangeTooLarge)?;
        let range_length =
            u64::try_from(overlap_end - overlap_start).map_err(|_| CarrierError::RangeTooLarge)?;
        let offset = mapping
            .range
            .offset
            .checked_add(source_delta)
            .ok_or(CarrierError::InvalidSourceRange)?;
        ranges.push(SourceRange {
            source: mapping.range.source.clone(),
            packet: mapping.range.packet,
            offset,
            length: range_length,
        });
    }
    if ranges.is_empty() {
        return Err(CarrierError::IncompleteMapping);
    }
    Ok(ranges)
}
