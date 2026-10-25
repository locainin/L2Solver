use super::super::{MessageOrigin, ProtocolError};
use super::model::StreamMessageParser;
use crate::reconstruction::Origin;

impl StreamMessageParser {
    pub(super) fn map_sources(
        &self,
        start: usize,
        end: usize,
    ) -> Result<Vec<MessageOrigin>, ProtocolError> {
        let mut mapped = Vec::new();
        if let Some(origins) = self.source_origins.query_overlapping(start, end) {
            for origin in origins {
                if let Some(mapping) = map_origin_overlap(&origin, start, end)? {
                    mapped
                        .try_reserve(1)
                        .map_err(|_| ProtocolError::AllocationFailed)?;
                    mapped.push(mapping);
                }
            }
        }
        mapped.sort_by_key(|origin| (origin.message_offset, origin.packet, origin.frame_offset));
        Ok(mapped)
    }
}

pub(super) fn map_origin_overlap(
    origin: &Origin,
    start: usize,
    end: usize,
) -> Result<Option<MessageOrigin>, ProtocolError> {
    if origin.packet == 0 || origin.length == 0 {
        return Ok(None);
    }
    let origin_end = origin
        .offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    origin
        .frame_offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    let overlap_start = start.max(origin.offset);
    let overlap_end = end.min(origin_end);
    if overlap_start >= overlap_end {
        return Ok(None);
    }
    let frame_offset = origin
        .frame_offset
        .checked_add(overlap_start - origin.offset)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    Ok(Some(MessageOrigin {
        packet: origin.packet,
        frame_offset,
        message_offset: overlap_start - start,
        length: overlap_end - overlap_start,
    }))
}

pub(super) fn collect_source_origins(
    start: usize,
    end: usize,
    origins: &[Origin],
) -> Result<Vec<Origin>, ProtocolError> {
    let mut intersecting = Vec::new();
    for origin in origins {
        if source_overlap_range(origin, start, end)?.is_some() {
            intersecting
                .try_reserve(1)
                .map_err(|_| ProtocolError::AllocationFailed)?;
            intersecting.push(origin.clone());
        }
    }

    // Order ranges first while keeping exact duplicates adjacent
    intersecting.sort_unstable_by_key(|origin| {
        (
            origin.offset,
            origin.length,
            origin.packet,
            origin.frame_offset,
        )
    });
    intersecting.dedup();
    let ranges = intersecting.iter().map(|origin| {
        // Every retained endpoint passed checked arithmetic during collection
        (
            start.max(origin.offset),
            end.min(origin.offset + origin.length),
        )
    });
    if !ranges_cover(start, end, ranges) {
        return Err(ProtocolError::IncompleteSourceMap);
    }
    Ok(intersecting)
}

pub(super) fn source_map_covers(
    start: usize,
    end: usize,
    origins: &[Origin],
) -> Result<bool, ProtocolError> {
    let mut ranges = Vec::new();
    for origin in origins {
        if let Some(range) = source_overlap_range(origin, start, end)? {
            ranges.push(range);
        }
    }
    ranges.sort_unstable();
    Ok(ranges_cover(start, end, ranges))
}

fn source_overlap_range(
    origin: &Origin,
    start: usize,
    end: usize,
) -> Result<Option<(usize, usize)>, ProtocolError> {
    if origin.packet == 0 || origin.length == 0 {
        return Ok(None);
    }
    origin
        .frame_offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    let origin_end = origin
        .offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    let overlap_start = start.max(origin.offset);
    let overlap_end = end.min(origin_end);
    Ok((overlap_start < overlap_end).then_some((overlap_start, overlap_end)))
}

fn ranges_cover(
    start: usize,
    end: usize,
    ranges: impl IntoIterator<Item = (usize, usize)>,
) -> bool {
    let mut covered = start;
    for (range_start, range_end) in ranges {
        if range_start > covered {
            return false;
        }
        covered = covered.max(range_end);
        if covered >= end {
            return true;
        }
    }
    covered >= end
}

pub(super) fn message_origins_cover(
    message_length: usize,
    origins: &[MessageOrigin],
) -> Result<bool, ProtocolError> {
    if message_length == 0 {
        return Ok(origins.is_empty());
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(origins.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    for origin in origins {
        let Some(message_end) = origin.message_offset.checked_add(origin.length) else {
            return Ok(false);
        };
        if origin.packet == 0
            || origin.length == 0
            || origin.frame_offset.checked_add(origin.length).is_none()
            || message_end > message_length
        {
            return Ok(false);
        }
        ranges.push((origin.message_offset, message_end));
    }
    ranges.sort_unstable();
    Ok(ranges_cover(0, message_length, ranges))
}
