use super::{
    Coverage, Endpoint, Origin, RangeKind, ReconstructionError, SequenceBudget, Stream, Transport,
};
use crate::tcp_range::{MAX_RANGE_BYTES, Segment, TcpRange};
use l2_discovery::TransportHeader;
use std::collections::BTreeSet;

struct Bounds {
    start: u32,
    start_known: bool,
    ambiguous: bool,
    extent: usize,
    fin_ends: Vec<usize>,
    outside: usize,
    origins: Vec<Origin>,
}

pub(super) fn finish(
    source: Endpoint,
    destination: Endpoint,
    packets: &[Transport],
    budget: &mut SequenceBudget,
) -> Result<Stream, ReconstructionError> {
    let mut bounds = bounds(packets)?;
    let end_observed = bounds.fin_ends.len() == 1
        && bounds
            .fin_ends
            .first()
            .is_some_and(|end| *end == bounds.extent);
    bounds.ambiguous |= bounds.fin_ends.len() > 1
        || bounds
            .fin_ends
            .first()
            .is_some_and(|end| *end < bounds.extent);
    let coverage = if bounds.extent == 0 {
        None
    } else if budget.reserve(bounds.extent, RangeKind::Tcp)? {
        let coverage = coverage(packets, bounds.start, bounds.extent, budget)?;
        Some(budget.retain_coverage(coverage, RangeKind::Tcp)?)
    } else {
        bounds.ambiguous = true;
        None
    };
    Ok(Stream {
        source,
        destination,
        start_sequence: bounds.start,
        start_known: bounds.start_known,
        end_observed,
        sequence_ambiguous: bounds.ambiguous,
        outside_segments: bounds.outside,
        coverage,
        origins: bounds.origins,
        packets: packets.iter().map(|packet| packet.packet).collect(),
        fragment_candidates: packets
            .iter()
            .filter_map(|packet| packet.fragment_candidate)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    })
}

fn bounds(packets: &[Transport]) -> Result<Bounds, ReconstructionError> {
    let syns: Vec<_> = packets
        .iter()
        .filter_map(|packet| match packet.header {
            TransportHeader::Tcp {
                sequence, flags, ..
            } if flags & 7 == 2 => Some(sequence.wrapping_add(1)),
            _ => None,
        })
        .collect();
    let start_known = !syns.is_empty();
    let mut start = syns
        .first()
        .copied()
        .or_else(|| {
            packets
                .iter()
                .find(|packet| !packet.bytes.is_empty())
                .and_then(data_sequence)
        })
        .unwrap_or(0);
    if !start_known {
        for packet in packets.iter().filter(|packet| !packet.bytes.is_empty()) {
            if let Some(sequence) = data_sequence(packet)
                && start.wrapping_sub(sequence) < 0x8000_0000
            {
                start = sequence;
            }
        }
    }
    let mut bounds = Bounds {
        start,
        start_known,
        ambiguous: syns.iter().any(|syn| *syn != start),
        extent: 0,
        fin_ends: Vec::new(),
        outside: 0,
        origins: Vec::new(),
    };
    for packet in packets {
        let TransportHeader::Tcp { flags, .. } = packet.header else {
            continue;
        };
        let Some(offset) = offset(packet, start)? else {
            if !packet.bytes.is_empty() || flags & 1 != 0 {
                bounds.outside += 1;
                bounds.ambiguous = true;
            }
            continue;
        };
        // Bare acknowledgements do not declare a payload byte interval
        if !packet.bytes.is_empty() || flags & 1 != 0 {
            bounds.extent = bounds.extent.max(offset + packet.bytes.len());
        }
        if flags & 1 != 0 {
            bounds.fin_ends.push(offset + packet.bytes.len());
        }
        bounds
            .origins
            .extend(packet.origins.iter().cloned().map(|mut origin| {
                origin.offset += offset;
                origin
            }));
    }
    bounds.fin_ends.sort_unstable();
    bounds.fin_ends.dedup();
    Ok(bounds)
}

const fn data_sequence(packet: &Transport) -> Option<u32> {
    match packet.header {
        TransportHeader::Tcp {
            sequence, flags, ..
        } => Some(sequence.wrapping_add((flags & 2 != 0) as u32)),
        TransportHeader::Udp => None,
    }
}

fn offset(packet: &Transport, start: u32) -> Result<Option<usize>, ReconstructionError> {
    let sequence = data_sequence(packet).ok_or(ReconstructionError("TCP stream received UDP"))?;
    let offset = usize::try_from(sequence.wrapping_sub(start))
        .map_err(|_| ReconstructionError("sequence offset is not representable"))?;
    Ok(
        (offset <= MAX_RANGE_BYTES && packet.bytes.len() <= MAX_RANGE_BYTES.saturating_sub(offset))
            .then_some(offset),
    )
}

fn coverage(
    packets: &[Transport],
    start: u32,
    extent: usize,
    budget: &SequenceBudget,
) -> Result<Coverage, ReconstructionError> {
    let mut range = TcpRange::new_with_limits(
        start,
        extent,
        budget.range_observations,
        budget.range_retained_bytes,
    )
    .map_err(|_| ReconstructionError("invalid TCP episode range"))?;
    for packet in packets {
        if offset(packet, start)?.is_none() {
            continue;
        }
        if let TransportHeader::Tcp {
            sequence, flags, ..
        } = packet.header
        {
            // Fragmented segments keep their original frame ranges in the separate origin map
            range
                .observe(Segment {
                    packet_index: packet.packet,
                    payload_frame_offset: 0,
                    sequence,
                    flags,
                    payload: &packet.bytes,
                })
                .map_err(|_| ReconstructionError("invalid TCP observation range"))?;
        }
    }
    Ok(Coverage::from_range(range.finish()))
}
