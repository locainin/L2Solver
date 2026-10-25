use super::{
    Coverage, Datagram, Endpoint, Origin, RangeKind, ReconstructionError, SequenceBudget, Transport,
};
use crate::tcp_range::{Segment, TcpRange};
use l2_audit::ForensicScope;
use l2_discovery::{FragmentPacket, IpFamily, NetworkAddress, fragment_transport};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    scope: ForensicScope,
    family: IpFamily,
    source: NetworkAddress,
    destination: NetworkAddress,
    identification: u32,
    ipv4_protocol: Option<u8>,
}

pub(super) struct Piece {
    key: Key,
    protocol: u8,
    offset: usize,
    more: bool,
    declared_length: usize,
    captured_complete: bool,
    bytes: Vec<u8>,
    origin: Origin,
    header_length: usize,
}

impl Piece {
    pub(super) fn new(
        scope: ForensicScope,
        packet: u32,
        ethernet_length: usize,
        fragment: FragmentPacket<'_>,
    ) -> Self {
        Self {
            key: Key {
                scope,
                family: fragment.family,
                source: fragment.source,
                destination: fragment.destination,
                identification: fragment.identification,
                ipv4_protocol: (fragment.family == IpFamily::V4).then_some(fragment.protocol),
            },
            protocol: fragment.protocol,
            offset: fragment.offset,
            more: fragment.more,
            declared_length: fragment.declared_payload_length,
            captured_complete: fragment.captured_complete,
            bytes: fragment.payload.to_vec(),
            header_length: fragment.payload_offset,
            origin: Origin {
                packet,
                frame_offset: ethernet_length + fragment.payload_offset,
                offset: fragment.offset,
                length: fragment.payload.len(),
            },
        }
    }
}

pub(super) fn finish(
    pieces: Vec<Piece>,
    maximum: usize,
    budget: &mut SequenceBudget,
) -> Result<(Vec<Datagram>, Vec<Transport>, usize), ReconstructionError> {
    let mut groups: BTreeMap<Key, Vec<Piece>> = BTreeMap::new();
    let mut omitted = 0;
    for piece in pieces {
        if !groups.contains_key(&piece.key) && groups.len() == maximum {
            omitted += 1;
        } else {
            groups.entry(piece.key.clone()).or_default().push(piece);
        }
    }
    let mut datagrams = Vec::new();
    let mut transports = Vec::new();
    for (key, pieces) in groups {
        let (datagram, mut transport) = resolve(key, &pieces, budget)?;
        if let Some(transport) = &mut transport {
            transport.fragment_candidate = Some(datagrams.len());
        }
        datagrams.push(datagram);
        transports.extend(transport);
    }
    Ok((datagrams, transports, omitted))
}

fn resolve(
    key: Key,
    pieces: &[Piece],
    budget: &mut SequenceBudget,
) -> Result<(Datagram, Option<Transport>), ReconstructionError> {
    let protocols: BTreeSet<_> = pieces.iter().map(|piece| piece.protocol).collect();
    let final_lengths: BTreeSet<_> = pieces
        .iter()
        .filter(|piece| !piece.more)
        .map(|piece| piece.offset + piece.declared_length)
        .collect();
    let extent = pieces
        .iter()
        .map(|piece| piece.offset + piece.declared_length)
        .max()
        .unwrap_or(0);
    let length = final_lengths.first().copied().unwrap_or(extent).min(65_535);
    let metadata_consistent = protocols.len() == 1
        && final_lengths.len() <= 1
        && extent <= 65_535
        && pieces.iter().all(|piece| {
            piece.captured_complete
                && (!piece.more
                    || (piece.declared_length != 0 && piece.declared_length.is_multiple_of(8)))
                && piece.offset + piece.declared_length <= length
                && (key.family != IpFamily::V4
                    || piece.offset != 0
                    || length <= 65_535 - piece.header_length)
        });
    let origins: Vec<_> = pieces.iter().map(|piece| piece.origin.clone()).collect();
    let coverage = if length == 0 || !budget.reserve(length, RangeKind::Fragment)? {
        None
    } else {
        let coverage = coverage(pieces, length, budget)?;
        Some(budget.retain_coverage(coverage, RangeKind::Fragment)?)
    };
    let complete = metadata_consistent
        && final_lengths.len() == 1
        && coverage.as_ref().is_some_and(Coverage::unique);
    let transport = if complete {
        recover(&key, &protocols, &origins, coverage.as_ref())
    } else {
        None
    };
    Ok((
        Datagram {
            scope: key.scope,
            family: key.family,
            source: key.source,
            destination: key.destination,
            identification: key.identification,
            protocols: protocols.into_iter().collect(),
            final_lengths: final_lengths.into_iter().collect(),
            complete,
            identity_ambiguous: true,
            metadata_consistent,
            coverage,
            origins,
        },
        transport,
    ))
}

fn coverage(
    pieces: &[Piece],
    length: usize,
    budget: &SequenceBudget,
) -> Result<Coverage, ReconstructionError> {
    let mut range = TcpRange::new_with_limits(
        0,
        length,
        budget.range_observations,
        budget.range_retained_bytes,
    )
    .map_err(|_| ReconstructionError("invalid fragment candidate range"))?;
    for piece in pieces {
        range
            .observe(Segment {
                packet_index: piece.origin.packet,
                payload_frame_offset: piece.origin.frame_offset,
                sequence: u32::try_from(piece.offset)
                    .map_err(|_| ReconstructionError("fragment offset exceeds sequence range"))?,
                flags: 0,
                payload: &piece.bytes,
            })
            .map_err(|_| ReconstructionError("invalid fragment source range"))?;
    }
    Ok(Coverage::from_range(range.finish()))
}

fn recover(
    key: &Key,
    protocols: &BTreeSet<u8>,
    origins: &[Origin],
    coverage: Option<&Coverage>,
) -> Option<Transport> {
    // Unique values establish a candidate byte string, never a receiver reassembly policy
    let bytes: Vec<_> = coverage?
        .spans
        .iter()
        .filter_map(|span| span.bytes.as_ref())
        .flatten()
        .copied()
        .collect();
    let transport = fragment_transport(key.family, *protocols.first()?, &bytes)?;
    Some(Transport {
        scope: key.scope.clone(),
        source: Endpoint {
            address: key.source,
            port: transport.ports.0,
        },
        destination: Endpoint {
            address: key.destination,
            port: transport.ports.1,
        },
        packet: origins.iter().map(|origin| origin.packet).max()?,
        header: transport.header,
        bytes: transport.payload.to_vec(),
        origins: clip_origins(origins, transport.payload_offset, transport.payload.len()),
        trailing_bytes: transport.trailing_bytes.to_vec(),
        trailing_origins: clip_origins(
            origins,
            transport.payload_offset + transport.payload.len(),
            transport.trailing_bytes.len(),
        ),
        fragment_candidate: None,
    })
}

/// Preserve every supporting range, including duplicate identical observations
fn clip_origins(origins: &[Origin], start: usize, length: usize) -> Vec<Origin> {
    let end = start + length;
    origins
        .iter()
        .filter_map(|origin| {
            let first = origin.offset.max(start);
            let last = (origin.offset + origin.length).min(end);
            (first < last).then(|| Origin {
                packet: origin.packet,
                frame_offset: origin.frame_offset + first - origin.offset,
                offset: first - start,
                length: last - first,
            })
        })
        .collect()
}
