use super::{
    Endpoint, ReconstructionError, SequenceBudget, TcpSession, Transport, UdpMessage, handshake,
    stream,
};
use l2_audit::ForensicScope;
use l2_discovery::TransportHeader;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    scope: ForensicScope,
    endpoints: [Endpoint; 2],
}
struct Episode {
    key: Key,
    packets: [Vec<Transport>; 2],
    generation_ambiguous: bool,
    // Cache only the facts needed to avoid rescanning a SYN retransmission history
    syn_history: [SynHistory; 2],
}

#[derive(Clone, Copy, Default)]
struct SynHistory {
    initial_sequence: Option<u32>,
    payload_or_close: bool,
}

pub(super) fn finish(
    transports: Vec<Transport>,
    maximum: usize,
    budget: &mut SequenceBudget,
) -> Result<(Vec<TcpSession>, Vec<UdpMessage>, usize), ReconstructionError> {
    let mut active = BTreeMap::new();
    let mut episodes = Vec::new();
    let mut udp = Vec::new();
    let mut omitted = 0;
    for item in transports {
        if matches!(item.header, TransportHeader::Udp) {
            udp.push(UdpMessage {
                scope: item.scope,
                source: item.source,
                destination: item.destination,
                packet: item.packet,
                bytes: item.bytes,
                origins: item.origins,
                trailing_bytes: item.trailing_bytes,
                trailing_origins: item.trailing_origins,
                fragment_candidate: item.fragment_candidate,
            });
        } else if omitted != 0 || !append(item, &mut active, &mut episodes, maximum)? {
            // A skipped generation boundary makes all later TCP assignment unresolved
            omitted += 1;
        }
    }
    let sessions = episodes
        .into_iter()
        .map(|episode| episode.finish(budget))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((sessions, udp, omitted))
}

fn append(
    item: Transport,
    active: &mut BTreeMap<Key, usize>,
    episodes: &mut Vec<Episode>,
    maximum: usize,
) -> Result<bool, ReconstructionError> {
    let TransportHeader::Tcp {
        sequence, flags, ..
    } = item.header
    else {
        return Err(ReconstructionError(
            "TCP assignment received a UDP observation",
        ));
    };
    let endpoints = if item.source <= item.destination {
        [item.source.clone(), item.destination.clone()]
    } else {
        [item.destination.clone(), item.source.clone()]
    };
    let direction = usize::from(endpoints.first() != Some(&item.source));
    let key = Key {
        scope: item.scope.clone(),
        endpoints,
    };
    let previous = active.get(&key).copied();
    let initial_syn = flags & 0x17 == 0x02;
    let split = previous.is_none()
        || initial_syn
            && previous
                .and_then(|index| episodes.get(index))
                .is_some_and(|episode| episode.split_at_syn(direction, sequence));
    let index = if split {
        let reused = previous.is_some();
        if reused {
            for episode in episodes.iter_mut().filter(|episode| episode.key == key) {
                episode.generation_ambiguous = true;
            }
        }
        if episodes.len() == maximum {
            return Ok(false);
        }
        let index = episodes.len();
        episodes.push(Episode {
            key: key.clone(),
            packets: [Vec::new(), Vec::new()],
            generation_ambiguous: reused || !initial_syn || item.fragment_candidate.is_some(),
            syn_history: [SynHistory::default(); 2],
        });
        active.insert(key, index);
        index
    } else {
        previous.ok_or(ReconstructionError("missing active TCP episode"))?
    };
    let episode = episodes
        .get_mut(index)
        .ok_or(ReconstructionError("TCP episode index is absent"))?;
    episode.generation_ambiguous |= item.fragment_candidate.is_some();
    let history = episode
        .syn_history
        .get_mut(direction)
        .ok_or(ReconstructionError("TCP SYN history index is absent"))?;
    if initial_syn {
        history.initial_sequence = Some(sequence);
    }
    history.payload_or_close |= !item.bytes.is_empty() || flags & 5 != 0;
    episode
        .packets
        .get_mut(direction)
        .ok_or(ReconstructionError("TCP direction index is absent"))?
        .push(item);
    Ok(true)
}

impl Episode {
    fn split_at_syn(&self, direction: usize, sequence: u32) -> bool {
        let Some(packets) = self.packets.get(direction) else {
            return true;
        };
        if packets.is_empty() {
            return self.packets.iter().any(|items| !items.is_empty());
        }
        // A reused SYN after either direction progressed cannot identify one generation
        self.syn_history
            .iter()
            .any(|history| history.payload_or_close)
            || self
                .syn_history
                .get(direction)
                .is_none_or(|history| history.initial_sequence != Some(sequence))
    }

    fn finish(self, budget: &mut SequenceBudget) -> Result<TcpSession, ReconstructionError> {
        let [forward, reverse] = self.packets;
        let handshake = handshake::assess([&forward, &reverse]);
        let packets = forward.iter().chain(&reverse);
        let first_packet = packets
            .clone()
            .map(|packet| packet.packet)
            .min()
            .ok_or(ReconstructionError("empty TCP episode"))?;
        let reset_packets = packets
            .clone()
            .filter(
                |item| matches!(item.header, TransportHeader::Tcp { flags, .. } if flags & 4 != 0),
            )
            .map(|item| item.packet)
            .collect();
        let initiators: BTreeSet<_> = packets.filter(|item| matches!(item.header, TransportHeader::Tcp { flags, .. } if flags & 0x17 == 0x02)).map(|item| item.source.clone()).collect();
        let initiator = if initiators.len() == 1 {
            initiators.first().cloned()
        } else {
            None
        };
        let [left, right] = self.key.endpoints;
        let directions = [
            stream::finish(left.clone(), right.clone(), &forward, budget)?,
            stream::finish(right.clone(), left.clone(), &reverse, budget)?,
        ];
        Ok(TcpSession {
            scope: self.key.scope,
            endpoints: [left, right],
            first_packet,
            initiator,
            generation_ambiguous: self.generation_ambiguous,
            reset_packets,
            handshake,
            directions,
        })
    }
}
