use super::Transport;
use l2_discovery::TransportHeader;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_WITNESSES: usize = 64;

/// Classification of acknowledgement relationships visible in capture order
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    #[default]
    NoInitialSyn,
    InitialSynOnly,
    SynSynAckObserved,
    ThreeWayObserved,
    Ambiguous,
}

#[derive(Debug, Serialize)]
pub struct HandshakeMatch {
    pub initiator_direction: usize,
    pub syn_packet: u32,
    pub synack_packet: u32,
    pub ack_packet: Option<u32>,
    pub initiator_next_sequence: u32,
    pub responder_next_sequence: u32,
}

/// Packet relationships qualify observations without proving delivery or peer state
#[derive(Debug, Default, Serialize)]
pub struct HandshakeAssessment {
    pub status: HandshakeStatus,
    pub matches: Vec<HandshakeMatch>,
    pub mismatched_synack_packets: Vec<u32>,
    pub omitted_observations: usize,
}

pub(super) fn assess(directions: [&[Transport]; 2]) -> HandshakeAssessment {
    let mut report = HandshakeAssessment::default();
    let mut initial = BTreeMap::new();
    for (direction, packets) in directions.iter().enumerate() {
        for packet in *packets {
            if let Some((sequence, _, flags)) = tcp(packet)
                && flags & 0x17 == 2
            {
                let key = (direction, sequence, packet.bytes.len());
                // Episode assignment allows repeated SYNs and at most their first payload variant
                // A changed sequence, opposite initial direction, or later progress starts a new episode
                initial.entry(key).or_insert(packet);
            }
        }
    }
    let mut mismatched = BTreeSet::new();
    let mut matched = BTreeSet::new();
    for ((direction, _, _), syn) in &initial {
        if let (Some(client), Some(server)) =
            (directions.get(*direction), directions.get(1 - *direction))
        {
            match_syn(
                *direction,
                syn,
                client,
                server,
                &mut report,
                &mut mismatched,
                &mut matched,
            );
        }
    }
    for packet in mismatched.difference(&matched) {
        if report.mismatched_synack_packets.len() == MAX_WITNESSES {
            report.omitted_observations += 1;
        } else {
            report.mismatched_synack_packets.push(*packet);
        }
    }
    report.status = if report.omitted_observations != 0 || report.matches.len() > 1 {
        HandshakeStatus::Ambiguous
    } else if report
        .matches
        .first()
        .is_some_and(|item| item.ack_packet.is_some())
    {
        HandshakeStatus::ThreeWayObserved
    } else if !report.matches.is_empty() {
        HandshakeStatus::SynSynAckObserved
    } else if !initial.is_empty() {
        HandshakeStatus::InitialSynOnly
    } else {
        HandshakeStatus::NoInitialSyn
    };
    report
}

fn match_syn(
    direction: usize,
    syn: &Transport,
    client: &[Transport],
    server: &[Transport],
    report: &mut HandshakeAssessment,
    mismatched: &mut BTreeSet<u32>,
    matched: &mut BTreeSet<u32>,
) {
    let Some(next_client) = next_sequence(syn) else {
        return;
    };
    let mut replies = BTreeSet::new();
    for reply in server {
        let Some((sequence, acknowledgement, flags)) = tcp(reply) else {
            continue;
        };
        if reply.packet <= syn.packet || flags & 0x17 != 0x12 {
            continue;
        }
        if acknowledgement != next_client {
            mismatched.insert(reply.packet);
            continue;
        }
        matched.insert(reply.packet);
        // Identical SYN/ACK retransmissions supply one relationship witness
        if !replies.insert((sequence, reply.bytes.len())) {
            continue;
        }
        if report.matches.len() == MAX_WITNESSES {
            report.omitted_observations += 1;
            continue;
        }
        let Some(next_server) = next_sequence(reply) else {
            continue;
        };
        let ack_packet = client
            .iter()
            .find(|packet| {
                packet.packet > reply.packet
                    && tcp(packet).is_some_and(|(seq, ack, bits)| {
                        bits & 0x16 == 0x10 && seq == next_client && ack == next_server
                    })
            })
            .map(|packet| packet.packet);
        report.matches.push(HandshakeMatch {
            initiator_direction: direction,
            syn_packet: syn.packet,
            synack_packet: reply.packet,
            ack_packet,
            initiator_next_sequence: next_client,
            responder_next_sequence: next_server,
        });
    }
}

const fn tcp(packet: &Transport) -> Option<(u32, u32, u8)> {
    if let TransportHeader::Tcp {
        sequence,
        acknowledgement,
        flags,
        ..
    } = packet.header
    {
        Some((sequence, acknowledgement, flags))
    } else {
        None
    }
}

fn next_sequence(packet: &Transport) -> Option<u32> {
    let (sequence, _, _) = tcp(packet)?;
    // SYN occupies one sequence number; payload also occupies sequence space
    Some(
        sequence
            .wrapping_add(u32::try_from(packet.bytes.len()).ok()?)
            .wrapping_add(1),
    )
}
