//! A bounded neighbor table and selected protocol framing rules

use l2_canary::AgentId;
use l2_codecs::Validity;
use l2_core::FrameField;

use super::model::{Identity, Observed, Protocol};

const LLDP_DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
const CDP_DESTINATION: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
const CDP_SNAP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
const MAX_CDP_TLVS: usize = 128;
const MAX_CDP_ID_LEN: usize = 255;

#[derive(Clone, Copy)]
struct Neighbor<'a> {
    source: AgentId,
    protocol: Protocol,
    identity: Identity<'a>,
    expires_at: u64,
}

#[derive(Clone, Copy)]
struct Advertisement<'a> {
    identity: Identity<'a>,
    hold_seconds: u16,
}

pub(super) struct Receiver<'a> {
    neighbors: Vec<Neighbor<'a>>,
}

impl<'a> Receiver<'a> {
    pub(super) fn new(capacity: usize) -> Result<Self, super::DiscoveryError> {
        let mut neighbors = Vec::new();
        neighbors
            .try_reserve_exact(capacity)
            .map_err(|_| super::DiscoveryError::Allocation)?;
        Ok(Self { neighbors })
    }

    pub(super) const fn count(&self) -> usize {
        self.neighbors.len()
    }

    pub(super) fn clear(&mut self) {
        self.neighbors.clear();
    }

    pub(super) fn receive(
        &mut self,
        source: AgentId,
        protocol: Protocol,
        wire: &'a [u8],
        at_millis: u64,
    ) -> (Observed<'a>, Option<Identity<'a>>, Option<Identity<'a>>) {
        // Expired neighbors disappear before the next scheduled delivery
        self.neighbors
            .retain(|neighbor| neighbor.expires_at > at_millis);
        let before = self.identity(source, protocol);
        let Some(advertisement) = parse(protocol, wire) else {
            return (Observed::Rejected, before, before);
        };
        let identity = advertisement.identity;
        if advertisement.hold_seconds == 0 {
            // A shutdown cannot withdraw a different identity on the same port
            self.neighbors.retain(|neighbor| {
                !(neighbor.source == source
                    && neighbor.protocol == protocol
                    && neighbor.identity == identity)
            });
            return (
                Observed::Withdrawn(identity),
                before,
                self.identity(source, protocol),
            );
        }

        // Admitted time and protocol TTL maxima keep this addition in range
        let expires_at = at_millis + u64::from(advertisement.hold_seconds) * 1_000;
        if let Some(neighbor) = self
            .neighbors
            .iter_mut()
            .find(|item| item.source == source && item.protocol == protocol)
        {
            neighbor.identity = identity;
            neighbor.expires_at = expires_at;
        } else {
            self.neighbors.push(Neighbor {
                source,
                protocol,
                identity,
                expires_at,
            });
        }
        (Observed::Accepted(identity), before, Some(identity))
    }

    fn identity(&self, source: AgentId, protocol: Protocol) -> Option<Identity<'a>> {
        self.neighbors
            .iter()
            .find(|item| item.source == source && item.protocol == protocol)
            .map(|item| item.identity)
    }
}

fn parse(protocol: Protocol, wire: &[u8]) -> Option<Advertisement<'_>> {
    let frame = l2_core::decode(wire).ok()?;
    // The model accepts untagged link-local advertisements from unicast sources
    if !valid_link_source(&frame) {
        return None;
    }
    match protocol {
        Protocol::Lldp
            if frame.destination == LLDP_DESTINATION
                && frame.field == FrameField::EtherType(0x88cc) =>
        {
            parse_lldp(frame.payload)
        }
        Protocol::Cdp
            if frame.destination == CDP_DESTINATION
                && matches!(frame.field, FrameField::Length(_)) =>
        {
            let payload = frame.payload.strip_prefix(&CDP_SNAP)?;
            parse_cdp(payload)
        }
        Protocol::Lldp | Protocol::Cdp => None,
    }
}

fn valid_link_source(frame: &l2_core::EthernetFrame<'_>) -> bool {
    let [first, ..] = frame.source;
    frame.vlan_tags.is_empty() && frame.source != [0; 6] && first & 1 == 0
}

fn parse_lldp(payload: &[u8]) -> Option<Advertisement<'_>> {
    let frame = l2_codecs::decode_lldp(payload).ok()?;
    if frame.validity != Validity::Valid {
        return None;
    }
    // The canonical codec validates order, uniqueness, subtype, and TTL length
    let device = frame.tlvs.iter().find(|tlv| tlv.kind == 1)?.value;
    let port = frame.tlvs.iter().find(|tlv| tlv.kind == 2)?.value;
    let ttl: [u8; 2] = frame
        .tlvs
        .iter()
        .find(|tlv| tlv.kind == 3)?
        .value
        .try_into()
        .ok()?;
    Some(Advertisement {
        identity: Identity::new(device, port),
        hold_seconds: u16::from_be_bytes(ttl),
    })
}

fn parse_cdp(payload: &[u8]) -> Option<Advertisement<'_>> {
    let (header, remaining) = payload.split_first_chunk::<4>()?;
    let [version, hold, _, _] = *header;
    if !matches!(version, 1 | 2) || !cdp_checksum_valid(payload) {
        return None;
    }
    Some(Advertisement {
        identity: cdp_identity(remaining)?,
        hold_seconds: u16::from(hold),
    })
}

fn cdp_identity(mut remaining: &[u8]) -> Option<Identity<'_>> {
    let mut device = None;
    let mut port = None;
    let mut count = 0;
    while !remaining.is_empty() {
        count += 1;
        if count > MAX_CDP_TLVS {
            return None;
        }
        let (kind, value, next) = cdp_tlv(remaining)?;
        remaining = next;
        record_cdp_identity(kind, value, &mut device, &mut port)?;
    }
    Some(Identity::new(device?, port?))
}

fn cdp_tlv(input: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let (header, body) = input.split_first_chunk::<4>()?;
    let [type_high, type_low, length_high, length_low] = *header;
    let kind = u16::from_be_bytes([type_high, type_low]);
    let length = usize::from(u16::from_be_bytes([length_high, length_low]));
    let (value, remaining) = body.split_at_checked(length.checked_sub(4)?)?;
    Some((kind, value, remaining))
}

const fn record_cdp_identity<'a>(
    kind: u16,
    value: &'a [u8],
    device: &mut Option<&'a [u8]>,
    port: &mut Option<&'a [u8]>,
) -> Option<()> {
    // Identity TLVs are unique and bounded; unknown types remain opaque
    let slot = match kind {
        1 => device,
        3 => port,
        _ => return Some(()),
    };
    if slot.is_some() || value.is_empty() || value.len() > MAX_CDP_ID_LEN {
        return None;
    }
    *slot = Some(value);
    Some(())
}

fn cdp_checksum_valid(payload: &[u8]) -> bool {
    let mut pairs = payload.chunks_exact(2);
    let mut sum = 0_u32;
    for pair in &mut pairs {
        if let [high, low] = *pair {
            sum += u32::from(u16::from_be_bytes([high, low]));
        }
    }
    if let [last] = pairs.remainder() {
        // CDP uses a signed low octet for an odd final byte, unlike IP padding
        sum += if *last >= 0x80 {
            0xff00 | u32::from(*last - 1)
        } else {
            u32::from(*last)
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}
