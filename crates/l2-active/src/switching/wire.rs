//! Recognize the explicitly selected untagged Cisco multicast profile

use l2_core::FrameField;

const DESTINATION: [u8; 6] = [1, 0, 0x0c, 0xcc, 0xcc, 0xcc];
const SNAP_LENGTH: usize = 8;
const ETHERNET_LENGTH: usize = 14;

pub(super) enum Candidate<'a> {
    Payload { source: [u8; 6], bytes: &'a [u8] },
    MalformedEnvelope,
}

pub(super) fn classify(frame: &[u8], protocol: u16) -> Option<Candidate<'_>> {
    let [high, low] = protocol.to_be_bytes();
    let expected_snap = [0xaa, 0xaa, 3, 0, 0, 0x0c, high, low];
    if let Ok(ethernet) = l2_core::decode(frame) {
        if ethernet.destination != DESTINATION
            || !ethernet.vlan_tags.is_empty()
            || !matches!(ethernet.field, FrameField::Length(_))
        {
            return None;
        }
        let bytes = ethernet.payload.strip_prefix(&expected_snap)?;
        Some(Candidate::Payload {
            source: ethernet.source,
            bytes,
        })
    } else {
        // Report a broken declared length only when its full protocol signature is in scope
        let destination = frame.get(..6)?;
        let field = <[u8; 2]>::try_from(frame.get(12..14)?).ok()?;
        let declared = usize::from(u16::from_be_bytes(field));
        let snap = frame.get(ETHERNET_LENGTH..ETHERNET_LENGTH + SNAP_LENGTH)?;
        if destination == DESTINATION
            && (SNAP_LENGTH..=1500).contains(&declared)
            && snap == expected_snap
        {
            Some(Candidate::MalformedEnvelope)
        } else {
            None
        }
    }
}

pub(super) fn valid_source(source: [u8; 6]) -> bool {
    let [first, ..] = source;
    source != [0; 6] && first & 1 == 0
}
