use l2_core::{EthernetFrame, FrameField, VlanTag};
use l2_discovery::{FingerprintStatus, Protocol, fingerprint};

pub const DESTINATION: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
pub const SOURCE: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

pub const fn ethernet(ether_type: u16, payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: DESTINATION,
        source: SOURCE,
        vlan_tags: Vec::<VlanTag>::new(),
        payload,
        padding: &[],
        field: FrameField::EtherType(ether_type),
    }
}

pub fn length_frame(payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: DESTINATION,
        source: SOURCE,
        vlan_tags: Vec::<VlanTag>::new(),
        payload,
        padding: &[],
        field: FrameField::Length(payload.len().try_into().unwrap_or(u16::MAX)),
    }
}

#[track_caller]
pub fn observed(frame: &EthernetFrame<'_>, protocol: Protocol) {
    let result = fingerprint(frame);
    assert_eq!(
        result,
        Some(l2_discovery::Fingerprint {
            protocol,
            status: FingerprintStatus::Observed,
        })
    );
}

#[track_caller]
pub fn status(frame: &EthernetFrame<'_>, protocol: Protocol, expected: FingerprintStatus) {
    let result = fingerprint(frame);
    assert_eq!(
        result,
        Some(l2_discovery::Fingerprint {
            protocol,
            status: expected,
        })
    );
}
