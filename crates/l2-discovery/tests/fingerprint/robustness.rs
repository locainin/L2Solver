use super::cisco_snap::snap;
use super::common::{DESTINATION, SOURCE, ethernet};
use super::ipv4::{ipv4_protocol, ipv4_udp};
use super::ipv6::ipv6_packet;
use l2_core::{EthernetFrame, FrameField, decode};
use l2_discovery::fingerprint;

#[test]
fn all_parsers_handle_captured_prefixes() {
    let mut arp = vec![0, 1, 0x08, 0, 6, 4, 0, 1];
    arp.extend(std::iter::repeat_n(0, 20));
    let mut macsec = vec![0, 0, 0, 0, 0, 1];
    macsec.extend(std::iter::repeat_n(0, 16));
    let mut ra = vec![134, 0, 0, 0];
    ra.extend(std::iter::repeat_n(0, 12));
    let payloads = [
        (FrameField::EtherType(0x888e), vec![2, 0, 0, 0, 1]),
        (FrameField::EtherType(0x8809), vec![1, 1, 0]),
        (FrameField::EtherType(0x88e5), macsec),
        (FrameField::EtherType(0x0806), arp),
        (
            FrameField::EtherType(0x0800),
            ipv4_udp(68, 67, 8, 20, 0, &[]),
        ),
        (
            FrameField::EtherType(0x0800),
            ipv4_protocol(112, &[0x21, 1, 100, 0, 0, 1, 0, 0]),
        ),
        (FrameField::EtherType(0x86dd), ipv6_packet(58, &ra)),
        (FrameField::Length(8), snap(0x2000, &[])),
    ];

    for (field, payload) in payloads {
        for end in 0..=payload.len() {
            let Some(prefix) = payload.get(..end) else {
                continue;
            };
            let prefix_frame = EthernetFrame {
                destination: DESTINATION,
                source: SOURCE,
                vlan_tags: Vec::new(),
                payload: prefix,
                padding: &[],
                field,
            };
            let result = std::panic::catch_unwind(|| fingerprint(&prefix_frame));
            assert!(result.is_ok(), "fingerprint panicked at {end} bytes");
        }
    }
}

#[test]
fn ignores_length_and_unknown_protocols() {
    let bytes = [
        DESTINATION.as_slice(),
        SOURCE.as_slice(),
        0x00_u16.to_be_bytes().as_slice(),
    ]
    .concat();
    let Ok(frame) = decode(&bytes) else {
        return;
    };
    assert_eq!(fingerprint(&frame), None);
    assert_eq!(fingerprint(&ethernet(0x1234, &[0; 64])), None);
}
