use super::common::{length_frame, observed};
use l2_discovery::{FingerprintStatus, Protocol, fingerprint};

pub fn snap(pid: u16, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c];
    packet.extend_from_slice(&pid.to_be_bytes());
    packet.extend_from_slice(body);
    packet
}

#[test]
fn recognizes_cisco_snap_protocols() {
    for (pid, protocol) in [
        (0x2000, Protocol::Cdp),
        (0x2004, Protocol::Dtp),
        (0x2003, Protocol::Vtp),
        (0x0104, Protocol::Pagp),
        (0x010b, Protocol::PvstPlus),
    ] {
        observed(&length_frame(&snap(pid, &[])), protocol);
    }
    assert_eq!(
        fingerprint(&length_frame(&snap(0x9999, &[]))),
        Some(l2_discovery::Fingerprint {
            protocol: Protocol::CiscoSnap,
            status: FingerprintStatus::Unsupported,
        })
    );
    assert_eq!(
        fingerprint(&length_frame(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c])),
        Some(l2_discovery::Fingerprint {
            protocol: Protocol::CiscoSnap,
            status: FingerprintStatus::Truncated,
        })
    );
    assert_eq!(
        fingerprint(&length_frame(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20])),
        Some(l2_discovery::Fingerprint {
            protocol: Protocol::CiscoSnap,
            status: FingerprintStatus::Truncated,
        })
    );
    assert_eq!(
        fingerprint(&length_frame(&[0xaa, 0xaa, 0x03, 0, 0, 0x0d, 0x20, 0])),
        None
    );
    for length in 0..8 {
        assert_eq!(fingerprint(&length_frame(&vec![0; length])), None);
    }
}
