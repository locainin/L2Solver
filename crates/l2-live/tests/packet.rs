#[path = "../src/metadata.rs"]
mod metadata;
#[path = "../src/packet.rs"]
mod packet;

use l2_capture::LinkType;

const fn source()
-> Result<l2_capture::LinuxInterfaceIdentity, l2_capture::LinuxInterfaceIdentityError> {
    l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)
}

#[test]
fn invalid_live_lengths_rejected_copying() -> Result<(), Box<dyn std::error::Error>> {
    let source = source()?;
    assert!(
        packet::capture_with_link_type(source, LinkType::Ethernet, &[0; 3], 2, 3, 0, 0).is_err()
    );
    assert!(
        packet::capture_with_link_type(source, LinkType::Ethernet, &[0; 3], 3, 2, 0, 0).is_err()
    );
    let oversized = vec![0; l2_capture::MAX_FRAME_LENGTH + 1];
    assert!(
        packet::capture_with_link_type(
            source,
            LinkType::Ethernet,
            &oversized,
            65_536,
            65_536,
            0,
            0
        )
        .is_err()
    );
    assert!(packet::capture_with_link_type(source, LinkType::Ethernet, &[], 0, 0, -1, 0).is_err());
    Ok(())
}

#[test]
fn live_conversion_bytes_truncation() -> Result<(), Box<dyn std::error::Error>> {
    let source = source()?;
    let frame = packet::capture_with_link_type(
        source,
        l2_capture::LinkType::Ethernet,
        &[1, 2, 3],
        3,
        4,
        1,
        2,
    )?;
    assert_eq!(frame.bytes(), &[1, 2, 3]);
    assert!(frame.is_truncated());
    assert_eq!(frame.metadata().linux_interface(), Some(source));
    assert_eq!(frame.metadata().direction(), l2_capture::Direction::Unknown);
    assert_eq!(
        frame
            .metadata()
            .timestamp()
            .map(l2_capture::CaptureTimestamp::ticks),
        Some(1_000_002)
    );
    assert_eq!(frame.metadata().fcs(), l2_capture::FcsStatus::Unknown);
    assert!(frame.metadata().vlan().is_none());
    let maximal = vec![0; l2_capture::MAX_FRAME_LENGTH];
    assert!(
        packet::capture_with_link_type(source, LinkType::Ethernet, &maximal, 65_535, 65_535, 0, 0,)
            .is_ok()
    );
    Ok(())
}
