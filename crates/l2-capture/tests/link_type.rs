use l2_capture::{CaptureMetadata, InterfaceId, LinkType};

#[test]
fn maps_datalinks_and_bounds_unknown() {
    assert_eq!(LinkType::from_raw(1), LinkType::Ethernet);
    assert_eq!(LinkType::from_raw(105), LinkType::Ieee80211);
    assert_eq!(LinkType::from_raw(127), LinkType::Ieee80211Radiotap);
    assert_eq!(LinkType::from_raw(u16::MAX), LinkType::Unknown(u16::MAX));

    assert_eq!(LinkType::Ethernet.raw(), 1);
    assert_eq!(LinkType::Ieee80211.raw(), 105);
    assert_eq!(LinkType::Ieee80211Radiotap.raw(), 127);
    assert_eq!(LinkType::Unknown(0x1234).raw(), 0x1234);
}

#[test]
fn unknown_link_type_not_ethernet() {
    assert!(LinkType::Ethernet.is_supported());
    assert!(LinkType::Ieee80211.is_supported());
    assert!(LinkType::Ieee80211Radiotap.is_supported());
    assert!(!LinkType::Unknown(101).is_supported());
    assert!(!LinkType::Unknown(101).is_ethernet());
    assert!(!LinkType::Ethernet.is_wireless());
    assert!(LinkType::Ieee80211.is_wireless());
    assert!(LinkType::Ieee80211Radiotap.is_wireless());
    assert!(!LinkType::Unknown(127).is_wireless());
}

#[test]
fn metadata_keeps_checked_link_type() {
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 2,
            index: 4,
        },
        12,
        None,
        None,
        l2_capture::Direction::Unknown,
        None,
        l2_capture::FcsStatus::Unknown,
    )
    .with_link_type(LinkType::Ieee80211Radiotap);

    assert_eq!(metadata.link_type(), LinkType::Ieee80211Radiotap);
}
