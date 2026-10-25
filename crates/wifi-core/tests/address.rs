use wifi_core::MacAddress;

#[test]
fn group_unicast_addresses_distinct() {
    let unicast = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
    let multicast = MacAddress::new([0x01, 0, 0, 0, 0, 1]);
    let broadcast = MacAddress::new([0xff; 6]);
    let unspecified = MacAddress::new([0; 6]);

    assert!(!unicast.is_group());
    assert!(unicast.is_usable_unicast());
    assert!(multicast.is_group());
    assert!(!multicast.is_usable_unicast());
    assert!(broadcast.is_group());
    assert!(!broadcast.is_usable_unicast());
    assert!(!unspecified.is_group());
    assert!(!unspecified.is_usable_unicast());
}
