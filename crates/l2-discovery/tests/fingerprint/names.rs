use l2_discovery::{FingerprintStatus, Protocol};

#[test]
fn protocol_names_are_stable() {
    assert_eq!(Protocol::Eapol.to_string(), "EAPOL");
    assert_eq!(Protocol::Ipv6Ra.to_string(), "IPv6 RA");
    assert_eq!(Protocol::PvstPlus.to_string(), "PVST+");
    assert_eq!(
        serde_json::to_string(&Protocol::Dhcpv6).unwrap_or_default(),
        "\"dhcpv6\""
    );
    assert_eq!(
        serde_json::to_string(&FingerprintStatus::Truncated).unwrap_or_default(),
        "\"truncated\""
    );
    assert_eq!(
        serde_json::to_string(&FingerprintStatus::Unsupported).unwrap_or_default(),
        "\"unsupported\""
    );
}
