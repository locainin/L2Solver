use l2_discovery::{FingerprintStatus, IdentityRole, NetworkAddress};

#[test]
fn status_role_labels_stable() {
    // Status labels are embedded in operator reports and machine-readable output
    for (status, expected) in [
        (FingerprintStatus::Observed, "observed"),
        (FingerprintStatus::Malformed, "malformed"),
        (FingerprintStatus::Truncated, "truncated"),
        (FingerprintStatus::Unsupported, "unsupported"),
    ] {
        assert_eq!(status.as_str(), expected);
        assert_eq!(status.to_string(), expected);
    }

    // Role labels explain the conservative identity classification
    for (role, expected) in [
        (
            IdentityRole::AccessControlParticipant,
            "access-control participant",
        ),
        (IdentityRole::AddressClaim, "address claim"),
        (
            IdentityRole::AggregationParticipant,
            "aggregation participant",
        ),
        (
            IdentityRole::ControlPlaneParticipant,
            "control-plane participant",
        ),
        (IdentityRole::DhcpClient, "DHCP client"),
        (IdentityRole::DhcpServer, "DHCP server"),
        (IdentityRole::Dhcpv6Participant, "DHCPv6 participant"),
        (IdentityRole::FirstHopRouter, "first-hop router participant"),
        (
            IdentityRole::Ipv6Neighbor,
            "IPv6 neighbor-discovery participant",
        ),
        (IdentityRole::Ipv6Router, "IPv6 router"),
        (
            IdentityRole::LinkSecurityParticipant,
            "link-security participant",
        ),
        (IdentityRole::MulticastParticipant, "multicast participant"),
    ] {
        assert_eq!(role.as_str(), expected);
        assert_eq!(role.to_string(), expected);
    }
}

#[test]
fn network_addresses_standard_text_forms() {
    // Both address families retain their normal diagnostic spelling
    assert_eq!(
        NetworkAddress::Ipv4([192, 0, 2, 7]).to_string(),
        "192.0.2.7"
    );
    assert_eq!(
        NetworkAddress::Ipv6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]).to_string(),
        "fe80::1"
    );
}
