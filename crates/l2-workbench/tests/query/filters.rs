use l2_workbench::query::{IpCidr, IpDirection, Selector};

#[test]
fn filter_parser_explicit_bounded_values() -> Result<(), Box<dyn std::error::Error>> {
    let selector = Selector::parse(&[
        "ip=192.0.2.0/24",
        "ip_direction=destination",
        "protocol=tcp",
        "dport=443",
        "packet=10..20",
        "interface=2:4",
        "vlan=37",
        "kind=packet",
        "status=observed",
    ])?;

    assert_eq!(selector.ip_direction, IpDirection::Destination);
    assert_eq!(selector.destination_port, Some(443));
    assert_eq!(
        selector.packet_range.map(|range| (range.first, range.last)),
        Some((10, 20))
    );
    assert_eq!(
        selector.interface.map(|scope| (scope.section, scope.index)),
        Some((2, 4))
    );
    assert_eq!(selector.vlan, Some(37));
    Ok(())
}

#[test]
fn filter_parser_protocol_names_numbers() -> Result<(), Box<dyn std::error::Error>> {
    for protocol in ["arp", "icmp", "icmpv6", "1", "58", "255"] {
        let selector = Selector::parse(&[&format!("proto={protocol}")])?;
        assert_eq!(selector.protocol.as_deref(), Some(protocol));
    }
    Ok(())
}

#[test]
fn filter_parser_packet_field_values() -> Result<(), Box<dyn std::error::Error>> {
    let selector = Selector::parse(&["ip=192.0.2.10", "time=12..20", "field.ip.proto=1"])?;
    let exact_address = "192.0.2.10".parse()?;

    assert!(
        selector
            .ip
            .is_some_and(|network| network.contains(exact_address))
    );
    assert_eq!(
        selector.time_range.map(|range| (range.first, range.last)),
        Some((12, 20))
    );
    assert_eq!(
        selector
            .fields
            .first()
            .map(|field| (field.name.as_str(), field.value.as_str())),
        Some(("ip.proto", "1"))
    );
    Ok(())
}

#[test]
fn filter_parser_expressions_invalid_bounds() {
    for filters in [
        vec!["unknown=value"],
        vec!["ip=192.0.2.1/24; true"],
        vec!["protocol=sctp"],
        vec!["protocol=256"],
        vec!["field.ip.src;true=192.0.2.1"],
        vec!["time=20..12"],
        vec!["time=1.5..2"],
        vec!["port=65536"],
        vec!["packet=20..10"],
        vec!["vlan=4095"],
        vec!["kind=packet", "kind=tcp_episode"],
    ] {
        assert!(Selector::parse(&filters).is_err(), "accepted {filters:?}");
    }

    let too_many = vec!["kind=packet"; 33];
    let too_long_kind = format!("kind={}", "a".repeat(65));
    assert!(Selector::parse(&too_many).is_err());
    assert!(Selector::parse(&[&too_long_kind]).is_err());
    assert!(Selector::parse(&["src=192.0.2.0/24", "source=192.0.2.0/24"]).is_err());
}

#[test]
fn cidr_matching_family_prefix_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let ipv4 = IpCidr::parse("192.0.2.0/24")?;
    let ipv6 = IpCidr::parse("2001:db8::/32")?;

    assert!(ipv4.contains("192.0.2.99".parse()?));
    assert!(!ipv4.contains("192.0.3.1".parse()?));
    assert!(!ipv4.contains("2001:db8::1".parse()?));
    assert!(ipv6.contains("2001:db8::1".parse()?));
    assert!(IpCidr::parse("0.0.0.0/0").is_ok());
    assert!(IpCidr::parse("::/0").is_ok());
    assert!(IpCidr::parse("192.0.2.1/33").is_err());
    assert!(IpCidr::parse("192.0.2.1")?.contains("192.0.2.1".parse()?));
    Ok(())
}
