use std::{error::Error, net::Ipv6Addr, time::Duration};

use l2_active::{Limits, NdpPlanError, NdpProbe};
use l2_onpath::MacAddress;

const REQUEST: [u8; 86] = [
    0x33, 0x33, 0xff, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xdd, 0x60, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0xff, 0x00, 0x00, 0x02, 0x87, 0x00, 0x7a, 0x97, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn limits() -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(20), 64, 8192)?)
}

#[test]
fn solicitation_uses_the_solicited_node_addresses_and_valid_checksum() -> Result<(), Box<dyn Error>>
{
    let selected_limits = limits()?;
    let probe = NdpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        "fe80::1".parse()?,
        64,
        "fe80::2".parse()?,
        None,
        selected_limits,
    )?;
    // This independently constructed frame includes the IPv6 pseudo-header checksum
    assert_eq!(probe.frame(), REQUEST);
    assert_eq!(probe.source_mac(), MacAddress::new([2, 0, 0, 0, 0, 1])?);
    assert_eq!(probe.source_ip(), "fe80::1".parse::<Ipv6Addr>()?);
    assert_eq!(probe.prefix_len(), 64);
    assert_eq!(probe.target(), "fe80::2".parse::<Ipv6Addr>()?);
    assert_eq!(probe.expected(), None);
    assert_eq!(probe.limits(), selected_limits);
    Ok(())
}

#[test]
fn plan_errors_describe_the_rejected_scope_and_preserve_encoder_cause() {
    for (error, detail) in [
        (NdpPlanError::InvalidAddress, "IPv6"),
        (NdpPlanError::SameAddress, "source"),
        (NdpPlanError::InvalidPrefix, "prefix"),
        (NdpPlanError::TargetOffLink, "on-link"),
    ] {
        assert!(error.to_string().contains(detail));
        assert!(error.source().is_none());
    }
    let encoding = NdpPlanError::Encode(l2_core::EncodeError::BufferTooShort {
        needed: 86,
        available: 0,
    });
    assert!(encoding.to_string().contains("encode"));
    assert!(encoding.source().is_some());
}

#[test]
fn non_unicast_or_self_addresses_are_rejected() -> Result<(), Box<dyn Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let source: Ipv6Addr = "fe80::1".parse()?;
    let target: Ipv6Addr = "fe80::2".parse()?;
    for bad in ["::", "::1", "ff02::1", "::ffff:192.0.2.1", "::192.0.2.1"] {
        let bad = bad.parse()?;
        assert!(matches!(
            NdpProbe::new(mac, bad, 64, target, None, limits()?),
            Err(NdpPlanError::InvalidAddress)
        ));
        assert!(matches!(
            NdpProbe::new(mac, source, 64, bad, None, limits()?),
            Err(NdpPlanError::InvalidAddress)
        ));
    }
    assert!(matches!(
        NdpProbe::new(mac, source, 64, source, None, limits()?),
        Err(NdpPlanError::SameAddress)
    ));
    Ok(())
}

#[test]
fn target_must_be_in_the_selected_source_prefix() -> Result<(), Box<dyn Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let source: Ipv6Addr = "2001:db8:1::1".parse()?;
    let target: Ipv6Addr = "2001:db8:2::2".parse()?;
    assert!(matches!(
        NdpProbe::new(mac, source, 64, target, None, limits()?),
        Err(NdpPlanError::TargetOffLink)
    ));
    for prefix in [0, 129] {
        assert!(matches!(
            NdpProbe::new(mac, source, prefix, target, None, limits()?),
            Err(NdpPlanError::InvalidPrefix)
        ));
    }
    Ok(())
}

#[test]
fn non_octet_prefix_boundary_is_checked_exactly() -> Result<(), Box<dyn Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let source = "2001:db8::4000:0:0:1".parse()?;
    let target = "2001:db8::c000:0:0:2".parse()?;
    assert!(matches!(
        NdpProbe::new(mac, source, 65, target, None, limits()?),
        Err(NdpPlanError::TargetOffLink)
    ));
    assert!(NdpProbe::new(mac, source, 64, target, None, limits()?).is_ok());
    Ok(())
}
