use std::{error::Error, net::Ipv4Addr, time::Duration};

use l2_active::{ArpProbe, Limits, validate_ipv4_target};
use l2_onpath::MacAddress;

use super::fixture::{LOCAL_IP, LOCAL_MAC, TARGET_IP, probe};

#[test]
fn one_untagged_arp_request_contains_the_selected_source_and_target() -> Result<(), Box<dyn Error>>
{
    let probe = probe(None, 10, 1024)?;
    let frame = l2_core::decode(probe.frame())?;
    let arp = l2_discovery::arp_packet(&frame).ok_or("missing ARP packet")?;
    assert_eq!(frame.destination, [0xff; 6]);
    assert_eq!(frame.source, LOCAL_MAC);
    assert_eq!(probe.frame().len(), 60);
    assert_eq!(arp.operation, 1);
    assert_eq!(arp.sender_mac, LOCAL_MAC);
    assert_eq!(arp.sender_ip, LOCAL_IP.octets());
    assert_eq!(arp.target_mac, [0; 6]);
    assert_eq!(arp.target_ip, TARGET_IP.octets());
    Ok(())
}

#[test]
fn invalid_target_and_insufficient_resource_limits_are_rejected() -> Result<(), Box<dyn Error>> {
    for address in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert!(validate_ipv4_target(address).is_err());
    }
    assert!(Limits::new(Duration::ZERO, 1, 60).is_err());
    assert!(Limits::new(Duration::from_secs(1), 0, 60).is_err());
    assert!(Limits::new(Duration::from_secs(1), 1, 0).is_err());
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    assert!(
        ArpProbe::new(
            MacAddress::new(LOCAL_MAC)?,
            LOCAL_IP,
            LOCAL_IP,
            None,
            limits
        )
        .is_err()
    );
    Ok(())
}
