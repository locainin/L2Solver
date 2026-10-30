use super::Intent;
use l2_active::{Limits, NdpProbe};
use l2_onpath::MacAddress;
use std::{net::Ipv6Addr, time::Duration};

#[test]
fn typed_ndp_intent_retains_the_exact_prepared_solicitation()
-> Result<(), Box<dyn std::error::Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let source: Ipv6Addr = "fe80::1".parse()?;
    let target: Ipv6Addr = "fe80::2".parse()?;
    let limits = Limits::new(Duration::from_secs(1), 4, 4096)?;
    let probe = NdpProbe::new(mac, source, 64, target, None, limits)?;
    let intent = Intent::ndp(&probe)?;
    assert_eq!(intent.frame(), probe.frame());
    assert_eq!(intent.frame().len(), 86);
    Ok(())
}
