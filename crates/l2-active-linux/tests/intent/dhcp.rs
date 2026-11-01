use super::Intent;
use crate::InterfaceInfo;
use l2_active::{Limits, dhcp::DhcpProbe};
use l2_onpath::MacAddress;
use std::{io, num::NonZeroU32, time::Duration};

fn fixture() -> Result<InterfaceInfo, Box<dyn std::error::Error>> {
    Ok(InterfaceInfo {
        name: "veth0".into(),
        identity: l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        mac: [2, 0, 0, 0, 0, 1],
        mtu: 1500,
        flags: 1,
        hardware_type: 1,
        assignments: Vec::new(),
        vlan: None,
    })
}

fn probe() -> Result<DhcpProbe, Box<dyn std::error::Error>> {
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let transaction = NonZeroU32::new(0x1234_5678).ok_or("zero transaction")?;
    let limits = Limits::new(Duration::from_secs(1), 10, 4096)?;
    Ok(DhcpProbe::new(mac, transaction, None, limits)?)
}

#[test]
fn discover_uses_the_actual_mac_without_requiring_an_ipv4_assignment()
-> Result<(), Box<dyn std::error::Error>> {
    let probe = probe()?;
    let intent = Intent::dhcp(&probe)?;
    intent.validate(&fixture()?)?;
    assert_eq!(intent.frame(), probe.frame());
    assert_eq!(intent.frame().len(), 342);
    Ok(())
}

#[test]
fn admission_rejects_a_vlan_with_header_reordering_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let mut info = fixture()?;
    info.vlan = Some(crate::VlanInfo {
        id: 37,
        protocol: crate::VlanProtocol::Ieee8021Q,
        parent: l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 6, 7)?,
        reorders_headers: false,
    });
    let error = Intent::dhcp(&probe()?)?
        .validate(&info)
        .err()
        .ok_or("reorder-off VLAN was accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}

#[test]
fn discover_rejects_a_foreign_mac_non_ethernet_link_or_small_mtu()
-> Result<(), Box<dyn std::error::Error>> {
    let intent = Intent::dhcp(&probe()?)?;
    let mut info = fixture()?;
    info.mac = [2, 0, 0, 0, 0, 2];
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    info.mac = [2, 0, 0, 0, 0, 1];
    info.hardware_type = 772;
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    info.hardware_type = 1;
    info.mtu = 327;
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}
