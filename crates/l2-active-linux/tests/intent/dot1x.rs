use super::Intent;
use crate::InterfaceInfo;
use l2_active::{Limits, dot1x::Dot1xProbe};
use l2_onpath::MacAddress;
use std::{error::Error, io, time::Duration};

fn interface() -> Result<InterfaceInfo, Box<dyn Error>> {
    Ok(InterfaceInfo {
        name: "veth0".into(),
        identity: l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        mac: [2, 0, 0, 0, 0, 1],
        mtu: 1_500,
        flags: 0x1001,
        hardware_type: 1,
        assignments: Vec::new(),
        vlan: None,
    })
}

fn intent() -> Result<Intent, Box<dyn Error>> {
    let probe = Dot1xProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        Limits::new(Duration::from_secs(1), 10, 4_096)?,
    )?;
    Ok(Intent::dot1x(&probe)?)
}

#[test]
fn start_admission_accepts_the_selected_mac_without_any_ip_assignment() -> Result<(), Box<dyn Error>>
{
    let info = interface()?;
    assert!(info.ipv4_assignments().is_empty());
    intent()?.validate(&info)?;
    Ok(())
}

#[test]
fn start_admission_rejects_a_different_mac_or_down_interface() -> Result<(), Box<dyn Error>> {
    let mut info = interface()?;
    let intent = intent()?;
    info.mac = [2, 0, 0, 0, 0, 2];
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    info.mac = [2, 0, 0, 0, 0, 1];
    info.flags = 0;
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::NotConnected)
    );
    Ok(())
}

#[test]
fn start_admission_requires_ethernet_and_a_sufficient_payload_mtu() -> Result<(), Box<dyn Error>> {
    let mut info = interface()?;
    let intent = intent()?;
    info.hardware_type = 772;
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    info.hardware_type = 1;
    info.mtu = 45;
    assert_eq!(
        intent.validate(&info).err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    info.mtu = 46;
    intent.validate(&info)?;
    Ok(())
}

#[test]
fn start_admission_requires_multicast_capability() -> Result<(), Box<dyn Error>> {
    let mut info = interface()?;
    info.flags = 1;
    let error = intent()?
        .validate(&info)
        .err()
        .ok_or("an interface without multicast must be rejected")?;
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}
