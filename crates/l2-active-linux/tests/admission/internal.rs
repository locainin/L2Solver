use super::select_arp_source;
use crate::{InterfaceInfo, Ipv4Assignment};
use std::{io, net::Ipv4Addr};

fn fixture() -> Result<InterfaceInfo, Box<dyn std::error::Error>> {
    Ok(InterfaceInfo {
        name: "veth0".into(),
        identity: l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        mac: [2, 0, 0, 0, 0, 1],
        mtu: 1500,
        flags: 1,
        hardware_type: 1,
        assignments: vec![Ipv4Assignment {
            address: Ipv4Addr::new(192, 0, 2, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
        }],
        vlan: None,
    })
}

#[test]
fn one_on_link_source_is_selected_without_a_guess() -> Result<(), Box<dyn std::error::Error>> {
    let info = fixture()?;
    assert_eq!(
        select_arp_source(&info, None, Ipv4Addr::new(192, 0, 2, 2))?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    Ok(())
}

#[test]
fn nonlocal_unassigned_and_broadcast_targets_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let info = fixture()?;
    for target in [
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(192, 0, 2, 0),
        Ipv4Addr::new(192, 0, 2, 255),
    ] {
        assert_eq!(
            select_arp_source(&info, None, target)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let result = select_arp_source(
        &info,
        Some(Ipv4Addr::new(192, 0, 2, 99)),
        Ipv4Addr::new(192, 0, 2, 2),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[test]
fn multiple_sources_require_an_explicit_assigned_address() -> Result<(), Box<dyn std::error::Error>>
{
    let mut info = fixture()?;
    info.assignments.push(Ipv4Assignment {
        address: Ipv4Addr::new(192, 0, 2, 3),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
    });
    assert_eq!(
        select_arp_source(&info, None, Ipv4Addr::new(192, 0, 2, 2))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        select_arp_source(
            &info,
            Some(Ipv4Addr::new(192, 0, 2, 3)),
            Ipv4Addr::new(192, 0, 2, 2)
        )?,
        Ipv4Addr::new(192, 0, 2, 3)
    );
    Ok(())
}

#[test]
fn malformed_kernel_netmask_never_expands_the_target_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let mut info = fixture()?;
    if let Some(assignment) = info.assignments.first_mut() {
        assignment.netmask = Ipv4Addr::new(255, 0, 255, 0);
    }
    assert_eq!(
        select_arp_source(&info, None, Ipv4Addr::new(192, 0, 2, 2))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[test]
fn one_address_with_multiple_masks_remains_an_unambiguous_source()
-> Result<(), Box<dyn std::error::Error>> {
    let mut info = fixture()?;
    info.assignments.push(Ipv4Assignment {
        address: Ipv4Addr::new(192, 0, 2, 1),
        netmask: Ipv4Addr::new(255, 255, 255, 128),
    });
    assert_eq!(
        select_arp_source(&info, None, Ipv4Addr::new(192, 0, 2, 2))?,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    Ok(())
}
