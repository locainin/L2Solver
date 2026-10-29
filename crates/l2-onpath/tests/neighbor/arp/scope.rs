use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use l2_onpath::neighbor::arp::{ArpAnnouncementKind, ArpProofError, ArpScope};
use l2_onpath::{
    AgentId, CheckKind, ControlledEndpoint, InterfaceBindingRequest, MacAddress, NeighborBinding,
    Stimulus,
};

use super::fixture;

#[test]
fn scope_derives_control_and_conflict_from_the_checked_agents() -> Result<(), Box<dyn Error>> {
    let conflict = fixture::conflict()?;
    let control = fixture::control()?;
    let (sender, observer, subject) = fixture::roles()?;
    assert_eq!(conflict.kind(), ArpAnnouncementKind::Conflict);
    assert_eq!(control.kind(), ArpAnnouncementKind::Control);
    assert_eq!(
        (conflict.sender(), conflict.observer(), conflict.subject()),
        (sender, observer, subject)
    );
    assert_eq!(conflict.stimulus(), fixture::stimulus(sender)?);
    assert_eq!(control.sender(), subject);
    Ok(())
}

#[test]
fn scope_rejects_wrong_check_sender_and_aliased_observer() -> Result<(), Box<dyn Error>> {
    let (sender, observer, subject) = fixture::roles()?;
    let wrong_check = Stimulus::new(7, CheckKind::Dai, sender.id(), 17)?;
    assert!(ArpScope::new(wrong_check, sender, observer, subject).is_err());
    assert!(ArpScope::new(fixture::stimulus(subject)?, sender, observer, subject).is_err());
    assert!(ArpScope::new(fixture::stimulus(sender)?, sender, sender, subject).is_err());
    assert!(ArpScope::new(fixture::stimulus(sender)?, sender, subject, subject).is_err());
    Ok(())
}

#[test]
fn scope_rejects_inconsistent_same_agent_and_duplicate_identity_facts() -> Result<(), Box<dyn Error>>
{
    let (_, observer, subject) = fixture::roles()?;
    let inconsistent_subject = fixture::endpoint(2, Ipv4Addr::new(192, 0, 2, 2), 2, 4)?;
    assert!(
        ArpScope::new(
            fixture::stimulus(subject)?,
            subject,
            observer,
            inconsistent_subject
        )
        .is_err()
    );
    let duplicate_mac = fixture::endpoint(3, Ipv4Addr::new(192, 0, 2, 66), 2, 3)?;
    assert!(
        ArpScope::new(
            fixture::stimulus(duplicate_mac)?,
            duplicate_mac,
            observer,
            subject
        )
        .is_err()
    );
    let duplicate_address = fixture::endpoint(3, Ipv4Addr::new(192, 0, 2, 1), 3, 3)?;
    assert!(
        ArpScope::new(
            fixture::stimulus(duplicate_address)?,
            duplicate_address,
            observer,
            subject
        )
        .is_err()
    );
    let duplicate_interface = fixture::endpoint(3, Ipv4Addr::new(192, 0, 2, 66), 3, 2)?;
    assert!(
        ArpScope::new(
            fixture::stimulus(duplicate_interface)?,
            duplicate_interface,
            observer,
            subject
        )
        .is_err()
    );
    let observer_with_subject_mac = fixture::endpoint(1, Ipv4Addr::new(192, 0, 2, 10), 2, 1)?;
    let (sender, _, _) = fixture::roles()?;
    assert!(
        ArpScope::new(
            fixture::stimulus(sender)?,
            sender,
            observer_with_subject_mac,
            subject
        )
        .is_err()
    );
    let observer_with_subject_address = fixture::endpoint(1, Ipv4Addr::new(192, 0, 2, 1), 1, 1)?;
    assert!(
        ArpScope::new(
            fixture::stimulus(sender)?,
            sender,
            observer_with_subject_address,
            subject
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn scope_rejects_non_ethernet_bindings_and_ipv6_roles() -> Result<(), Box<dyn Error>> {
    let (sender, observer, subject) = fixture::roles()?;
    let wireless = ControlledEndpoint::new(
        sender.binding(),
        InterfaceBindingRequest::new(1, 1, 3, 105)?,
    );
    assert_eq!(
        ArpScope::new(fixture::stimulus(wireless)?, wireless, observer, subject).err(),
        Some(ArpProofError::NonEthernetInterface)
    );
    let v6 = ControlledEndpoint::new(
        NeighborBinding::new(
            AgentId::new([4; 16])?,
            IpAddr::V6("2001:db8::4".parse::<Ipv6Addr>()?),
            MacAddress::new([2, 0, 0, 0, 0, 4])?,
        )?,
        InterfaceBindingRequest::new(1, 1, 4, 1)?,
    );
    assert_eq!(
        ArpScope::new(fixture::stimulus(v6)?, v6, observer, subject).err(),
        Some(ArpProofError::Ipv4Required)
    );
    assert_eq!(
        ArpScope::new(fixture::stimulus(sender)?, sender, v6, subject).err(),
        Some(ArpProofError::Ipv4Required)
    );
    assert_eq!(
        ArpScope::new(fixture::stimulus(sender)?, sender, observer, v6).err(),
        Some(ArpProofError::Ipv4Required)
    );
    Ok(())
}

#[test]
fn same_ifindex_in_another_namespace_is_a_distinct_interface() -> Result<(), Box<dyn Error>> {
    let (sender, observer, subject) = fixture::roles()?;
    let isolated_sender = ControlledEndpoint::new(
        sender.binding(),
        InterfaceBindingRequest::new(2, 2, subject.interface().ifindex(), 1)?,
    );
    let scope = ArpScope::new(
        fixture::stimulus(isolated_sender)?,
        isolated_sender,
        observer,
        subject,
    )?;
    assert_eq!(scope.kind(), ArpAnnouncementKind::Conflict);
    Ok(())
}
