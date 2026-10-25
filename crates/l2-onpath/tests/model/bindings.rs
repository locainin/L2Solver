use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use l2_onpath::{
    AddressFamily, AgentId, ControlledEndpoint, InterfaceBindingRequest, MacAddress, ModelError,
    NeighborBinding,
};

// Repeated identity bytes keep family assertions focused on the binding itself
const fn agent(value: u8) -> Result<AgentId, l2_onpath::AgentIdError> {
    AgentId::new([value; l2_onpath::ID_LEN])
}

#[test]
fn bindings_keep_family_identity_explicit() -> Result<(), Box<dyn Error>> {
    let v4 = NeighborBinding::new(
        agent(1)?,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        MacAddress::new([0x02, 0, 0, 0, 0, 1])?,
    )?;
    assert_eq!(v4.family(), AddressFamily::Ipv4);
    assert_eq!(v4.endpoint(), agent(1)?);

    let v6 = NeighborBinding::new(
        agent(2)?,
        IpAddr::V6("2001:db8::20".parse::<Ipv6Addr>()?),
        MacAddress::new([0x02, 0, 0, 0, 0, 2])?,
    )?;
    assert_eq!(v6.family(), AddressFamily::Ipv6);

    // Endpoint construction preserves the exact neighbor binding
    let interface = InterfaceBindingRequest::new(1, 2, 1, 1)?;
    let endpoint = ControlledEndpoint::new(v4, interface);
    assert_eq!(endpoint.binding(), v4);
    assert_eq!(endpoint.interface(), interface);
    // The canonical agent constructor rejects the reserved identity before binding validation
    assert!(agent(0).is_err());
    Ok(())
}

#[test]
fn dual_family_agent_targeting() -> Result<(), Box<dyn Error>> {
    let interface = InterfaceBindingRequest::new(1, 2, 7, 1)?;
    let endpoint_v4 = ControlledEndpoint::new(
        NeighborBinding::new(
            agent(7)?,
            Ipv4Addr::new(192, 0, 2, 70).into(),
            MacAddress::new([0x02, 0, 0, 0, 0, 7])?,
        )?,
        interface,
    );
    let endpoint_v6 = ControlledEndpoint::new(
        NeighborBinding::new(
            agent(7)?,
            "2001:db8::70".parse::<Ipv6Addr>()?.into(),
            MacAddress::new([0x02, 0, 0, 0, 0, 8])?,
        )?,
        interface,
    );

    // One stable agent identity may carry independent IPv4 and IPv6 bindings
    let mut plan = l2_onpath::AssessmentPlan::for_replay([7; l2_onpath::ID_LEN])?;
    plan.add_endpoint(endpoint_v4)?;
    plan.add_endpoint(endpoint_v6)?;
    plan.add_check(l2_onpath::CheckKind::ArpSpoofSusceptibility)?;
    plan.add_check(l2_onpath::CheckKind::NdpSpoofSusceptibility)?;
    plan.add_stimulus(l2_onpath::Stimulus::new(
        1,
        l2_onpath::CheckKind::ArpSpoofSusceptibility,
        agent(7)?,
        1,
    )?)?;
    plan.add_stimulus(l2_onpath::Stimulus::new(
        2,
        l2_onpath::CheckKind::NdpSpoofSusceptibility,
        agent(7)?,
        2,
    )?)?;
    assert_eq!(plan.stimuli().len(), 2);
    Ok(())
}

#[test]
fn neighbor_bindings_unicast_ip_identities() -> Result<(), Box<dyn Error>> {
    let endpoint = agent(8)?;
    let mac = MacAddress::new([0x02, 0, 0, 0, 0, 8])?;

    assert_eq!(
        NeighborBinding::new(endpoint, Ipv4Addr::BROADCAST.into(), mac),
        Err(ModelError::BroadcastAddress)
    );
    for address in [
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6("ff02::1".parse::<Ipv6Addr>()?),
    ] {
        assert_eq!(
            NeighborBinding::new(endpoint, address, mac),
            Err(ModelError::MulticastAddress)
        );
    }
    for address in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        assert_eq!(
            NeighborBinding::new(endpoint, address, mac),
            Err(ModelError::LoopbackAddress)
        );
    }
    Ok(())
}

mod mac_identity {
    use super::*;

    #[test]
    fn rejects_non_unicast_values() {
        for invalid in [[0; 6], [0xff; 6], [0x01, 0, 0, 0, 0, 1]] {
            assert!(MacAddress::new(invalid).is_err(), "accepted {invalid:02x?}");
        }
    }

    #[test]
    fn accepts_local_unicast_value() -> Result<(), Box<dyn Error>> {
        let value = [0x02, 1, 2, 3, 4, 5];

        assert_eq!(MacAddress::new(value)?.bytes(), value);
        Ok(())
    }
}
