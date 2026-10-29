use std::{error::Error, net::Ipv4Addr};

use l2_onpath::neighbor::arp::ArpScope;
use l2_onpath::{
    AgentId, CheckKind, ControlledEndpoint, InterfaceBindingRequest, MacAddress, NeighborBinding,
    RunId, Stimulus,
};

pub const FRAME_LENGTH: usize = 42;

pub fn endpoint(
    id: u8,
    address: Ipv4Addr,
    mac: u8,
    interface: u32,
) -> Result<ControlledEndpoint, Box<dyn Error>> {
    let binding = NeighborBinding::new(
        AgentId::new([id; 16])?,
        address.into(),
        MacAddress::new([0x02, 0, 0, 0, 0, mac])?,
    )?;
    Ok(ControlledEndpoint::new(
        binding,
        InterfaceBindingRequest::new(1, 1, interface, 1)?,
    ))
}

pub fn roles()
-> Result<(ControlledEndpoint, ControlledEndpoint, ControlledEndpoint), Box<dyn Error>> {
    Ok((
        endpoint(3, Ipv4Addr::new(192, 0, 2, 66), 3, 3)?,
        endpoint(1, Ipv4Addr::new(192, 0, 2, 10), 1, 1)?,
        endpoint(2, Ipv4Addr::new(192, 0, 2, 1), 2, 2)?,
    ))
}

pub fn stimulus(sender: ControlledEndpoint) -> Result<Stimulus, Box<dyn Error>> {
    Ok(Stimulus::new(
        7,
        CheckKind::ArpSpoofSusceptibility,
        sender.id(),
        17,
    )?)
}

pub fn conflict() -> Result<ArpScope, Box<dyn Error>> {
    let (sender, observer, subject) = roles()?;
    Ok(ArpScope::new(stimulus(sender)?, sender, observer, subject)?)
}

pub fn control() -> Result<ArpScope, Box<dyn Error>> {
    let (_, observer, subject) = roles()?;
    Ok(ArpScope::new(
        stimulus(subject)?,
        subject,
        observer,
        subject,
    )?)
}

pub fn run_id() -> Result<RunId, Box<dyn Error>> {
    Ok(RunId::from_recorded([0x31; 16])?)
}

pub fn announcement(sender: ControlledEndpoint) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xff; 6]);
    frame.extend_from_slice(&sender.binding().mac().bytes());
    frame.extend_from_slice(&0x0806_u16.to_be_bytes());
    frame.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&sender.binding().mac().bytes());
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame
}

pub fn overwrite(frame: &mut [u8], start: usize, replacement: &[u8]) -> Result<(), Box<dyn Error>> {
    let end = start
        .checked_add(replacement.len())
        .ok_or("offset overflow")?;
    frame
        .get_mut(start..end)
        .ok_or("missing fixture bytes")?
        .copy_from_slice(replacement);
    Ok(())
}
