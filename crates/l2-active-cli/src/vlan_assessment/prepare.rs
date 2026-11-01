//! Discover both interface scopes before granting either transmit session

use std::{io, net::Ipv4Addr, sync::atomic::AtomicBool, time::Instant};

use l2_active_linux::{InterfaceInfo, InterfaceSelector};
use l2_onpath::MacAddress;

use crate::{Error, vlan_arguments::VlanAssessmentArgs};

use super::{output::Endpoint, scope};

pub(super) struct Selected<'a> {
    pub selector: &'a InterfaceSelector,
    pub info: InterfaceInfo,
    pub source: Ipv4Addr,
    pub mac: MacAddress,
}

impl Selected<'_> {
    pub fn endpoint(&self) -> Endpoint<'_> {
        Endpoint {
            name: self.selector.name(),
            identity: self.info.identity(),
            vlan: self.info.vlan(),
            source_ip: self.source,
            source_mac: self.mac,
        }
    }
}

pub(super) struct Prepared<'a> {
    pub control: Selected<'a>,
    pub test: Selected<'a>,
}

pub(super) fn prepare<'a>(
    options: &'a VlanAssessmentArgs,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Prepared<'a>, Error> {
    if options.interface == options.control_interface {
        return Err(Error::Scope(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control and test must identify distinct interfaces",
        )));
    }
    // Source selection is checked for both interfaces before any packet is sent
    let control = select(
        &options.control_interface,
        options.control_source_ip,
        options.target,
        deadline,
        cancelled,
    )?;
    let test = select(
        &options.interface,
        options.source_ip,
        options.target,
        deadline,
        cancelled,
    )?;
    scope::validate_pair(
        control.info.identity(),
        test.info.identity(),
        control.mac,
        test.mac,
        options.expected_mac,
    )
    .map_err(Error::Scope)?;
    Ok(Prepared { control, test })
}

fn select<'a>(
    selector: &'a InterfaceSelector,
    source: Option<Ipv4Addr>,
    target: Ipv4Addr,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Selected<'a>, Error> {
    let info =
        l2_active_linux::discover_until(selector, deadline, cancelled).map_err(Error::Discovery)?;
    let source = l2_active_linux::select_arp_source(&info, source, target).map_err(Error::Scope)?;
    let mac = MacAddress::new(info.mac()).map_err(Error::Address)?;
    Ok(Selected {
        selector,
        info,
        source,
        mac,
    })
}
