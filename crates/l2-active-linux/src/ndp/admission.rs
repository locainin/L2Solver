use std::{io, net::Ipv6Addr};

use l2_active::{Limits, NdpPlanError, NdpProbe};
use l2_onpath::MacAddress;

use super::{Ipv6Assignment, NdpInterfaceInfo};

/// Select a kernel-assigned IPv6 source and prepare one on-link solicitation
///
/// Only an up, multicast-capable Ethernet interface with an IPv6-sized MTU is
/// eligible and this native profile permits only link-local source and target
/// addresses. Tentative, optimistic, DAD-failed and deprecated sources are
/// excluded, and multiple compatible assignments require an explicit source
/// The privileged sender must repeat discovery and admission just before use
///
/// # Errors
/// Returns `Unsupported` for an unsuitable link or a non-link-local request
/// or `InvalidInput` if the source is absent, ambiguous, unusable or does not
/// cover the target
pub fn prepare(
    info: &NdpInterfaceInfo,
    requested: Option<Ipv6Addr>,
    target: Ipv6Addr,
    expected: Option<MacAddress>,
    limits: Limits,
) -> io::Result<NdpProbe> {
    // An assigned global prefix alone does not establish an on-link route
    if !target.is_unicast_link_local()
        || requested.is_some_and(|source| !source.is_unicast_link_local())
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native NDP currently requires link-local source and target addresses",
        ));
    }
    let interface = info.interface();
    if !interface.is_ethernet()
        || !interface.is_up()
        || interface.flags() & 0x1000 == 0
        || interface.mtu() < 1280
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NDP requires an up multicast-capable Ethernet link with an IPv6-sized MTU",
        ));
    }
    let mac = MacAddress::new(interface.mac())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut selected = None;
    for assignment in info.assignments().iter().copied() {
        if requested.is_some_and(|address| address != assignment.address()) || !eligible(assignment)
        {
            continue;
        }
        // The protocol planner owns unicast, prefix and target validation
        let probe = match NdpProbe::new(
            mac,
            assignment.address(),
            assignment.prefix_len(),
            target,
            expected,
            limits,
        ) {
            Ok(probe) => probe,
            Err(
                NdpPlanError::InvalidAddress
                | NdpPlanError::SameAddress
                | NdpPlanError::InvalidPrefix
                | NdpPlanError::TargetOffLink,
            ) => continue,
            Err(error) => return Err(io::Error::other(error)),
        };
        // A caller must choose when more than one assignment can reach the target
        if selected.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "multiple IPv6 assignments match; select one unambiguous source",
            ));
        }
        selected = Some(probe);
    }
    selected.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no usable assigned IPv6 source covers the target",
        )
    })
}

const fn eligible(assignment: Ipv6Assignment) -> bool {
    // Exclude optimistic, DAD-failed, deprecated and tentative addresses
    const UNUSABLE_FLAGS: u8 = 0x04 | 0x08 | 0x20 | 0x40;
    assignment.address().is_unicast_link_local()
        && assignment.flags() & UNUSABLE_FLAGS == 0
        && assignment.scope() == 0x20
}
