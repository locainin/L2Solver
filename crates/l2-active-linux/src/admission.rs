use crate::{InterfaceInfo, Ipv4Assignment};
use std::{io, net::Ipv4Addr};

#[cfg(test)]
#[path = "../tests/admission/internal.rs"]
mod tests;

/// Select an assigned source and confirm that a target is on its local subnet
///
/// This check is repeated by the privileged worker against a fresh interface
/// snapshot, so a caller cannot authorize an unassigned source with stale data
///
/// # Errors
/// Returns `Unsupported` for a non-Ethernet link, or `InvalidInput` for an
/// absent, ambiguous, non-unicast or out-of-scope address
pub fn select_arp_source(
    info: &InterfaceInfo,
    requested: Option<Ipv4Addr>,
    target: Ipv4Addr,
) -> io::Result<Ipv4Addr> {
    if info.hardware_type() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ARP probe requires an Ethernet interface",
        ));
    }
    l2_active::validate_ipv4_target(target).map_err(invalid_input)?;
    let assignments = info.ipv4_assignments();
    let source = match requested {
        Some(address) if assignments.iter().any(|item| item.address == address) => address,
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source IPv4 address is not assigned to the interface",
            ));
        }
        None => unique_source(assignments)?,
    };
    l2_active::validate_ipv4_target(source).map_err(invalid_input)?;
    if source == target
        || !info
            .ipv4_assignments()
            .iter()
            .any(|assignment| assignment.address == source && is_on_link(*assignment, target))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target is not a distinct on-link unicast host",
        ));
    }
    Ok(source)
}

fn unique_source(assignments: &[Ipv4Assignment]) -> io::Result<Ipv4Addr> {
    let address = assignments
        .first()
        .map(|item| item.address())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "select one assigned source IPv4 address",
            )
        })?;
    if assignments.iter().any(|item| item.address != address) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "select one assigned source IPv4 address",
        ));
    }
    Ok(address)
}

fn is_on_link(assignment: Ipv4Assignment, target: Ipv4Addr) -> bool {
    let mask = u32::from(assignment.netmask);
    let prefix = mask.leading_ones();
    let expected = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    if mask != expected || prefix == 0 {
        return false;
    }
    let target = u32::from(target);
    let source = u32::from(assignment.address);
    let host = target & !mask;
    source & mask == target & mask && (prefix >= 31 || (host != 0 && host != !mask))
}

fn invalid_input(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}
