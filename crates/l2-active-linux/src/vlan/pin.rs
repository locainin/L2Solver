//! Hold and recheck the selected VLAN's immediate parent

use std::{io, sync::atomic::AtomicBool, time::Instant};

use crate::{
    InterfaceSelector, netlink,
    pin::{InterfaceIdentityChanged, PinnedInterface},
};

use super::{UnsupportedVlan, VlanData, VlanInfo, VlanScopeChanged, query, unsupported};

#[cfg(test)]
#[path = "../../tests/vlan/errors.rs"]
mod tests;

// A retained parent handle and a sampled snapshot guard the admitted scope
pub struct VlanPin {
    info: VlanInfo,
    parent_selector: InterfaceSelector,
    parent: PinnedInterface,
}

impl VlanPin {
    pub const fn info(&self) -> VlanInfo {
        self.info
    }

    // A successful sample cannot prevent changes after the last check
    pub fn revalidate(
        &self,
        selector: &InterfaceSelector,
        selected: &PinnedInterface,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<()> {
        netlink::check_control(deadline, cancelled)?;
        selected
            .revalidate(selector)
            .map_err(changed_if_identity_replaced)?;
        self.parent
            .revalidate(&self.parent_selector)
            .map_err(changed_if_identity_replaced)?;
        let current = query::lookup(selected.identity.ifindex(), deadline, cancelled)
            .map_err(changed_if_scope_gone_or_unsupported)?;
        let expected = VlanData {
            id: self.info.id,
            protocol: self.info.protocol,
            parent_ifindex: self.info.parent.ifindex(),
            reorders_headers: self.info.reorders_headers,
        };
        if current != Some(expected) {
            return Err(scope_changed());
        }
        reject_stacked(self.parent.identity.ifindex(), deadline, cancelled)
            .map_err(changed_if_scope_gone_or_unsupported)?;
        selected
            .revalidate(selector)
            .map_err(changed_if_identity_replaced)?;
        self.parent
            .revalidate(&self.parent_selector)
            .map_err(changed_if_identity_replaced)?;
        netlink::check_control(deadline, cancelled)
    }
}

pub fn check_unscoped(
    selector: &InterfaceSelector,
    selected: &PinnedInterface,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    netlink::check_control(deadline, cancelled)?;
    // Check the retained interface on both sides of the kernel query
    selected
        .revalidate(selector)
        .map_err(changed_if_identity_replaced)?;
    if query::lookup(selected.identity.ifindex(), deadline, cancelled)
        .map_err(changed_if_scope_gone_or_unsupported)?
        .is_some()
    {
        return Err(scope_changed());
    }
    selected
        .revalidate(selector)
        .map_err(changed_if_identity_replaced)?;
    netlink::check_control(deadline, cancelled)
}

pub fn pin(
    selector: &InterfaceSelector,
    selected: &PinnedInterface,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Option<VlanPin>> {
    netlink::check_control(deadline, cancelled)?;
    let Some(data) = query::lookup(selected.identity.ifindex(), deadline, cancelled)? else {
        selected.revalidate(selector)?;
        netlink::check_control(deadline, cancelled)?;
        return Ok(None);
    };
    // Resolve the parent in the same namespace and hold its kernel object
    let name = nix::net::if_::if_indextoname(data.parent_ifindex).map_err(io::Error::from)?;
    let name = std::str::from_utf8(name.as_bytes()).map_err(invalid)?;
    let parent_selector = InterfaceSelector::new(name)?;
    let parent = PinnedInterface::open(&parent_selector)?;
    if parent.identity.ifindex() != data.parent_ifindex
        || parent.identity.namespace_device() != selected.identity.namespace_device()
        || parent.identity.namespace_inode() != selected.identity.namespace_inode()
    {
        return Err(invalid("VLAN parent identity changed"));
    }
    reject_stacked(data.parent_ifindex, deadline, cancelled)?;
    let info = VlanInfo {
        id: data.id,
        protocol: data.protocol,
        parent: parent.identity,
        reorders_headers: data.reorders_headers,
    };
    let pinned = VlanPin {
        info,
        parent_selector,
        parent,
    };
    pinned.revalidate(selector, selected, deadline, cancelled)?;
    Ok(Some(pinned))
}

fn reject_stacked(index: u32, deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
    if query::lookup(index, deadline, cancelled)?.is_some() {
        return Err(unsupported("stacked VLAN interfaces are unsupported"));
    }
    Ok(())
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn scope_changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, VlanScopeChanged)
}

fn changed_if_scope_gone_or_unsupported(error: io::Error) -> io::Error {
    // Keep transport errors distinct from unsupported VLAN properties
    if matches!(error.get_ref(), Some(source) if source.is::<UnsupportedVlan>())
        || error.kind() == io::ErrorKind::NotFound
        || matches!(
            error.raw_os_error(),
            Some(nix::libc::ENODEV | nix::libc::ENXIO)
        )
    {
        scope_changed()
    } else {
        error
    }
}

fn changed_if_identity_replaced(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::NotFound
        || matches!(error.get_ref(), Some(source) if source.is::<InterfaceIdentityChanged>())
    {
        scope_changed()
    } else {
        error
    }
}
