#[cfg(test)]
#[path = "../tests/privileges/selection.rs"]
mod tests;

use rustix::thread::{self, CapabilitySet, CapabilitySets};
use std::io;

const fn narrow(existing: CapabilitySets) -> CapabilitySets {
    CapabilitySets {
        effective: existing.effective.intersection(CapabilitySet::NET_RAW),
        permitted: existing.permitted.intersection(CapabilitySet::NET_RAW),
        inheritable: CapabilitySet::empty(),
    }
}

pub fn restrict_startup() -> io::Result<()> {
    // No later executable may gain new authority from file capabilities
    thread::set_no_new_privs(true)?;
    let desired = narrow(thread::capabilities(None)?);
    thread::set_capabilities(None, desired)?;
    confirm(desired)
}

pub fn drop_all() -> io::Result<()> {
    let desired = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    thread::set_capabilities(None, desired)?;
    confirm(desired)
}

fn confirm(expected: CapabilitySets) -> io::Result<()> {
    if thread::capabilities(None)? != expected || !thread::no_new_privs()? {
        return Err(io::Error::other(
            "worker capability reduction was not confirmed",
        ));
    }
    Ok(())
}
