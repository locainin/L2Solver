//! Prepare a bounded receive-only observer before opening its helper

use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use l2_active::Limits;
use l2_active_linux::InterfaceInfo;

use super::{Error, ObserveArgs, session_options};

pub struct Prepared {
    pub info: InterfaceInfo,
    pub limits: Limits,
    pub deadline: Instant,
    pub helper: PathBuf,
}

pub fn prepare(options: &ObserveArgs, cancelled: &AtomicBool) -> Result<Prepared, Error> {
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Discovery(std::io::ErrorKind::Interrupted.into()));
    }
    let limits = session_options::limits(&options.session)?;
    // The single deadline starts before any interface discovery
    let deadline = session_options::deadline(limits)?;
    let info = l2_active_linux::discover_until(&options.interface, deadline, cancelled)
        .map_err(Error::Discovery)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(Error::Discovery(std::io::ErrorKind::Interrupted.into()));
    }
    let helper = session_options::helper(options.session.helper.as_deref())?;
    Ok(Prepared {
        info,
        limits,
        deadline,
        helper,
    })
}
