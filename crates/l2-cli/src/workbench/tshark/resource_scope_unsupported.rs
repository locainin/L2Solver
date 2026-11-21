//! Refuse resource-scoped launches when Linux cgroup controls are unavailable

use super::sandbox::Launch;
use l2_workbench::tshark::ScopeReceipt;
use std::{
    fs::File,
    io,
    num::NonZeroU64,
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/resource_scope_unsupported.rs"]
mod tests;

pub(super) struct ResourceScope;
pub(super) struct Gate;

impl ResourceScope {
    pub(super) fn new(_: NonZeroU64, _: u64, _: NonZeroU64, _: Duration) -> io::Result<Self> {
        Err(unsupported())
    }

    pub(super) fn wrap(self, _: Launch) -> io::Result<Launch> {
        Err(unsupported())
    }
}

impl Gate {
    pub(super) fn claim(&mut self) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn verify(&mut self, _: u32) -> io::Result<bool> {
        Err(unsupported())
    }

    pub(super) fn verify_member(&self, _: &File) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn request_freeze(&mut self) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn poll_frozen(&mut self) -> io::Result<bool> {
        Err(unsupported())
    }

    pub(super) fn verify_only_members(&mut self, _: u32) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn stop_verified_scope(&mut self, _: Instant) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) const fn receipt(&self) -> Option<ScopeReceipt> {
        None
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "TShark resource scopes require Linux cgroup v2",
    )
}
