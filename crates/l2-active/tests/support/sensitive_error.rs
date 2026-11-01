use std::{error::Error, io, sync::atomic::AtomicBool, time::Instant};

use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent};
use l2_capture::LinuxInterfaceIdentity;

pub const MARKER: &str = "UNTRUSTED-ERROR-PAYLOAD";

pub struct SensitiveErrorLink {
    identity: LinuxInterfaceIdentity,
}

impl SensitiveErrorLink {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            identity: crate::support::identity()?,
        })
    }
}

impl ActiveLink for SensitiveErrorLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.identity
    }

    fn send(
        &mut self,
        _frame: &[u8],
        _deadline: Instant,
        _cancelled: &AtomicBool,
    ) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Ok(Some(PreSendUsage::new(0, 0)))
    }

    fn receive(
        &mut self,
        _deadline: Instant,
        _cancelled: &AtomicBool,
        _max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        Err(io::Error::other(MARKER))
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Err(io::Error::other(MARKER))
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Err(io::Error::other(MARKER))
    }
}
