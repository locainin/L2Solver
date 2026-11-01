use std::{collections::VecDeque, error::Error, io, sync::atomic::AtomicBool, time::Instant};

use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent};
use l2_capture::{CapturedFrame, LinuxInterfaceIdentity};

pub const SECRET: &str = "AuthP@ss PAD-SECRET";

pub fn captured(bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    crate::test_support::captured(
        bytes.to_vec(),
        Some(identity()?),
        u32::try_from(bytes.len())?,
    )
}

pub fn identity() -> Result<LinuxInterfaceIdentity, Box<dyn Error>> {
    crate::test_support::identity()
}

pub struct SensitiveLink {
    pub identity: LinuxInterfaceIdentity,
    pub frames: VecDeque<CapturedFrame>,
}

impl ActiveLink for SensitiveLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.identity
    }

    fn send(&mut self, _: &[u8], _: Instant, _: &AtomicBool) -> io::Result<()> {
        Err(io::Error::other("receive-only monitor attempted to send"))
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Err(io::Error::other(
            "receive-only monitor attempted a pre-send drain",
        ))
    }

    fn receive(&mut self, _: Instant, _: &AtomicBool, _: usize) -> io::Result<ReceiveEvent> {
        self.frames
            .pop_front()
            .map(ReceiveEvent::Frame)
            .ok_or_else(|| io::Error::other(SECRET))
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Err(io::Error::other(SECRET))
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Err(io::Error::other(SECRET))
    }
}

pub fn assert_no_secrets(text: &str) {
    for secret in [
        "AuthP@ss",
        "PAD-SECRET",
        "4175746850407373",
        "5041442d534543524554",
        "65, 117, 116, 104, 80, 64, 115, 115",
    ] {
        assert!(!text.contains(secret), "sensitive data leaked into output");
    }
}
