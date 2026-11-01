use std::{
    io,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent};
use l2_active_linux::HelperLink;
use l2_capture::LinuxInterfaceIdentity;

pub fn wait_for_change(deadline: Instant) -> io::Result<()> {
    let ready = std::env::var_os("L2_TEST_VLAN_READY")
        .ok_or_else(|| io::Error::other("missing ready path"))?;
    let go =
        std::env::var_os("L2_TEST_VLAN_GO").ok_or_else(|| io::Error::other("missing go path"))?;
    std::fs::write(ready, b"ready")?;
    while !Path::new(&go).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !Path::new(&go).exists() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "VLAN mutation was not confirmed",
        ));
    }
    Ok(())
}

pub struct AfterFrame(pub HelperLink, pub bool);

impl ActiveLink for AfterFrame {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.0.interface()
    }

    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        self.0.send(frame, deadline, cancelled)
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        self.0.pre_send_usage()
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        let event = self.0.receive(deadline, cancelled, max_bytes)?;
        if matches!(event, ReceiveEvent::Frame(_)) && !self.1 {
            self.1 = true;
            wait_for_change(deadline)?;
        }
        Ok(event)
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        self.0.capture_loss()
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        self.0.capture_backlog()
    }
}
