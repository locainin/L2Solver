use std::{error::Error, io, sync::atomic::AtomicBool, time::Instant};

use l2_active::{ActiveLink, PreSendUsage, ReceiveEvent, StopReason, isl::IslMonitor};
use l2_capture::LinuxInterfaceIdentity;

use crate::{fixture, support::Link};

struct SensitiveErrorLink(Link);

impl ActiveLink for SensitiveErrorLink {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.0.interface()
    }

    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        self.0.send(frame, deadline, cancelled)
    }

    fn receive(
        &mut self,
        _deadline: Instant,
        _cancelled: &AtomicBool,
        _max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        Err(io::Error::other("PRIVATE-BACKEND-ERROR"))
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        self.0.pre_send_usage()
    }
    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        self.0.capture_loss()
    }
    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        self.0.capture_backlog()
    }
}

#[test]
fn isl_default_report_debug_does_not_print_backend_error_contents() -> Result<(), Box<dyn Error>> {
    let mut link = SensitiveErrorLink(Link::new(vec![], Some(0))?);
    let report =
        IslMonitor::new(fixture::limits(8, 4096)?).run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().stop_reason(), StopReason::TransportError);
    assert!(report.summary().transport_error().is_some());
    assert!(!format!("{report:?}").contains("PRIVATE-BACKEND-ERROR"));
    assert_eq!(link.0.sent, [] as [std::vec::Vec<u8>; 0]);
    Ok(())
}
