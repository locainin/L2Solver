use std::{
    error::Error,
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use crate::{ActiveLink, Limits, PreSendUsage, ReceiveEvent, StopReason};
use l2_capture::LinuxInterfaceIdentity;

enum ReadResult {
    Interrupted,
    UnexpectedInterrupt,
    ScopeFailure,
    BackendDeadline,
    EarlyTimeout,
    CallerDeadline,
}

struct ReadAfterConsumption {
    interface: LinuxInterfaceIdentity,
    result: ReadResult,
}

impl ActiveLink for ReadAfterConsumption {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.interface
    }

    fn send(&mut self, _: &[u8], _: Instant, _: &AtomicBool) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Ok(Some(PreSendUsage::new(0, 0)))
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        _: usize,
    ) -> io::Result<ReceiveEvent> {
        match self.result {
            ReadResult::Interrupted => {
                cancelled.store(true, Ordering::Release);
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
            ReadResult::UnexpectedInterrupt => Err(io::Error::from(io::ErrorKind::Interrupted)),
            ReadResult::ScopeFailure => {
                cancelled.store(true, Ordering::Release);
                Err(io::Error::new(io::ErrorKind::InvalidData, "scope changed"))
            }
            ReadResult::BackendDeadline => Ok(ReceiveEvent::BackendTimedOut),
            ReadResult::EarlyTimeout => Err(io::Error::from(io::ErrorKind::TimedOut)),
            ReadResult::CallerDeadline => {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
        }
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Ok(Some(0))
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Ok(Some(false))
    }
}

fn run(result: ReadResult) -> Result<crate::RunSummary, Box<dyn Error>> {
    let timeout = if matches!(&result, ReadResult::CallerDeadline) {
        Duration::from_millis(20)
    } else {
        Duration::from_secs(1)
    };
    let mut link = ReadAfterConsumption {
        interface: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        result,
    };
    let limits = Limits::new(timeout, 8, 1024)?;
    Ok(super::run_listen_until(
        &mut link,
        limits,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(1),
        |_| false,
    )?)
}

#[test]
fn interrupted_consumed_frame_reports_cancellation_and_unknown_totals() -> Result<(), Box<dyn Error>>
{
    let summary = run(ReadResult::Interrupted)?;
    assert_eq!(summary.stop_reason(), StopReason::Cancelled);
    assert_eq!(summary.total_received_packets(), None);
    assert_eq!(summary.total_received_bytes(), None);
    assert_eq!(
        summary.transport_error().map(io::Error::kind),
        Some(io::ErrorKind::Interrupted)
    );
    assert_eq!(summary.received_packets(), 0);
    Ok(())
}

#[test]
fn scope_failure_is_not_hidden_by_concurrent_cancellation() -> Result<(), Box<dyn Error>> {
    let summary = run(ReadResult::ScopeFailure)?;
    assert_eq!(summary.stop_reason(), StopReason::TransportError);
    assert_eq!(
        summary.transport_error().map(io::Error::kind),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(summary.total_received_packets(), None);
    Ok(())
}

#[test]
fn backend_deadline_reports_unknown_receive_totals() -> Result<(), Box<dyn Error>> {
    let summary = run(ReadResult::BackendDeadline)?;
    assert_eq!(summary.stop_reason(), StopReason::BackendDeadline);
    assert_eq!(summary.total_received_packets(), None);
    assert_eq!(summary.total_received_bytes(), None);
    assert_eq!(summary.received_packets(), 0);
    Ok(())
}

#[test]
fn interrupt_without_cancellation_remains_a_transport_error() -> Result<(), Box<dyn Error>> {
    let summary = run(ReadResult::UnexpectedInterrupt)?;
    assert_eq!(summary.stop_reason(), StopReason::TransportError);
    assert_eq!(summary.total_received_packets(), None);
    Ok(())
}

#[test]
fn timeout_after_caller_deadline_keeps_the_diagnostic_and_unknown_totals()
-> Result<(), Box<dyn Error>> {
    let summary = run(ReadResult::CallerDeadline)?;
    assert_eq!(summary.stop_reason(), StopReason::Deadline);
    assert_eq!(
        summary.transport_error().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(summary.total_received_packets(), None);
    assert_eq!(summary.total_received_bytes(), None);
    Ok(())
}

#[test]
fn timeout_before_caller_deadline_remains_a_transport_error() -> Result<(), Box<dyn Error>> {
    let summary = run(ReadResult::EarlyTimeout)?;
    assert_eq!(summary.stop_reason(), StopReason::TransportError);
    assert_eq!(summary.total_received_packets(), None);
    assert_eq!(summary.total_received_bytes(), None);
    Ok(())
}
