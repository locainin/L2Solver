//! One bounded transmit and capture loop shared by active protocols

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use l2_capture::{CapturedFrame, Direction, LinkType};

use crate::{
    ActiveLink, Limits, PreSendUsage, ReceiveEvent, RunError, RunSummary, StopReason,
    report::TransportFailure,
};

#[cfg(test)]
#[path = "../tests/session/listen.rs"]
mod listen_tests;

#[cfg(test)]
#[path = "../tests/session/post_read.rs"]
mod post_read_tests;

pub fn run_single_until(
    link: &mut impl ActiveLink,
    frame: &[u8],
    limits: Limits,
    cancelled: &AtomicBool,
    deadline: Instant,
    accept: impl FnMut(CapturedFrame) -> bool,
) -> Result<RunSummary, RunError> {
    run_until(link, Some(frame), limits, cancelled, deadline, accept)
}

pub fn run_listen_until(
    link: &mut impl ActiveLink,
    limits: Limits,
    cancelled: &AtomicBool,
    deadline: Instant,
    accept: impl FnMut(CapturedFrame) -> bool,
) -> Result<RunSummary, RunError> {
    run_until(link, None, limits, cancelled, deadline, accept)
}

fn run_until(
    link: &mut impl ActiveLink,
    frame: Option<&[u8]>,
    limits: Limits,
    cancelled: &AtomicBool,
    deadline: Instant,
    mut accept: impl FnMut(CapturedFrame) -> bool,
) -> Result<RunSummary, RunError> {
    let latest = Instant::now()
        .checked_add(limits.timeout())
        .ok_or(RunError::DeadlineOverflow)?;
    let deadline = deadline.min(latest);
    let mut summary = RunSummary {
        interface: link.interface(),
        stop_reason: StopReason::Deadline,
        send_attempted: false,
        pre_send_usage: Some(PreSendUsage::new(0, 0)),
        sent_bytes: 0,
        received_packets: 0,
        received_bytes: 0,
        outbound_packets: 0,
        truncated_packets: 0,
        unscoped_packets: 0,
        capture_loss: None,
        capture_backlog: None,
        transport_error: None,
        loss_error: None,
        accounting_error: None,
        backlog_error: None,
    };
    let mut sample_quality = false;
    if cancelled.load(Ordering::Acquire) {
        summary.stop_reason = StopReason::Cancelled;
    } else if Instant::now() >= deadline {
        summary.stop_reason = StopReason::Deadline;
    } else if let Some(frame) = frame {
        summary.send_attempted = true;
        sample_quality = true;
        let sent = match link.send(frame, deadline, cancelled) {
            Ok(()) => {
                summary.sent_bytes = u64::try_from(frame.len()).unwrap_or(u64::MAX);
                true
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted
                    && cancelled.load(Ordering::Acquire) =>
            {
                summary.stop_reason = StopReason::Cancelled;
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                summary.stop_reason = StopReason::Deadline;
                false
            }
            Err(error) => {
                summary.stop_reason = StopReason::TransportError;
                summary.transport_error = Some(TransportFailure::Send(error));
                false
            }
        };
        if pre_send_accounted(link, limits, sent, &mut summary) && sent {
            collect(link, limits, cancelled, deadline, &mut summary, &mut accept);
        }
    } else {
        sample_quality = true;
        collect(link, limits, cancelled, deadline, &mut summary, &mut accept);
    }
    if sample_quality {
        match link.capture_loss() {
            Ok(loss) => summary.capture_loss = loss,
            Err(error) => summary.loss_error = Some(error),
        }
        match link.capture_backlog() {
            Ok(backlog) => summary.capture_backlog = backlog,
            Err(error) => summary.backlog_error = Some(error),
        }
    }
    Ok(summary)
}

fn pre_send_accounted(
    link: &mut impl ActiveLink,
    limits: Limits,
    sent: bool,
    summary: &mut RunSummary,
) -> bool {
    let usage = match link.pre_send_usage() {
        Ok(usage) => usage,
        Err(error) => {
            summary.accounting_error = Some(error);
            None
        }
    };
    summary.pre_send_usage = usage;
    let Some(usage) = usage else {
        if sent {
            summary.stop_reason = StopReason::AccountingUnavailable;
        }
        return false;
    };
    if usage.packets() > limits.max_received_packets()
        || usage.bytes() > limits.max_received_bytes()
        || !usage.is_consistent()
    {
        summary.stop_reason = StopReason::BackendViolation;
        return false;
    }
    true
}

fn collect(
    link: &mut impl ActiveLink,
    limits: Limits,
    cancelled: &AtomicBool,
    deadline: Instant,
    summary: &mut RunSummary,
    accept: &mut impl FnMut(CapturedFrame) -> bool,
) {
    let Some(pre_send) = summary.pre_send_usage else {
        return;
    };
    loop {
        if cancelled.load(Ordering::Acquire) {
            summary.stop_reason = StopReason::Cancelled;
            break;
        }
        if u64::from(pre_send.packets()) + u64::from(summary.received_packets)
            >= u64::from(limits.max_received_packets())
        {
            summary.stop_reason = StopReason::PacketLimit;
            break;
        }
        if pre_send.bytes() + summary.received_bytes >= limits.max_received_bytes() {
            summary.stop_reason = StopReason::ByteLimit;
            break;
        }
        if Instant::now() >= deadline {
            summary.stop_reason = StopReason::Deadline;
            break;
        }
        let remaining = limits.max_received_bytes() - pre_send.bytes() - summary.received_bytes;
        let max_bytes = usize::try_from(remaining.min(l2_capture::MAX_FRAME_LENGTH as u64))
            .unwrap_or(l2_capture::MAX_FRAME_LENGTH);
        match link.receive(deadline, cancelled, max_bytes) {
            Ok(ReceiveEvent::Frame(frame)) => {
                summary.received_packets += 1;
                summary.received_bytes += u64::try_from(frame.captured_len()).unwrap_or(u64::MAX);
                if frame.captured_len() > max_bytes {
                    summary.stop_reason = StopReason::BackendViolation;
                    break;
                }
                if scoped(frame, summary, accept) {
                    summary.stop_reason = StopReason::ObservationLimit;
                    break;
                }
            }
            Ok(ReceiveEvent::TimedOut) => {
                summary.stop_reason = StopReason::Deadline;
                break;
            }
            Ok(ReceiveEvent::BackendTimedOut) => {
                summary.stop_reason = StopReason::BackendDeadline;
                break;
            }
            Ok(ReceiveEvent::Cancelled) => {
                summary.stop_reason = StopReason::Cancelled;
                break;
            }
            Ok(ReceiveEvent::InterfaceDown) => {
                summary.stop_reason = StopReason::InterfaceDown;
                break;
            }
            Err(error) => {
                summary.stop_reason = if error.kind() == std::io::ErrorKind::Interrupted
                    && cancelled.load(Ordering::Acquire)
                {
                    StopReason::Cancelled
                } else if error.kind() == std::io::ErrorKind::TimedOut && Instant::now() >= deadline
                {
                    StopReason::Deadline
                } else {
                    StopReason::TransportError
                };
                // A consumed frame may not have reached the caller before the error
                summary.transport_error = Some(TransportFailure::Receive(error));
                break;
            }
        }
    }
}

fn scoped(
    frame: CapturedFrame,
    summary: &mut RunSummary,
    accept: &mut impl FnMut(CapturedFrame) -> bool,
) -> bool {
    let metadata = frame.metadata();
    if metadata.linux_interface() != Some(summary.interface)
        || metadata.link_type() != LinkType::Ethernet
    {
        summary.unscoped_packets += 1;
        return false;
    }
    match metadata.direction() {
        Direction::Outbound => {
            summary.outbound_packets += 1;
            return false;
        }
        Direction::Unknown => {
            summary.unscoped_packets += 1;
            return false;
        }
        Direction::Inbound => {}
    }
    if metadata.vlan().is_some() {
        summary.unscoped_packets += 1;
        return false;
    }
    if frame.is_truncated() {
        summary.truncated_packets += 1;
        return false;
    }
    accept(frame)
}
