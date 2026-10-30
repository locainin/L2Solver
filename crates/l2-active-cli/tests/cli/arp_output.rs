use std::{
    collections::VecDeque,
    error::Error as StdError,
    io,
    net::Ipv4Addr,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use l2_active::{ActiveLink, ArpProbe, Limits, PreSendUsage, ReceiveEvent};
use l2_active_linux::InterfaceSelector;
use l2_capture::{
    CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId, LinuxInterfaceIdentity,
};
use l2_onpath::MacAddress;

use super as output;
use crate::{ActiveOutcome, OutputFormat};

const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const EXPECTED: [u8; 6] = [2, 0, 0, 0, 0, 2];
const OTHER: [u8; 6] = [2, 0, 0, 0, 0, 3];
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

fn prepared(expected: Option<[u8; 6]>) -> Result<ArpProbe, Box<dyn StdError>> {
    let expected = expected.map(MacAddress::new).transpose()?;
    Ok(ArpProbe::new(
        MacAddress::new(LOCAL)?,
        SOURCE,
        TARGET,
        expected,
        Limits::new(Duration::from_millis(100), 8, 1024)?,
    )?)
}

struct Link {
    identity: LinuxInterfaceIdentity,
    frames: VecDeque<CapturedFrame>,
    pre_send: Option<PreSendUsage>,
    fail_after_frames: bool,
    backend_deadline_early: bool,
    send_error: Option<io::ErrorKind>,
    backlog: Option<bool>,
    backlog_error: bool,
}

impl Link {
    fn new(
        identity: LinuxInterfaceIdentity,
        frames: impl IntoIterator<Item = CapturedFrame>,
    ) -> Self {
        Self {
            identity,
            frames: frames.into_iter().collect(),
            pre_send: Some(PreSendUsage::new(0, 0)),
            fail_after_frames: false,
            backend_deadline_early: false,
            send_error: None,
            backlog: Some(false),
            backlog_error: false,
        }
    }
}

impl ActiveLink for Link {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.identity
    }
    fn send(
        &mut self,
        _frame: &[u8],
        _deadline: Instant,
        _cancelled: &AtomicBool,
    ) -> io::Result<()> {
        self.send_error.map_or(Ok(()), |kind| {
            Err(io::Error::new(kind, "send acknowledgement unavailable"))
        })
    }
    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        Ok(self.pre_send)
    }
    fn receive(
        &mut self,
        deadline: Instant,
        _cancelled: &AtomicBool,
        _max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        if let Some(frame) = self.frames.pop_front() {
            return Ok(ReceiveEvent::Frame(frame));
        }
        if self.fail_after_frames {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "capture denied",
            ));
        }
        if self.backend_deadline_early {
            return Ok(ReceiveEvent::BackendTimedOut);
        }
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        Ok(ReceiveEvent::TimedOut)
    }
    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Ok(Some(0))
    }
    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        if self.backlog_error {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "backlog unavailable",
            ))
        } else {
            Ok(self.backlog)
        }
    }
}

fn captured(
    identity: LinuxInterfaceIdentity,
    sender: [u8; 6],
) -> Result<CapturedFrame, Box<dyn StdError>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&LOCAL);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&TARGET.octets());
    bytes.extend_from_slice(&LOCAL);
    bytes.extend_from_slice(&SOURCE.octets());
    bytes.resize(60, 0);
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 5,
        },
        60,
        None,
        None,
        Direction::Inbound,
        None,
        FcsStatus::Absent,
    )
    .with_linux_interface(identity);
    Ok(CapturedFrame::new(bytes, metadata)?)
}

fn outbound(
    identity: LinuxInterfaceIdentity,
    bytes: &[u8],
) -> Result<CapturedFrame, Box<dyn StdError>> {
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 5,
        },
        u32::try_from(bytes.len())?,
        None,
        None,
        Direction::Outbound,
        None,
        FcsStatus::Absent,
    )
    .with_linux_interface(identity);
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}

fn assert_frame_hex(
    value: &serde_json::Value,
    original: &CapturedFrame,
) -> Result<(), Box<dyn StdError>> {
    let encoded = value
        .get("frame_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing frame bytes")?;
    assert_eq!(encoded.len(), original.bytes().len() * 2);
    for (pair, expected) in encoded.as_bytes().chunks_exact(2).zip(original.bytes()) {
        assert_eq!(
            u8::from_str_radix(std::str::from_utf8(pair)?, 16)?,
            *expected
        );
    }
    Ok(())
}

#[test]
fn text_reports_conflicting_replies_and_unconfirmed_cleanup() -> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(Some(EXPECTED))?;
    let mut link = Link::new(
        identity,
        [captured(identity, EXPECTED)?, captured(identity, OTHER)?],
    );
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let cleanup = io::Error::other("helper close was not acknowledged");
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        Some(&cleanup),
        OutputFormat::Text,
        &mut bytes,
    )?;
    let text = std::str::from_utf8(&bytes)?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    assert!(text.contains("ARP probe: 192.0.2.20 on test0 (index 5)"));
    assert!(text.contains("Status: unexpected_identity  completion: incomplete"));
    assert!(text.contains("Reply: 02:00:00:00:00:02  expected match: yes"));
    assert!(text.contains("Reply: 02:00:00:00:00:03  expected match: no"));
    assert!(text.contains("Conflicting identities: yes"));
    assert!(text.contains("Helper cleanup: unconfirmed (helper close was not acknowledged)"));
    assert!(text.contains("physical delivery unconfirmed"));
    assert!(text.contains("ARP replies are unauthenticated"));
    Ok(())
}

#[test]
fn json_reports_actual_reply_claims_and_socket_acceptance_without_implying_authentication()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(Some(EXPECTED))?;
    let mut link = Link::new(
        identity,
        [captured(identity, EXPECTED)?, captured(identity, OTHER)?],
    );
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Findings);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value
            .pointer("/limits/requested_timeout_ms")
            .and_then(serde_json::Value::as_u64),
        Some(100)
    );
    assert!(value.pointer("/limits/timeout_ms").is_none());
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("unexpected_identity")
    );
    assert_eq!(
        value
            .get("conflicting_identities")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let tx = value.get("tx").ok_or("missing transmit record")?;
    assert_eq!(
        tx.get("attempt_scope").and_then(serde_json::Value::as_str),
        Some("link_send_call")
    );
    assert_eq!(
        tx.get("accepted_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        tx.get("delivery_confirmed")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let replies = value
        .get("replies")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing replies")?;
    assert_eq!(replies.len(), 2);
    assert!(replies.iter().any(|reply| {
        reply
            .get("matches_expected")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    }));
    let observed = replies
        .iter()
        .find(|reply| {
            reply.get("mac").and_then(serde_json::Value::as_str) == Some("02:00:00:00:00:03")
        })
        .ok_or("missing unexpected reply")?;
    assert_frame_hex(observed, &captured(identity, OTHER)?)?;
    assert_eq!(
        value
            .get("authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let limitation = value
        .get("limitation")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing limitation")?;
    assert!(limitation.contains("sampled"), "{limitation}");
    Ok(())
}

#[test]
fn cleanup_failure_keeps_observed_reply_but_makes_completion_inconclusive()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let cleanup = io::Error::other("helper close was not acknowledged");
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        Some(&cleanup),
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    let cleanup = value.get("cleanup").ok_or("missing cleanup status")?;
    assert_eq!(
        cleanup
            .get("confirmed")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(
        cleanup
            .get("error")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    assert_eq!(
        value
            .get("replies")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn no_reply_is_inconclusive_even_when_request_and_cleanup_succeed() -> Result<(), Box<dyn StdError>>
{
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, []);
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        value
            .get("replies")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn cancelled_core_session_reports_no_send_and_preserves_cancellation_outcome()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, []);
    let report = probe.run(&mut link, &AtomicBool::new(true))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("stop_reason").and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    let tx = value.get("tx").ok_or("missing transmit record")?;
    assert_eq!(
        tx.get("attempted").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn known_outbound_request_is_counted_without_making_the_reply_incomplete()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(Some(EXPECTED))?;
    let mut link = Link::new(
        identity,
        [
            outbound(identity, probe.frame())?,
            captured(identity, EXPECTED)?,
        ],
    );
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Completed);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let rx = value.get("rx").ok_or("missing receive accounting")?;
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("complete")
    );
    assert_eq!(
        rx.get("outbound_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        rx.get("unscoped_packets")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    Ok(())
}

#[test]
fn unavailable_pre_send_accounting_stays_unknown_and_incomplete() -> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, []);
    link.pre_send = None;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("stop_reason").and_then(serde_json::Value::as_str),
        Some("accounting_unavailable")
    );
    let rx = value.get("rx").ok_or("missing receive accounting")?;
    assert!(
        rx.get("setup_packets")
            .is_some_and(serde_json::Value::is_null)
    );
    assert!(
        rx.get("total_packets")
            .is_some_and(serde_json::Value::is_null)
    );
    Ok(())
}

#[test]
fn reported_capture_totals_include_confirmed_pre_send_drain() -> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    link.pre_send = Some(PreSendUsage::new(2, 100));
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Completed);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let rx = value.get("rx").ok_or("missing receive accounting")?;
    assert_eq!(
        rx.get("setup_packets").and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        rx.get("total_packets").and_then(serde_json::Value::as_u64),
        Some(3)
    );
    assert_eq!(
        rx.get("total_bytes").and_then(serde_json::Value::as_u64),
        Some(160)
    );
    Ok(())
}

#[test]
fn receive_error_keeps_observed_reply_and_marks_capture_total_unknown()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    link.fail_after_frames = true;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    let rx = value.get("rx").ok_or("missing receive accounting")?;
    assert_eq!(
        rx.get("collection_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert!(
        rx.get("total_packets")
            .is_some_and(serde_json::Value::is_null)
    );
    let error = value
        .get("transport_error")
        .ok_or("missing transport error")?;
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("permission_denied")
    );
    Ok(())
}

#[test]
fn packet_limit_keeps_observed_reply_but_reports_incomplete_collection()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = ArpProbe::new(
        MacAddress::new(LOCAL)?,
        SOURCE,
        TARGET,
        None,
        Limits::new(Duration::from_millis(100), 1, 1024)?,
    )?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        value.get("stop_reason").and_then(serde_json::Value::as_str),
        Some("packet_limit")
    );
    assert_eq!(
        value
            .get("replies")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn earlier_backend_deadline_does_not_present_a_full_observation_window()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    link.backend_deadline_early = true;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        value.get("stop_reason").and_then(serde_json::Value::as_str),
        Some("backend_deadline")
    );
    Ok(())
}

#[test]
fn failed_send_acknowledgement_is_unconfirmed_instead_of_claiming_no_transmission()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, []);
    link.send_error = Some(io::ErrorKind::BrokenPipe);
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let tx = value.get("tx").ok_or("missing transmit record")?;
    assert_eq!(
        tx.get("attempted").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        tx.get("acceptance").and_then(serde_json::Value::as_str),
        Some("unconfirmed")
    );
    assert_eq!(
        tx.get("accepted_packets")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    Ok(())
}

#[test]
fn pending_or_unknown_final_backlog_keeps_observed_reply_incomplete()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    for backlog in [Some(true), None] {
        let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
        link.backlog = backlog;
        let report = probe.run(&mut link, &AtomicBool::new(false))?;
        let mut bytes = Vec::new();
        let outcome = output::write(
            &InterfaceSelector::new("test0")?,
            &probe,
            &report,
            None,
            OutputFormat::Json,
            &mut bytes,
        )?;
        assert_eq!(outcome, ActiveOutcome::Incomplete);
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("observed")
        );
        let rx = value.get("rx").ok_or("missing receive accounting")?;
        assert_eq!(
            rx.get("final_backlog").and_then(serde_json::Value::as_bool),
            backlog
        );
    }
    Ok(())
}

#[test]
fn backlog_query_error_is_preserved_and_never_claims_complete_collection()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let probe = prepared(None)?;
    let mut link = Link::new(identity, [captured(identity, EXPECTED)?]);
    link.backlog_error = true;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = output::write(
        &InterfaceSelector::new("test0")?,
        &probe,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let error = value.get("backlog_error").ok_or("missing backlog error")?;
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("permission_denied")
    );
    let rx = value.get("rx").ok_or("missing receive accounting")?;
    assert!(
        rx.get("final_backlog")
            .is_some_and(serde_json::Value::is_null)
    );
    Ok(())
}
