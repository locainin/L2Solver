use std::{
    error::Error as StdError,
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crate::ActiveOutcome;
use l2_active::stp::StpMonitor;
use l2_active::{ActiveLink, Limits, ReceiveEvent};
use l2_capture::LinuxInterfaceIdentity;

use super as report_common;

use report_common::{Evidence, SendMode};

struct Link {
    identity: LinuxInterfaceIdentity,
    frames: std::collections::VecDeque<l2_capture::CapturedFrame>,
    loss: Option<u64>,
    backlog: Option<bool>,
}

impl ActiveLink for Link {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.identity
    }
    fn send(&mut self, _: &[u8], _: Instant, _: &AtomicBool) -> io::Result<()> {
        Err(io::Error::other("listen operation must not send"))
    }
    fn pre_send_usage(&mut self) -> io::Result<Option<l2_active::PreSendUsage>> {
        Err(io::Error::other(
            "listen operation must not drain before sending",
        ))
    }
    fn receive(&mut self, deadline: Instant, _: &AtomicBool, _: usize) -> io::Result<ReceiveEvent> {
        if let Some(frame) = self.frames.pop_front() {
            return Ok(ReceiveEvent::Frame(frame));
        }
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        Ok(ReceiveEvent::TimedOut)
    }
    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Ok(self.loss)
    }
    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Ok(self.backlog)
    }
}

#[test]
fn collection_quality_never_turns_missing_evidence_into_success() -> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    assert_eq!(
        report_common::outcome(
            report.summary(),
            SendMode::Listen,
            Evidence::Inconclusive,
            None
        ),
        ActiveOutcome::Incomplete
    );
    assert_eq!(
        report_common::outcome(report.summary(), SendMode::Listen, Evidence::Observed, None),
        ActiveOutcome::Completed
    );
    assert_eq!(
        report_common::outcome(report.summary(), SendMode::Single, Evidence::Observed, None),
        ActiveOutcome::Incomplete
    );
    Ok(())
}

#[test]
fn unknown_quality_and_failed_cleanup_preserve_incomplete_outcome() -> Result<(), Box<dyn StdError>>
{
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    for (loss, backlog) in [
        (None, Some(false)),
        (Some(1), Some(false)),
        (Some(0), None),
        (Some(0), Some(true)),
    ] {
        let report = StpMonitor::new(limits).run(
            &mut Link {
                identity,
                frames: std::collections::VecDeque::new(),
                loss,
                backlog,
            },
            &AtomicBool::new(false),
        )?;
        assert_eq!(
            report_common::outcome(report.summary(), SendMode::Listen, Evidence::Findings, None),
            ActiveOutcome::Incomplete
        );
    }
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let error = io::Error::other("helper close failed");
    assert_eq!(
        report_common::outcome(
            report.summary(),
            SendMode::Listen,
            Evidence::Observed,
            Some(&error)
        ),
        ActiveOutcome::Incomplete
    );
    Ok(())
}

#[test]
fn cancellation_remains_cancelled_even_when_findings_exist() -> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(true),
    )?;
    assert_eq!(
        report_common::outcome(report.summary(), SendMode::Listen, Evidence::Findings, None),
        ActiveOutcome::Cancelled
    );
    Ok(())
}

#[test]
fn structured_quality_reports_unknown_loss_and_exact_retained_bytes()
-> Result<(), Box<dyn StdError>> {
    let identity = LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: None,
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let selector = l2_active_linux::InterfaceSelector::new("test0")?;
    let value = serde_json::json!({
        "quality": report_common::QualityView::new(report.summary(), None),
        "scope": report_common::InterfaceView::new(&selector, report.summary()),
        "limits": report_common::LimitsView::new(limits),
        "completion": report_common::completion_name(ActiveOutcome::Incomplete),
        "frame_hex": report_common::frame_hex(&[0, 0x0f, 0x80, 0xff])?,
    });
    assert_eq!(
        value.pointer("/quality/rx/capture_loss"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(
        value
            .pointer("/quality/capture_scope")
            .and_then(serde_json::Value::as_str),
        Some("inbound_fixed_profile")
    );
    assert_eq!(
        value.pointer("/quality/tx/attempted"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(
        value
            .pointer("/scope/ifindex")
            .and_then(serde_json::Value::as_u64),
        Some(5)
    );
    assert_eq!(
        value
            .pointer("/limits/requested_timeout_ms")
            .and_then(serde_json::Value::as_u64),
        Some(20)
    );
    assert_eq!(
        value.get("frame_hex").and_then(serde_json::Value::as_str),
        Some("000f80ff")
    );
    let error = io::Error::other("failure\u{1b}[31m");
    let mut output = Vec::new();
    report_common::write_text_quality(report.summary(), Some(&error), &mut output)?;
    let text = String::from_utf8(output)?;
    assert!(text.contains("capture loss: unavailable"));
    assert!(text.contains("Helper cleanup: unconfirmed"));
    assert!(!text.contains('\u{1b}'));
    Ok(())
}

#[path = "listen.rs"]
mod listen;
#[path = "text.rs"]
mod text;
