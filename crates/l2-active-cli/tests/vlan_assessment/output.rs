use std::{error::Error, io, net::Ipv4Addr, sync::atomic::AtomicBool, time::Duration};

use l2_active::{ActiveLink, ArpProbe, Limits, PreSendUsage, ReceiveEvent};
use l2_capture::LinuxInterfaceIdentity;
use l2_onpath::MacAddress;

use super::{Context, Endpoint, write, write_stopped};
use crate::listen_output::collection::Disclosure;
use crate::vlan_assessment::engine::{Assessment, Attempt, FailureStage, SkipReason, Step};
use crate::{ActiveOutcome, OutputFormat};

fn context() -> Result<Context<'static>, Box<dyn Error>> {
    let control = Endpoint {
        name: "control0",
        identity: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        vlan: None,
        source_ip: Ipv4Addr::new(192, 0, 2, 1),
        source_mac: MacAddress::new([2, 0, 0, 0, 0, 1])?,
    };
    let test = Endpoint {
        name: "test0",
        identity: LinuxInterfaceIdentity::new(1, 2, 3, 6, 7)?,
        vlan: None,
        source_ip: Ipv4Addr::new(192, 0, 2, 2),
        source_mac: MacAddress::new([2, 0, 0, 0, 0, 2])?,
    };
    Ok(Context {
        control,
        test,
        target: Ipv4Addr::new(192, 0, 2, 9),
        expected: MacAddress::new([2, 0, 0, 0, 0, 9])?,
        budget: Limits::new(Duration::from_secs(3), 10, 1_000)?,
        disclosure: Disclosure::OmitRaw,
    })
}

fn observed(context: &Context<'_>, endpoint: &Endpoint<'_>) -> Result<Step, Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(20), 10, 1_000)?;
    let probe = ArpProbe::new(
        endpoint.source_mac,
        endpoint.source_ip,
        context.target,
        Some(context.expected),
        limits,
    )?;
    let mut bytes = probe.frame().to_vec();
    for (range, value) in [
        (0..6, endpoint.source_mac.bytes().to_vec()),
        (6..12, context.expected.bytes().to_vec()),
        (20..22, vec![0, 2]),
        (22..28, context.expected.bytes().to_vec()),
        (28..32, context.target.octets().to_vec()),
        (32..38, endpoint.source_mac.bytes().to_vec()),
        (38..42, endpoint.source_ip.octets().to_vec()),
    ] {
        bytes
            .get_mut(range)
            .ok_or("short ARP request")?
            .copy_from_slice(&value);
    }
    bytes
        .get_mut(42..50)
        .ok_or("short ARP padding")?
        .copy_from_slice(b"PADMARK!");
    let frame = crate::test_support::captured(bytes, Some(endpoint.identity), 60)?;
    let mut link = crate::test_support::Link::new(
        vec![ReceiveEvent::Frame(frame), ReceiveEvent::TimedOut],
        Some(0),
    )?;
    link.source = endpoint.identity;
    let report = probe.run(&mut link, &AtomicBool::new(false))?;
    Ok(Step::Attempted {
        limits,
        outcome: Attempt::Report {
            report,
            close_error: None,
        },
    })
}

#[test]
fn three_complete_matching_claims_are_reported_without_authentication() -> Result<(), Box<dyn Error>>
{
    let context = context()?;
    let result = Assessment {
        before: observed(&context, &context.control)?,
        test: observed(&context, &context.test)?,
        after: observed(&context, &context.control)?,
    };
    let mut output = Vec::new();
    let outcome = write(
        &context,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Json,
        &mut output,
    )?;
    assert_eq!(outcome, ActiveOutcome::Findings);
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        json.pointer("/status").and_then(serde_json::Value::as_str),
        Some("expected_claim_observed")
    );
    assert_eq!(
        json.pointer("/control_claims_observed")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        json.pointer("/authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        json.pointer("/test/replies/0/matches_expected")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        json.pointer("/test/tx/accepted_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert!(json.pointer("/test/replies/0/frame_hex").is_none());
    assert!(!std::str::from_utf8(&output)?.contains("5041444d41524b21"));
    let mut text_output = Vec::new();
    write(
        &context,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Text,
        &mut text_output,
    )?;
    assert!(!std::str::from_utf8(&text_output)?.contains("5041444d41524b21"));
    Ok(())
}

#[test]
fn raw_frame_is_included_only_after_explicit_opt_in() -> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.disclosure = Disclosure::IncludeRaw;
    let result = Assessment {
        before: observed(&context, &context.control)?,
        test: observed(&context, &context.test)?,
        after: observed(&context, &context.control)?,
    };
    let mut output = Vec::new();
    write(
        &context,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Json,
        &mut output,
    )?;
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    let raw = json
        .pointer("/test/replies/0/frame_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing explicitly requested raw frame")?;
    assert!(raw.contains("5041444d41524b21"));
    let mut text_output = Vec::new();
    write(
        &context,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Text,
        &mut text_output,
    )?;
    assert!(std::str::from_utf8(&text_output)?.contains("5041444d41524b21"));
    Ok(())
}

#[test]
fn phase_diagnostics_never_disclose_error_text_even_with_raw_opt_in() -> Result<(), Box<dyn Error>>
{
    let mut context = context()?;
    context.disclosure = Disclosure::IncludeRaw;
    let result = Assessment {
        before: Step::Attempted {
            limits: context.budget,
            outcome: Attempt::Failure {
                stage: FailureStage::Open,
                error: io::Error::new(io::ErrorKind::PermissionDenied, "OPEN-SECRET-MARKER"),
                close_error: Some(io::Error::other("CLEANUP-SECRET-MARKER")),
            },
        },
        test: Step::Skipped(SkipReason::PreviousFailure),
        after: Step::Skipped(SkipReason::PreviousFailure),
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        write(
            &context,
            &result,
            &AtomicBool::new(false),
            format,
            &mut output,
        )?;
        let text = std::str::from_utf8(&output)?;
        assert!(text.contains("permission_denied"));
        assert!(!text.contains("OPEN-SECRET-MARKER"));
        assert!(!text.contains("CLEANUP-SECRET-MARKER"));
    }
    Ok(())
}

struct SensitiveErrors(crate::test_support::Link);

impl ActiveLink for SensitiveErrors {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.0.interface()
    }

    fn send(
        &mut self,
        frame: &[u8],
        deadline: std::time::Instant,
        cancelled: &AtomicBool,
    ) -> io::Result<()> {
        self.0.send(frame, deadline, cancelled)
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        self.0.pre_send_usage()
    }

    fn receive(
        &mut self,
        _deadline: std::time::Instant,
        _cancelled: &AtomicBool,
        _max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "RECEIVE-SECRET-MARKER",
        ))
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        Err(io::Error::other("LOSS-SECRET-MARKER"))
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Err(io::Error::other("BACKLOG-SECRET-MARKER"))
    }
}

#[test]
fn collection_diagnostics_and_cleanup_expose_only_codes_in_both_formats()
-> Result<(), Box<dyn Error>> {
    let mut context = context()?;
    context.disclosure = Disclosure::IncludeRaw;
    let limits = Limits::new(Duration::from_millis(20), 10, 1_000)?;
    let probe = ArpProbe::new(
        context.control.source_mac,
        context.control.source_ip,
        context.target,
        Some(context.expected),
        limits,
    )?;
    let mut inner = crate::test_support::Link::new(Vec::new(), Some(0))?;
    inner.source = context.control.identity;
    let report = probe.run(&mut SensitiveErrors(inner), &AtomicBool::new(false))?;
    let result = Assessment {
        before: Step::Attempted {
            limits,
            outcome: Attempt::Report {
                report,
                close_error: Some(io::Error::other("CLOSE-SECRET-MARKER")),
            },
        },
        test: Step::Skipped(SkipReason::PreviousFailure),
        after: Step::Skipped(SkipReason::PreviousFailure),
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        write(
            &context,
            &result,
            &AtomicBool::new(false),
            format,
            &mut output,
        )?;
        let text = std::str::from_utf8(&output)?;
        assert!(text.contains("permission_denied"));
        for secret in [
            "RECEIVE-SECRET-MARKER",
            "LOSS-SECRET-MARKER",
            "BACKLOG-SECRET-MARKER",
            "CLOSE-SECRET-MARKER",
        ] {
            assert!(!text.contains(secret));
        }
    }
    Ok(())
}

#[test]
fn missing_final_control_keeps_test_evidence_but_marks_completion_incomplete()
-> Result<(), Box<dyn Error>> {
    let context = context()?;
    let result = Assessment {
        before: observed(&context, &context.control)?,
        test: observed(&context, &context.test)?,
        after: Step::Skipped(SkipReason::Budget),
    };
    let mut output = Vec::new();
    let outcome = write(
        &context,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Json,
        &mut output,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        json.pointer("/status").and_then(serde_json::Value::as_str),
        Some("expected_claim_observed")
    );
    assert_eq!(
        json.pointer("/completion")
            .and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        json.pointer("/control_claims_observed")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        json.pointer("/test/replies/0/matches_expected")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
fn skipped_assessment_reports_both_scopes_and_inconclusive_status() -> Result<(), Box<dyn Error>> {
    let result = Assessment {
        before: Step::Skipped(SkipReason::Budget),
        test: Step::Skipped(SkipReason::PreviousFailure),
        after: Step::Skipped(SkipReason::PreviousFailure),
    };
    let mut output = Vec::new();
    let outcome = write(
        &context()?,
        &result,
        &AtomicBool::new(false),
        OutputFormat::Json,
        &mut output,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        json.pointer("/status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        json.pointer("/scope/control/interface")
            .and_then(serde_json::Value::as_str),
        Some("control0")
    );
    assert_eq!(
        json.pointer("/scope/test/interface")
            .and_then(serde_json::Value::as_str),
        Some("test0")
    );
    assert_eq!(
        json.pointer("/scope/control/segment_status")
            .and_then(serde_json::Value::as_str),
        Some("unknown")
    );
    assert_eq!(
        json.pointer("/control_before/reason")
            .and_then(serde_json::Value::as_str),
        Some("budget")
    );
    assert_eq!(
        json.pointer("/authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(json.get("isolation_proved").is_none());
    Ok(())
}

#[test]
fn cancellation_after_partial_collection_is_reported_as_cancelled() -> Result<(), Box<dyn Error>> {
    let result = Assessment {
        before: Step::Skipped(SkipReason::Cancelled),
        test: Step::Skipped(SkipReason::Cancelled),
        after: Step::Skipped(SkipReason::Cancelled),
    };
    let mut output = Vec::new();
    let outcome = write(
        &context()?,
        &result,
        &AtomicBool::new(true),
        OutputFormat::Json,
        &mut output,
    )?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        json.pointer("/completion")
            .and_then(serde_json::Value::as_str),
        Some("cancelled")
    );
    Ok(())
}

#[test]
fn cancelled_preflight_names_both_interfaces_and_does_not_claim_a_send()
-> Result<(), Box<dyn Error>> {
    let mut output = Vec::new();
    let outcome = write_stopped(
        "control0",
        "test0",
        Ipv4Addr::new(192, 0, 2, 9),
        MacAddress::new([2, 0, 0, 0, 0, 9])?,
        SkipReason::Cancelled,
        OutputFormat::Json,
        &mut output,
    )?;
    assert_eq!(outcome, ActiveOutcome::Cancelled);
    let json: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        json.pointer("/scope/control_interface")
            .and_then(serde_json::Value::as_str),
        Some("control0")
    );
    assert_eq!(
        json.pointer("/scope/test_interface")
            .and_then(serde_json::Value::as_str),
        Some("test0")
    );
    assert_eq!(
        json.pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}
