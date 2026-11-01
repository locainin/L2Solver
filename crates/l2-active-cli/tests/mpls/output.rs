use std::{error::Error, io, sync::atomic::AtomicBool, time::Duration};

use l2_active::{Limits, ReceiveEvent, mpls::MplsMonitor};
use l2_active_linux::InterfaceSelector;

use crate::{
    ActiveOutcome, OutputFormat,
    first_hop_tests::fixture::{self, SensitiveLink},
    listen_output::collection::{Context, Disclosure},
    mpls_output,
};

const VALID: &[u8] = include_bytes!("../../../l2-active/tests/mpls/fixtures/valid.bin");
const MNA: &[u8] = include_bytes!("../../../l2-active/tests/mpls/fixtures/mna.bin");
const ZERO_TTL: &[u8] = include_bytes!("../../../l2-active/tests/mpls/fixtures/zero-ttl.bin");
const DESTINATION: [u8; 6] = [2, 0, 0, 0, 0, 1];

#[test]
fn mpls_output_shows_label_facts_and_redacts_payload_and_backend_errors()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(30), 8, 4_096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(VALID)?, fixture::captured(MNA)?].into(),
    };
    let report = MplsMonitor::new(DESTINATION, Some(101), limits)?
        .run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let close = io::Error::other(fixture::SECRET);
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: Some(&close),
        disclosure: Disclosure::OmitRaw,
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        assert_eq!(
            mpls_output::write(&context, &report, format, &mut output)?,
            ActiveOutcome::Incomplete
        );
        let text = String::from_utf8(output)?;
        fixture::assert_no_secrets(&text);
        for marker in ["SENSITIVE-PAYLOAD", "53454e534954495645", "frame_hex"] {
            assert!(!text.contains(marker));
        }
        if format == OutputFormat::Json {
            assert_mpls_json(&text)?;
        }
    }
    Ok(())
}

fn assert_mpls_json(text: &str) -> Result<(), Box<dyn Error>> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    assert_eq!(
        value
            .pointer("/details/expected_top_label")
            .and_then(serde_json::Value::as_u64),
        Some(101)
    );
    assert_eq!(
        value
            .pointer("/details/unexpected_top_label")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .pointer("/observations/0/disposition")
            .and_then(serde_json::Value::as_str),
        Some("stack")
    );
    assert_eq!(
        value
            .pointer("/observations/0/labels/0/value")
            .and_then(serde_json::Value::as_u64),
        Some(100)
    );
    assert_eq!(
        value
            .pointer("/observations/0/labels/0/traffic_class")
            .and_then(serde_json::Value::as_u64),
        Some(5)
    );
    assert_eq!(
        value
            .pointer("/observations/0/labels/0/ttl")
            .and_then(serde_json::Value::as_u64),
        Some(64)
    );
    assert_eq!(
        value
            .pointer("/observations/0/labels/0/bottom_of_stack")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .pointer("/observations/1/disposition")
            .and_then(serde_json::Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        value
            .pointer("/observations/1/reason")
            .and_then(serde_json::Value::as_str),
        Some("special_purpose_label")
    );
    assert_eq!(
        value
            .pointer("/transport_error/message")
            .and_then(serde_json::Value::as_str),
        Some("io_error")
    );
    assert_eq!(
        value
            .pointer("/cleanup/error")
            .and_then(serde_json::Value::as_str),
        Some("io_error")
    );
    Ok(())
}

#[test]
fn mpls_raw_evidence_is_only_emitted_when_explicitly_requested() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(30), 8, 4_096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(VALID)?].into(),
    };
    let report =
        MplsMonitor::new(DESTINATION, None, limits)?.run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::IncludeRaw,
    };
    let mut output = Vec::new();
    mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?;
    let text = String::from_utf8(output)?;
    fixture::assert_no_secrets(&text);
    assert!(text.contains("53454e534954495645"));
    let value: serde_json::Value = serde_json::from_str(&text)?;
    crate::fixture_assert::frame_hex(
        value
            .pointer("/observations/0")
            .ok_or("missing observation")?,
        VALID,
    )?;
    Ok(())
}

#[test]
fn unsupported_mpls_evidence_keeps_a_valid_observation_incomplete() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let events = [VALID, MNA]
        .into_iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(fixture::captured(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = crate::test_support::Link::new(events, Some(0))?;
    let report =
        MplsMonitor::new(DESTINATION, None, limits)?.run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    assert_eq!(
        mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?,
        ActiveOutcome::Incomplete
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value.get("completion").and_then(serde_json::Value::as_str),
        Some("incomplete")
    );
    assert_eq!(
        value
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn a_complete_mpls_window_reports_an_expected_label_mismatch_as_a_wire_fact()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let event = ReceiveEvent::Frame(fixture::captured(VALID)?);
    let mut link = crate::test_support::Link::new(vec![event], Some(0))?;
    let report = MplsMonitor::new(DESTINATION, Some(101), limits)?
        .run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    assert_eq!(
        mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?,
        ActiveOutcome::Findings
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value
            .pointer("/details/expected_top_label")
            .and_then(serde_json::Value::as_u64),
        Some(101)
    );
    assert_eq!(
        value
            .pointer("/details/unexpected_top_label")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
fn a_matching_expected_label_and_zero_top_ttl_are_reported_without_inferred_forwarding()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let event = ReceiveEvent::Frame(fixture::captured(ZERO_TTL)?);
    let mut link = crate::test_support::Link::new(vec![event], Some(0))?;
    let report = MplsMonitor::new(DESTINATION, Some(100), limits)?
        .run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    assert_eq!(
        mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?,
        ActiveOutcome::Completed
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value
            .pointer("/details/unexpected_top_label")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .pointer("/observations/0/top_ttl_is_zero")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        value
            .pointer("/observations/0/top_label_matches_expectation")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    Ok(())
}

#[test]
fn a_silent_mpls_window_remains_inconclusive() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let mut link = crate::test_support::Link::new(Vec::new(), Some(0))?;
    let report =
        MplsMonitor::new(DESTINATION, None, limits)?.run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    assert_eq!(
        mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?,
        ActiveOutcome::Incomplete
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        value
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        value
            .pointer("/tx/attempted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

#[test]
fn label_expectation_is_unknown_without_a_supported_stack() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let event = ReceiveEvent::Frame(fixture::captured(MNA)?);
    let mut link = crate::test_support::Link::new(vec![event], Some(0))?;
    let report = MplsMonitor::new(DESTINATION, Some(101), limits)?
        .run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?;
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        value
            .pointer("/details/expected_top_label")
            .and_then(serde_json::Value::as_u64),
        Some(101)
    );
    assert!(
        value
            .pointer("/details/unexpected_top_label")
            .is_some_and(serde_json::Value::is_null)
    );
    Ok(())
}

#[test]
fn unsupported_candidates_prevent_claiming_no_label_mismatch_was_seen() -> Result<(), Box<dyn Error>>
{
    let limits = Limits::new(Duration::from_millis(10), 8, 4_096)?;
    let events = [VALID, MNA]
        .into_iter()
        .map(|bytes| Ok(ReceiveEvent::Frame(fixture::captured(bytes)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut link = crate::test_support::Link::new(events, Some(0))?;
    let report = MplsMonitor::new(DESTINATION, Some(100), limits)?
        .run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    mpls_output::write(&context, &report, OutputFormat::Json, &mut output)?;
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert!(
        value
            .pointer("/details/unexpected_top_label")
            .is_some_and(serde_json::Value::is_null)
    );
    Ok(())
}
