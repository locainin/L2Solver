use std::{error::Error, sync::atomic::AtomicBool, time::Duration};

use l2_active::{Limits, discovery::DiscoveryMonitor, stp::StpMonitor};
use l2_active_linux::InterfaceSelector;

use super::Link;
use crate::{ActiveOutcome, OutputFormat, listen_output};

fn captured(bytes: &[u8]) -> Result<l2_capture::CapturedFrame, Box<dyn Error>> {
    use l2_capture::{CaptureMetadata, Direction, FcsStatus, InterfaceId};
    let metadata = CaptureMetadata::new(
        InterfaceId {
            section: 0,
            index: 5,
        },
        u32::try_from(bytes.len())?,
        None,
        None,
        Direction::Inbound,
        None,
        FcsStatus::Absent,
    )
    .with_linux_interface(l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?);
    Ok(l2_capture::CapturedFrame::new(bytes.to_vec(), metadata)?)
}

#[test]
fn stp_output_retains_exact_root_claim_and_timer_units() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("../../../l2-active/tests/fixtures/stp-configuration.bin");
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::from([captured(bytes)?]),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let mut output = Vec::new();
    assert_eq!(
        listen_output::write_stp(
            &InterfaceSelector::new("test0")?,
            None,
            limits,
            &report,
            None,
            OutputFormat::Json,
            &mut output
        )?,
        ActiveOutcome::Completed
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    crate::fixture_assert::sampled_non_vlan_scope(&value);
    assert_eq!(
        value
            .pointer("/observations/0/decoded/root/mac")
            .and_then(serde_json::Value::as_str),
        Some("02:11:22:33:44:55")
    );
    assert_eq!(
        value
            .pointer("/observations/0/decoded/timers/hello_ticks")
            .and_then(serde_json::Value::as_u64),
        Some(512)
    );
    assert_eq!(
        value
            .pointer("/observations/0/decoded/timers/ticks_per_second")
            .and_then(serde_json::Value::as_u64),
        Some(256)
    );
    assert_frame_bytes(&value, bytes)?;
    assert!(value.pointer("/rx/post_send_packets").is_none());
    assert_eq!(
        value
            .pointer("/rx/collection_packets")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    Ok(())
}

#[test]
fn discovery_retains_observed_identity_when_capture_quality_is_unknown()
-> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("../../../l2-active/tests/fixtures/lldp-advertisement.bin");
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = DiscoveryMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::from([captured(bytes)?]),
            loss: None,
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let selector = InterfaceSelector::new("test0")?;
    let mut output = Vec::new();
    assert_eq!(
        listen_output::write_discovery(
            &selector,
            None,
            limits,
            &report,
            None,
            OutputFormat::Json,
            &mut output
        )?,
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
            .pointer("/observations/0/protocol")
            .and_then(serde_json::Value::as_str),
        Some("lldp")
    );
    assert_eq!(
        value
            .pointer("/observations/0/device_hex")
            .and_then(serde_json::Value::as_str),
        Some("07696e646570656e64656e742d737769746368")
    );
    assert_eq!(
        value
            .pointer("/observations/0/port_hex")
            .and_then(serde_json::Value::as_str),
        Some("054769312f302f31")
    );
    assert_eq!(
        value
            .pointer("/observations/0/advertised_hold_seconds")
            .and_then(serde_json::Value::as_u64),
        Some(120)
    );
    assert_frame_bytes(&value, bytes)?;
    output.clear();
    listen_output::write_discovery(
        &selector,
        None,
        limits,
        &report,
        None,
        OutputFormat::Text,
        &mut output,
    )?;
    let text = String::from_utf8(output)?;
    assert!(text.contains("completion: incomplete"));
    assert!(!text.contains('\u{1b}'));
    Ok(())
}

fn assert_frame_bytes(value: &serde_json::Value, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let hex = value
        .pointer("/observations/0/frame_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing frame hex")?;
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    assert_eq!(bytes, expected);
    Ok(())
}

#[test]
fn valid_discovery_and_parser_limit_preserve_evidence_but_remain_incomplete()
-> Result<(), Box<dyn Error>> {
    let valid = include_bytes!("../../../l2-active/tests/fixtures/lldp-advertisement.bin");
    let mut limited = valid.get(..14).ok_or("short Ethernet fixture")?.to_vec();
    for _ in 0..129 {
        limited.extend_from_slice(&[0xfe, 0]);
    }
    limited.extend_from_slice(&[0, 0]);
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = DiscoveryMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::from([captured(valid)?, captured(&limited)?]),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let mut output = Vec::new();
    assert_eq!(
        listen_output::write_discovery(
            &InterfaceSelector::new("test0")?,
            None,
            limits,
            &report,
            None,
            OutputFormat::Json,
            &mut output
        )?,
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
            .pointer("/observations/1/disposition")
            .and_then(serde_json::Value::as_str),
        Some("parser_limit")
    );
    assert_eq!(
        value
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    Ok(())
}

#[test]
fn valid_stp_and_unsupported_version_preserve_claims_but_remain_incomplete()
-> Result<(), Box<dyn Error>> {
    let valid = include_bytes!("../../../l2-active/tests/fixtures/stp-configuration.bin");
    let mut unsupported = valid.to_vec();
    *unsupported.get_mut(19).ok_or("missing STP version")? = 3;
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::from([captured(valid)?, captured(&unsupported)?]),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let mut output = Vec::new();
    assert_eq!(
        listen_output::write_stp(
            &InterfaceSelector::new("test0")?,
            None,
            limits,
            &report,
            None,
            OutputFormat::Json,
            &mut output
        )?,
        ActiveOutcome::Incomplete
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value
            .pointer("/observations/1/disposition")
            .and_then(serde_json::Value::as_str),
        Some("unsupported")
    );
    assert_frame_bytes(&value, valid)?;
    Ok(())
}

#[test]
fn silent_listeners_report_inconclusive_with_zero_transmissions() -> Result<(), Box<dyn Error>> {
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?;
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let selector = InterfaceSelector::new("test0")?;
    let stp = StpMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let discovery = DiscoveryMonitor::new(limits).run(
        &mut Link {
            identity,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    let mut output = Vec::new();
    assert_eq!(
        listen_output::write_stp(
            &selector,
            None,
            limits,
            &stp,
            None,
            OutputFormat::Json,
            &mut output
        )?,
        ActiveOutcome::Incomplete
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        value
            .pointer("/tx/accepted_packets")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    output.clear();
    assert_eq!(
        listen_output::write_discovery(
            &selector,
            None,
            limits,
            &discovery,
            None,
            OutputFormat::Json,
            &mut output
        )?,
        ActiveOutcome::Incomplete
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value
            .get("authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}
