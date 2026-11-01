use std::{error::Error, io, sync::atomic::AtomicBool, time::Duration};

use l2_active::{Limits, first_hop::hsrp::HsrpMonitor};
use l2_active_linux::InterfaceSelector;

use super::fixture::{self, SensitiveLink};
use crate::{
    ActiveOutcome, OutputFormat,
    first_hop_output::{Context, Disclosure, write_hsrp},
};

const ADVERTISEMENT: &[u8] =
    include_bytes!("../../../l2-active/tests/first_hop/hsrp/fixtures/advertisement.bin");
const EXTENSION: &[u8] =
    include_bytes!("../../../l2-active/tests/first_hop/hsrp/fixtures/extension.bin");

#[test]
fn hsrp_default_output_hides_authentication_frames_and_backend_error_messages()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(50), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [
            fixture::captured(ADVERTISEMENT)?,
            fixture::captured(EXTENSION)?,
        ]
        .into(),
    };
    let report = HsrpMonitor::new(Some(0), limits).run(&mut link, &AtomicBool::new(false))?;
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
            write_hsrp(&context, Some(0), &report, format, &mut output)?,
            ActiveOutcome::Incomplete
        );
        let text = String::from_utf8(output)?;
        fixture::assert_no_secrets(&text);
        assert!(
            !text.contains("frame_hex"),
            "raw candidate appeared without opt-in"
        );
        if format == OutputFormat::Json {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            assert_eq!(
                value.get("authenticated"),
                Some(&serde_json::Value::Bool(false))
            );
            assert_eq!(
                value.pointer("/tx/attempted"),
                Some(&serde_json::Value::Bool(false))
            );
            assert_eq!(
                value
                    .pointer("/observations/0/group")
                    .and_then(serde_json::Value::as_u64),
                Some(0)
            );
            assert_eq!(
                value
                    .pointer("/transport_error/code")
                    .and_then(serde_json::Value::as_str),
                Some("io_error")
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
        }
    }
    Ok(())
}

#[test]
fn hsrp_explicit_raw_output_contains_each_complete_captured_candidate() -> Result<(), Box<dyn Error>>
{
    let limits = Limits::new(Duration::from_millis(50), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [
            fixture::captured(ADVERTISEMENT)?,
            fixture::captured(EXTENSION)?,
        ]
        .into(),
    };
    let report = HsrpMonitor::new(Some(0), limits).run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::IncludeRaw,
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        write_hsrp(&context, Some(0), &report, format, &mut output)?;
        let text = String::from_utf8(output)?;
        assert!(
            text.contains("4175746850407373"),
            "raw candidate was not included"
        );
        assert!(
            !text.contains(fixture::SECRET),
            "backend diagnostic must remain code-only"
        );
        if format == OutputFormat::Json {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            for (index, expected) in [ADVERTISEMENT, EXTENSION].into_iter().enumerate() {
                let observation = value
                    .pointer(&format!("/observations/{index}"))
                    .ok_or("missing candidate")?;
                crate::fixture_assert::frame_hex(observation, expected)?;
            }
        }
    }
    Ok(())
}

#[test]
fn silent_hsrp_window_is_inconclusive_without_raw_frames() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(10), 8, 4096)?;
    let mut link = crate::test_support::Link::new(Vec::new(), Some(0))?;
    let report = HsrpMonitor::new(None, limits).run(&mut link, &AtomicBool::new(false))?;
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
        write_hsrp(&context, None, &report, OutputFormat::Json, &mut output)?,
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
        value.pointer("/tx/attempted"),
        Some(&serde_json::Value::Bool(false))
    );
    Ok(())
}
