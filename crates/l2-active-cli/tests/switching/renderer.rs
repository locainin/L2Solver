use std::{error::Error, io, sync::atomic::AtomicBool, time::Duration};

use l2_active::{
    Limits,
    switching::{dtp::DtpMonitor, vtp::VtpMonitor},
};
use l2_active_linux::InterfaceSelector;

use crate::{
    ActiveOutcome, OutputFormat,
    first_hop_tests::fixture::{self, SensitiveLink},
    listen_output::collection::{Context, Disclosure},
};

const DTP: &[u8] = include_bytes!("../../../l2-active/tests/switching/fixtures/dtp.bin");
const VTP: &[u8] = include_bytes!("../../../l2-active/tests/switching/fixtures/vtp-summary.bin");
const SUBSET: &[u8] = include_bytes!("../../../l2-active/tests/switching/fixtures/vtp-subset.bin");

#[test]
fn dtp_structured_output_reports_claims_without_raw_frames_or_error_text()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(25), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(DTP)?].into(),
    };
    let report = DtpMonitor::new(limits).run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let error = io::Error::other(fixture::SECRET);
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: Some(&error),
        disclosure: Disclosure::OmitRaw,
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        assert_eq!(
            super::write_dtp(&context, &report, format, &mut output)?,
            ActiveOutcome::Incomplete
        );
        let text = String::from_utf8(output)?;
        fixture::assert_no_secrets(&text);
        assert!(!text.contains("frame_hex"));
        assert!(!text.contains("PADDING-SECRET"));
        if format == OutputFormat::Json {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            assert_eq!(
                value
                    .pointer("/observations/0/disposition")
                    .and_then(serde_json::Value::as_str),
                Some("advertisement")
            );
            assert_eq!(
                value
                    .pointer("/observations/0/status_raw")
                    .and_then(serde_json::Value::as_u64),
                Some(0x83)
            );
            assert_eq!(
                value
                    .pointer("/observations/0/domain_hex")
                    .and_then(serde_json::Value::as_str),
                Some("505249564154452d444f4d41494e00")
            );
            assert_eq!(
                value.pointer("/tx/attempted"),
                Some(&serde_json::Value::Bool(false))
            );
            assert_eq!(
                value
                    .pointer("/transport_error/message")
                    .and_then(serde_json::Value::as_str),
                Some("io_error")
            );
        }
    }
    Ok(())
}

#[test]
fn vtp_structured_fields_omit_digest_and_raw_frames_until_opted_in() -> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(25), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(VTP)?, fixture::captured(SUBSET)?].into(),
    };
    let report = VtpMonitor::new(limits).run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let mut context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    let mut output = Vec::new();
    super::write_vtp(&context, &report, OutputFormat::Json, &mut output)?;
    let text = String::from_utf8(output)?;
    assert!(!text.contains("frame_hex"));
    assert!(!text.contains("DIGEST-SECRET"));
    assert!(!text.contains("4449474553542d534543524554212121"));
    assert!(!text.contains("PADDING-SECRET"));
    fixture::assert_no_secrets(&text);
    let value: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(
        value
            .pointer("/observations/0/revision")
            .and_then(serde_json::Value::as_u64),
        Some(0x0102_0304)
    );
    assert_eq!(
        value
            .pointer("/observations/1/vlans/0/id")
            .and_then(serde_json::Value::as_u64),
        Some(37)
    );
    assert_eq!(
        value
            .pointer("/observations/1/vlans/0/name_hex")
            .and_then(serde_json::Value::as_str),
        Some("5345435245542d564c414e")
    );
    context.disclosure = Disclosure::IncludeRaw;
    let mut raw = Vec::new();
    super::write_vtp(&context, &report, OutputFormat::Json, &mut raw)?;
    let value: serde_json::Value = serde_json::from_slice(&raw)?;
    crate::fixture_assert::frame_hex(
        value
            .pointer("/observations/0")
            .ok_or("missing observation")?,
        VTP,
    )?;
    Ok(())
}

#[test]
fn vtp_domain_control_and_non_utf8_bytes_are_hex_encoded_in_text_and_json()
-> Result<(), Box<dyn Error>> {
    let mut frame = VTP.to_vec();
    *frame.get_mut(26).ok_or("missing first domain byte")? = 0x1b;
    *frame.get_mut(27).ok_or("missing second domain byte")? = 0xff;
    let limits = Limits::new(Duration::from_millis(25), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(&frame)?].into(),
    };
    let report = VtpMonitor::new(limits).run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: None,
        disclosure: Disclosure::OmitRaw,
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        super::write_vtp(&context, &report, format, &mut output)?;
        let text = String::from_utf8(output)?;
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("1bff49564154452d444f4d41494e"));
        assert!(!text.contains("frame_hex"));
    }
    Ok(())
}
