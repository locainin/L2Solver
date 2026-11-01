use std::{error::Error, io, sync::atomic::AtomicBool, time::Duration};

use l2_active::{Limits, isl::IslMonitor};
use l2_active_linux::InterfaceSelector;

use crate::{
    ActiveOutcome, OutputFormat,
    first_hop_tests::fixture::{self, SensitiveLink},
    listen_output::collection::{Context, Disclosure},
};

const FRAME: &[u8] = include_bytes!("../../../l2-active/tests/isl/fixtures/valid.bin");

#[test]
fn isl_structured_output_hides_encapsulated_traffic_and_error_contents()
-> Result<(), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(25), 8, 4096)?;
    let mut link = SensitiveLink {
        identity: fixture::identity()?,
        frames: [fixture::captured(FRAME)?].into(),
    };
    let report = IslMonitor::new(limits).run(&mut link, &AtomicBool::new(false))?;
    let selector = InterfaceSelector::new("test0")?;
    let error = io::Error::other(fixture::SECRET);
    let mut context = Context {
        interface: &selector,
        vlan: None,
        limits,
        close_error: Some(&error),
        disclosure: Disclosure::OmitRaw,
    };
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        assert_eq!(
            super::write(&context, &report, format, &mut output)?,
            ActiveOutcome::Incomplete
        );
        let text = String::from_utf8(output)?;
        fixture::assert_no_secrets(&text);
        assert!(!text.contains("frame_hex"));
        assert!(!text.contains("PRIVATE-USER-CONTENT"));
        assert!(!text.contains("505249564154452d555345522d434f4e54454e54"));
        if format == OutputFormat::Json {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            assert_eq!(
                value
                    .pointer("/observations/0/vlan_id")
                    .and_then(serde_json::Value::as_u64),
                Some(37)
            );
            assert_eq!(
                value
                    .pointer("/observations/0/port_index")
                    .and_then(serde_json::Value::as_u64),
                Some(17)
            );
            assert_eq!(
                value.pointer("/tx/attempted"),
                Some(&serde_json::Value::Bool(false))
            );
        }
    }
    context.disclosure = Disclosure::IncludeRaw;
    let mut output = Vec::new();
    super::write(&context, &report, OutputFormat::Json, &mut output)?;
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    crate::fixture_assert::frame_hex(
        value
            .pointer("/observations/0")
            .ok_or("missing observation")?,
        FRAME,
    )?;
    Ok(())
}
