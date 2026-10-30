use std::{error::Error, fs::OpenOptions, io, sync::atomic::AtomicBool, time::Duration};

use l2_active::{
    Limits,
    discovery::{DiscoveryMonitor, DiscoveryReport},
};
use l2_active_linux::InterfaceSelector;
use l2_capture::LinuxInterfaceIdentity;

use super::Link;
use crate::{ActiveOutcome, OutputFormat, listen_output};

fn silent_report() -> Result<(Limits, DiscoveryReport), Box<dyn Error>> {
    let limits = Limits::new(Duration::from_millis(20), 8, 1024)?;
    let report = DiscoveryMonitor::new(limits).run(
        &mut Link {
            identity: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
            frames: std::collections::VecDeque::new(),
            loss: Some(0),
            backlog: Some(false),
        },
        &AtomicBool::new(false),
    )?;
    Ok((limits, report))
}

#[test]
fn listener_text_escapes_unicode_controls_and_json_preserves_original_values()
-> Result<(), Box<dyn Error>> {
    let interface = "if\u{202e}0";
    let diagnostic =
        "failure \u{001b}\u{007f}\u{009b}\u{061c}\u{200e}\u{2069}\u{206f}\u{2028} café 🚀";
    let selector = InterfaceSelector::new(interface)?;
    let (limits, report) = silent_report()?;
    let error = io::Error::other(diagnostic);
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        let outcome = listen_output::write_discovery(
            &selector,
            limits,
            &report,
            Some(&error),
            format,
            &mut output,
        )?;
        assert_eq!(outcome, ActiveOutcome::Incomplete);
        let text = String::from_utf8(output)?;
        for control in [
            '\u{202e}', '\u{001b}', '\u{007f}', '\u{009b}', '\u{061c}', '\u{200e}', '\u{2069}',
            '\u{206f}', '\u{2028}',
        ] {
            assert!(
                !text.contains(control),
                "raw control {control:?} in {format:?} output"
            );
        }
        assert!(text.contains("café 🚀"));
        let json = match format {
            OutputFormat::Json => text.as_str(),
            OutputFormat::Text => text.split_once('\n').ok_or("missing JSON body")?.1,
        };
        if format == OutputFormat::Text {
            assert!(json.starts_with("{\n  \"operation\":"));
        }
        let report: serde_json::Value = serde_json::from_str(json)?;
        assert_eq!(
            report
                .pointer("/scope/interface")
                .and_then(serde_json::Value::as_str),
            Some(interface)
        );
        assert_eq!(
            report
                .pointer("/cleanup/error")
                .and_then(serde_json::Value::as_str),
            Some(diagnostic)
        );
    }
    Ok(())
}

#[test]
fn listener_json_propagates_real_output_failure() -> Result<(), Box<dyn Error>> {
    let selector = InterfaceSelector::new("test0")?;
    let (limits, report) = silent_report()?;
    let mut full = OpenOptions::new().write(true).open("/dev/full")?;
    assert!(matches!(
        listen_output::write_discovery(
            &selector,
            limits,
            &report,
            None,
            OutputFormat::Json,
            &mut full,
        ),
        Err(crate::Error::Json(_))
    ));
    Ok(())
}
