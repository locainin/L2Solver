use std::{error::Error as StdError, io, sync::atomic::AtomicBool};

use super::fixture::SECRET;
use crate::{Error, OutputFormat, write_error};

#[test]
fn discovery_timeout_reports_an_incomplete_window_before_opening_a_helper()
-> Result<(), Box<dyn StdError>> {
    let cancelled = AtomicBool::new(false);
    let stop = crate::preflight::discovery_failure(io::ErrorKind::TimedOut.into(), &cancelled)?;
    let selector = l2_active_linux::InterfaceSelector::new("test0")?;
    let mut output = Vec::new();
    let outcome = crate::preflight::write_stopped(
        "vrrp_observe",
        &selector,
        None,
        OutputFormat::Json,
        &mut output,
        stop,
        crate::preflight::HelperStage::NotStarted,
    )?;
    assert_eq!(outcome, crate::ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value.get("stop_reason").and_then(serde_json::Value::as_str),
        Some("discovery_timeout")
    );
    assert_eq!(
        value
            .pointer("/cleanup/state")
            .and_then(serde_json::Value::as_str),
        Some("not_started")
    );
    assert_eq!(
        value.pointer("/tx/attempted"),
        Some(&serde_json::Value::Bool(false))
    );
    let unexpected =
        crate::preflight::discovery_failure(io::ErrorKind::PermissionDenied.into(), &cancelled);
    assert!(matches!(unexpected, Err(Error::Discovery(_))));
    Ok(())
}

#[test]
fn observer_errors_keep_code_and_stage_without_untrusted_error_text()
-> Result<(), Box<dyn StdError>> {
    let failure = Error::Helper(io::Error::other(SECRET)).codes_only();
    assert_eq!(failure.code(), "io_error");
    assert_eq!(failure.stage(), "helper");
    assert!(!format!("{failure:?}").contains(SECRET));
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut output = Vec::new();
        write_error(&failure, format, &mut output)?;
        let text = String::from_utf8(output)?;
        super::fixture::assert_no_secrets(&text);
        assert!(
            text.contains("io_error"),
            "missing safe diagnostic category"
        );
        if format == OutputFormat::Json {
            let value: serde_json::Value = serde_json::from_str(&text)?;
            assert_eq!(
                value.get("stage").and_then(serde_json::Value::as_str),
                Some("helper")
            );
            assert_eq!(
                value.get("code").and_then(serde_json::Value::as_str),
                Some("io_error")
            );
        }
    }
    Ok(())
}
