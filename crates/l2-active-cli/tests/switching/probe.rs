use std::{error::Error, sync::atomic::AtomicBool};

use clap::Parser;

use crate::{ActiveOutcome, Cli, execute};

#[test]
fn cancelled_switching_observers_do_not_open_or_send() -> Result<(), Box<dyn Error>> {
    for protocol in ["dtp", "vtp", "isl"] {
        let cli = Cli::try_parse_from([
            "l2solver-active",
            protocol,
            "observe",
            "--interface",
            "l2s-no-test",
            "--format",
            "json",
        ])?;
        let mut output = Vec::new();
        assert_eq!(
            execute(&cli.active, &AtomicBool::new(true), &mut output)?,
            ActiveOutcome::Cancelled
        );
        let report: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            report.get("operation").and_then(serde_json::Value::as_str),
            Some(format!("{protocol}_observe").as_str())
        );
        assert_eq!(
            report.pointer("/tx/attempted"),
            Some(&serde_json::Value::Bool(false))
        );
        assert_eq!(
            report
                .pointer("/cleanup/state")
                .and_then(serde_json::Value::as_str),
            Some("not_started")
        );
    }
    Ok(())
}
