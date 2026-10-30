use std::{error::Error as StdError, sync::atomic::AtomicBool, time::Duration};

use clap::Parser;
use l2_active::{Limits, ReceiveEvent, dot1x::Dot1xProbe};
use l2_onpath::MacAddress;

use super::write;
use crate::{
    ActiveCommand, ActiveOutcome, Cli, Dot1xCommand, Dot1xProbeArgs, OutputFormat,
    test_support as support,
};

const REQUEST: &[u8] = include_bytes!("../../../l2-active/tests/dot1x/fixtures/request.bin");

fn options() -> Result<Dot1xProbeArgs, Box<dyn StdError>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "dot1x",
        "probe",
        "--interface",
        "test0",
        "--allow-eapol-start",
        "--dedicated-interface",
    ])?;
    let ActiveCommand::Dot1x {
        command: Dot1xCommand::Probe(options),
    } = cli.active.command
    else {
        return Err("expected 802.1X probe".into());
    };
    Ok(options)
}

fn probe() -> Result<Dot1xProbe, Box<dyn StdError>> {
    Ok(Dot1xProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        Limits::new(Duration::from_millis(40), 8, 4096)?,
    )?)
}

fn frame(bytes: &[u8]) -> Result<ReceiveEvent, Box<dyn StdError>> {
    Ok(ReceiveEvent::Frame(support::captured(
        bytes.to_vec(),
        Some(support::identity()?),
        u32::try_from(bytes.len())?,
    )?))
}

#[test]
fn observed_request_retains_frame_without_claiming_authentication() -> Result<(), Box<dyn StdError>>
{
    let plan = probe()?;
    let mut link = support::Link::new(vec![frame(REQUEST)?], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut output = Vec::new();
    assert_eq!(
        write(
            &options()?,
            &plan,
            &report,
            None,
            OutputFormat::Json,
            &mut output
        )?,
        ActiveOutcome::Completed
    );
    let value: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        value
            .pointer("/requests/0/identifier")
            .and_then(serde_json::Value::as_u64),
        Some(41)
    );
    assert_eq!(
        value
            .pointer("/requests/0/captured_bytes")
            .and_then(serde_json::Value::as_u64),
        Some(u64::try_from(REQUEST.len())?)
    );
    assert_eq!(
        value
            .get("authenticated")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(link.sent.len(), 1);
    Ok(())
}

#[test]
fn malformed_frame_keeps_valid_request_but_makes_completion_incomplete()
-> Result<(), Box<dyn StdError>> {
    let mut malformed = REQUEST.to_vec();
    malformed
        .get_mut(16..18)
        .ok_or("missing EAPOL length")?
        .copy_from_slice(&100_u16.to_be_bytes());
    let plan = probe()?;
    let mut link = support::Link::new(vec![frame(REQUEST)?, frame(&malformed)?], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut output = Vec::new();
    assert_eq!(
        write(
            &options()?,
            &plan,
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
            .pointer("/malformed/0/reason")
            .and_then(serde_json::Value::as_str),
        Some("EapolHeader")
    );
    assert_eq!(
        value
            .pointer("/requests/0/identifier")
            .and_then(serde_json::Value::as_u64),
        Some(41)
    );
    Ok(())
}

#[test]
fn no_request_is_inconclusive_after_a_clean_window() -> Result<(), Box<dyn StdError>> {
    let plan = probe()?;
    let mut link = support::Link::new(vec![], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut output = Vec::new();
    assert_eq!(
        write(
            &options()?,
            &plan,
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
        Some("inconclusive")
    );
    Ok(())
}
