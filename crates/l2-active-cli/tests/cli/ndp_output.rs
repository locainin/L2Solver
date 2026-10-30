use std::{error::Error as StdError, sync::atomic::AtomicBool, time::Duration};

use clap::Parser;
use l2_active::{Limits, NdpProbe, ReceiveEvent};
use l2_onpath::MacAddress;

use super::write;
use crate::{ActiveCommand, ActiveOutcome, Cli, NdpCommand, OutputFormat, test_support as support};

const ADVERTISEMENT: &[u8] =
    include_bytes!("../../../l2-active/tests/ndp/fixtures/advertisement.bin");

#[test]
fn default_text_reports_neighbor_claim_and_observation_limits() -> Result<(), Box<dyn StdError>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "ndp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "fe80::2",
        "--source-ip",
        "fe80::1",
        "--expected-mac",
        "02:00:00:00:00:02",
    ])?;
    assert_eq!(cli.active.format, OutputFormat::Text);
    let ActiveCommand::Ndp {
        command: NdpCommand::Probe(options),
    } = cli.active.command
    else {
        return Err("expected NDP probe".into());
    };
    let plan = NdpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        "fe80::1".parse()?,
        64,
        "fe80::2".parse()?,
        Some(MacAddress::new([2, 0, 0, 0, 0, 2])?),
        Limits::new(Duration::from_millis(40), 8, 4096)?,
    )?;
    let frame = support::captured(
        ADVERTISEMENT.to_vec(),
        Some(support::identity()?),
        u32::try_from(ADVERTISEMENT.len())?,
    )?;
    let mut link = support::Link::new(vec![ReceiveEvent::Frame(frame)], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    assert_eq!(
        write(
            &options,
            &plan,
            &report,
            None,
            OutputFormat::Text,
            &mut bytes
        )?,
        ActiveOutcome::Completed
    );
    let text = String::from_utf8(bytes)?;
    assert!(
        text.contains("NDP probe: fe80::2 on test0  status: observed"),
        "{text}"
    );
    assert!(
        text.contains("Reply: 02:00:00:00:00:02 from fe80::2  expected match: yes"),
        "{text}"
    );
    assert!(text.contains("socket acceptance: confirmed"), "{text}");
    assert!(text.contains("Helper cleanup: confirmed"), "{text}");
    assert!(text.contains("unauthenticated claims"), "{text}");
    Ok(())
}

#[test]
fn unexpected_neighbor_claim_is_retained_when_capture_loss_makes_it_incomplete()
-> Result<(), Box<dyn StdError>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "ndp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "fe80::2",
        "--source-ip",
        "fe80::1",
        "--expected-mac",
        "02:00:00:00:00:03",
    ])?;
    let ActiveCommand::Ndp {
        command: NdpCommand::Probe(options),
    } = cli.active.command
    else {
        return Err("expected NDP probe".into());
    };
    let plan = NdpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        "fe80::1".parse()?,
        64,
        "fe80::2".parse()?,
        Some(MacAddress::new([2, 0, 0, 0, 0, 3])?),
        Limits::new(Duration::from_millis(40), 8, 4096)?,
    )?;
    for (loss, expected_outcome) in [(0, ActiveOutcome::Findings), (2, ActiveOutcome::Incomplete)] {
        let frame = support::captured(
            ADVERTISEMENT.to_vec(),
            Some(support::identity()?),
            u32::try_from(ADVERTISEMENT.len())?,
        )?;
        let mut link = support::Link::new(vec![ReceiveEvent::Frame(frame)], Some(loss))?;
        let report = plan.run(&mut link, &AtomicBool::new(false))?;
        let mut bytes = Vec::new();
        assert_eq!(
            write(
                &options,
                &plan,
                &report,
                None,
                OutputFormat::Json,
                &mut bytes
            )?,
            expected_outcome
        );
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            value.get("status").and_then(serde_json::Value::as_str),
            Some("unexpected_identity")
        );
        assert_eq!(
            value
                .pointer("/replies/0/matches_expected")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            value
                .pointer("/rx/capture_loss")
                .and_then(serde_json::Value::as_u64),
            Some(loss)
        );
        assert_eq!(
            value
                .pointer("/replies/0/captured_bytes")
                .and_then(serde_json::Value::as_u64),
            Some(u64::try_from(ADVERTISEMENT.len())?)
        );
        let reply = value.pointer("/replies/0").ok_or("missing reply")?;
        crate::fixture_assert::frame_hex(reply, ADVERTISEMENT)?;
    }
    Ok(())
}
