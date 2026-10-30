use std::{
    error::Error as StdError, io, net::Ipv4Addr, num::NonZeroU32, sync::atomic::AtomicBool,
    time::Duration,
};

use clap::Parser;
use l2_active::{Limits, ReceiveEvent, dhcp::DhcpProbe};
use l2_onpath::MacAddress;

use super::write;
use crate::test_support as support;
use crate::{ActiveCommand, ActiveOutcome, Cli, DhcpCommand, DhcpProbeArgs, OutputFormat};

const OFFER: &[u8] = include_bytes!("../../../l2-active/tests/dhcp/fixtures/offer.bin");
const UNEXPECTED: &[u8] =
    include_bytes!("../../../l2-active/tests/dhcp/fixtures/unexpected-server.bin");
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn options() -> Result<DhcpProbeArgs, Box<dyn StdError>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "dhcp",
        "probe",
        "--interface",
        "test0",
        "--expected-server",
        "192.0.2.1",
    ])?;
    assert_eq!(cli.active.format, OutputFormat::Text);
    let ActiveCommand::Dhcp {
        command: DhcpCommand::Probe(options),
    } = cli.active.command
    else {
        return Err("expected DHCP probe".into());
    };
    Ok(options)
}

#[test]
fn default_text_reports_observed_offer_and_collection_limits() -> Result<(), Box<dyn StdError>> {
    let plan = probe()?;
    let mut link = support::Link::new(vec![frame(OFFER)?], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    assert_eq!(
        write(
            &options()?,
            &plan,
            &report,
            None,
            OutputFormat::Text,
            &mut bytes
        )?,
        ActiveOutcome::Completed
    );
    let text = String::from_utf8(bytes)?;
    assert!(text.contains("DHCP probe on test0: observed"), "{text}");
    assert!(
        text.contains("Offer: server 192.0.2.1  address 192.0.2.10  lease 3600s  expected: yes"),
        "{text}"
    );
    assert!(text.contains("socket acceptance: confirmed"), "{text}");
    assert!(text.contains("Helper cleanup: confirmed"), "{text}");
    assert!(text.contains("unauthenticated claims"), "{text}");
    Ok(())
}

fn probe() -> Result<DhcpProbe, Box<dyn StdError>> {
    Ok(DhcpProbe::new(
        MacAddress::new([2, 0, 0, 0, 0, 1])?,
        NonZeroU32::new(0x1234_5678).ok_or("zero transaction")?,
        Some(&[SERVER]),
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
fn unexpected_server_is_a_finding_with_its_original_offer() -> Result<(), Box<dyn StdError>> {
    let plan = probe()?;
    let mut link = support::Link::new(vec![frame(UNEXPECTED)?], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = write(
        &options()?,
        &plan,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Findings);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("unexpected_server")
    );
    assert_eq!(
        value
            .pointer("/offers/0/matches_expected")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .pointer("/offers/0/captured_bytes")
            .and_then(serde_json::Value::as_u64),
        Some(u64::try_from(UNEXPECTED.len())?)
    );
    assert_eq!(link.sent.len(), 1);
    Ok(())
}

#[test]
fn no_offer_is_inconclusive_after_a_clean_deadline() -> Result<(), Box<dyn StdError>> {
    let plan = probe()?;
    let mut link = support::Link::new(vec![], Some(0))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let mut bytes = Vec::new();
    let outcome = write(
        &options()?,
        &plan,
        &report,
        None,
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("inconclusive")
    );
    assert_eq!(
        value
            .get("offers")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    Ok(())
}

#[test]
fn loss_and_failed_cleanup_keep_the_observed_offer_in_an_incomplete_report()
-> Result<(), Box<dyn StdError>> {
    let plan = probe()?;
    let mut link = support::Link::new(vec![frame(OFFER)?], Some(2))?;
    let report = plan.run(&mut link, &AtomicBool::new(false))?;
    let close = io::Error::other("close was not confirmed");
    let mut bytes = Vec::new();
    let outcome = write(
        &options()?,
        &plan,
        &report,
        Some(&close),
        OutputFormat::Json,
        &mut bytes,
    )?;
    assert_eq!(outcome, ActiveOutcome::Incomplete);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("observed")
    );
    assert_eq!(
        value
            .pointer("/rx/capture_loss")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        value
            .pointer("/cleanup/confirmed")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .pointer("/offers/0/server_identifier")
            .and_then(serde_json::Value::as_str),
        Some("192.0.2.1")
    );
    Ok(())
}
