use std::{error::Error, process::Command};

use clap::Parser;
use l2_active_cli::{ActiveCommand, ArpCommand, Cli, OutputFormat};

fn run(arguments: &[&str]) -> Result<std::process::Output, Box<dyn Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_l2solver-active"))
        .args(arguments)
        .output()?)
}

#[test]
fn capabilities_requires_an_explicit_interface() -> Result<(), Box<dyn Error>> {
    let output = run(&["capabilities"])?;
    let error = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(2));
    assert!(error.contains("--interface"), "{error}");
    Ok(())
}

#[test]
fn arp_probe_requires_the_interface_and_target_before_any_execution() -> Result<(), Box<dyn Error>>
{
    let missing_interface = run(&["arp", "probe", "--target", "192.0.2.10"])?;
    let error = String::from_utf8(missing_interface.stderr)?;
    assert_eq!(missing_interface.status.code(), Some(2));
    assert!(error.contains("--interface"), "{error}");

    let missing_target = run(&["arp", "probe", "--interface", "test0"])?;
    let error = String::from_utf8(missing_target.stderr)?;
    assert_eq!(missing_target.status.code(), Some(2));
    assert!(error.contains("--target"), "{error}");
    Ok(())
}

#[test]
fn arp_probe_rejects_multicast_target_and_zero_timeout_before_execution()
-> Result<(), Box<dyn Error>> {
    let multicast = run(&[
        "arp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "224.0.0.1",
    ])?;
    let error = String::from_utf8(multicast.stderr)?;
    assert_eq!(multicast.status.code(), Some(2));
    assert!(error.contains("target"), "{error}");

    let timeout = run(&[
        "arp",
        "probe",
        "--interface",
        "test0",
        "--target",
        "192.0.2.10",
        "--timeout-ms",
        "0",
    ])?;
    let error = String::from_utf8(timeout.stderr)?;
    assert_eq!(timeout.status.code(), Some(2));
    assert!(error.contains("timeout"), "{error}");
    Ok(())
}

#[test]
fn help_lists_real_operation_without_advertising_unimplemented_protocols()
-> Result<(), Box<dyn Error>> {
    let output = run(&["--help"])?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("capabilities"), "{help}");
    assert!(help.contains("arp"), "{help}");
    assert!(help.contains("dhcp"), "{help}");
    assert!(help.contains("ndp"), "{help}");
    assert!(help.contains("stp"), "{help}");
    assert!(help.contains("discovery"), "{help}");
    assert!(help.contains("dot1x"), "{help}");
    Ok(())
}

#[test]
fn invalid_interface_name_is_rejected_before_interface_discovery() -> Result<(), Box<dyn Error>> {
    let output = run(&["capabilities", "--interface", "bad/name"])?;
    let error = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(2));
    assert!(error.contains("interface"), "{error}");
    Ok(())
}

#[test]
fn malformed_or_multicast_expected_mac_is_rejected_before_interface_discovery()
-> Result<(), Box<dyn Error>> {
    for mac in ["02:00:00:00:00", "01:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"] {
        let output = run(&[
            "arp",
            "probe",
            "--interface",
            "test0",
            "--target",
            "192.0.2.10",
            "--expected-mac",
            mac,
        ])?;
        let error = String::from_utf8(output.stderr)?;
        assert_eq!(output.status.code(), Some(2), "MAC {mac}: {error}");
        assert!(error.contains("expected-mac"), "MAC {mac}: {error}");
    }
    Ok(())
}

#[test]
fn explicit_probe_scope_and_finite_limits_parse_without_opening_a_network_interface()
-> Result<(), Box<dyn Error>> {
    let parsed = Cli::try_parse_from([
        "l2solver-active",
        "arp",
        "probe",
        "--interface",
        "eth0",
        "--target",
        "192.0.2.10",
        "--source-ip",
        "192.0.2.2",
        "--timeout-ms",
        "250",
        "--max-received-packets",
        "12",
        "--max-received-bytes",
        "8192",
        "--helper",
        "tools/active-helper",
        "--format",
        "json",
    ])?;
    assert_eq!(parsed.active.format, OutputFormat::Json);
    let ActiveCommand::Arp {
        command: ArpCommand::Probe(probe),
    } = parsed.active.command
    else {
        return Err("expected ARP probe".into());
    };
    assert_eq!(probe.interface.name(), "eth0");
    assert_eq!(probe.target.to_string(), "192.0.2.10");
    assert_eq!(
        probe.source_ip.map(|address| address.to_string()),
        Some("192.0.2.2".into())
    );
    assert_eq!(probe.timeout_ms, 250);
    assert_eq!(probe.max_received_packets, 12);
    assert_eq!(probe.max_received_bytes, 8192);
    assert_eq!(
        probe.helper.as_deref(),
        Some(std::path::Path::new("tools/active-helper"))
    );
    Ok(())
}
