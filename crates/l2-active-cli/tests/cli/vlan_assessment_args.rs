use std::error::Error;

use clap::Parser;
use l2_active_cli::{ActiveCommand, Cli, VlanCommand};

#[test]
fn vlan_assessment_requires_both_interfaces_the_canary_and_its_expected_mac() {
    let required = [
        ("--interface", "test0"),
        ("--control-interface", "control0"),
        ("--target", "192.0.2.20"),
        ("--expected-mac", "02:00:00:00:00:02"),
    ];
    for omitted in 0..required.len() {
        let mut arguments = vec!["l2solver-active", "vlan", "assess"];
        for (index, (flag, value)) in required.iter().enumerate() {
            if index != omitted {
                arguments.extend([*flag, *value]);
            }
        }
        assert!(
            Cli::try_parse_from(arguments).is_err(),
            "missing {} was accepted",
            required.get(omitted).map_or("argument", |item| item.0)
        );
    }
}

#[test]
fn vlan_assessment_parses_both_source_choices_and_one_shared_finite_budget()
-> Result<(), Box<dyn Error>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "vlan",
        "assess",
        "--interface",
        "test0",
        "--control-interface",
        "control0",
        "--target",
        "192.0.2.20",
        "--expected-mac",
        "02:00:00:00:00:02",
        "--source-ip",
        "192.0.2.10",
        "--control-source-ip",
        "192.0.2.11",
        "--timeout-ms",
        "3000",
        "--max-received-packets",
        "24",
        "--max-received-bytes",
        "8192",
    ])?;
    let ActiveCommand::Vlan {
        command: VlanCommand::Assess(options),
    } = cli.active.command
    else {
        return Err("expected VLAN assessment".into());
    };
    assert_eq!(options.interface.name(), "test0");
    assert_eq!(options.control_interface.name(), "control0");
    assert_eq!(options.target.to_string(), "192.0.2.20");
    assert_eq!(options.expected_mac.bytes(), [2, 0, 0, 0, 0, 2]);
    assert_eq!(
        options.source_ip.map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(
        options
            .control_source_ip
            .map(|ip| ip.to_string())
            .as_deref(),
        Some("192.0.2.11")
    );
    assert_eq!(options.session.timeout_ms, 3_000);
    assert_eq!(options.session.max_received_packets, 24);
    assert_eq!(options.session.max_received_bytes, 8192);
    assert!(!options.include_raw);
    Ok(())
}

#[test]
fn vlan_assessment_requires_explicit_raw_frame_opt_in() -> Result<(), Box<dyn Error>> {
    let cli = Cli::try_parse_from([
        "l2solver-active", "vlan", "assess", "--interface", "test0", "--control-interface", "control0",
        "--target", "192.0.2.20", "--expected-mac", "02:00:00:00:00:02", "--include-raw",
    ])?;
    let ActiveCommand::Vlan { command: VlanCommand::Assess(options) } = cli.active.command else {
        return Err("expected VLAN assessment".into());
    };
    assert!(options.include_raw);
    Ok(())
}

#[test]
fn vlan_assessment_rejects_invalid_canary_mac_target_and_zero_budget() {
    for (flag, value) in [
        ("--expected-mac", "ff:ff:ff:ff:ff:ff"),
        ("--target", "224.0.0.1"),
        ("--timeout-ms", "0"),
        ("--max-received-packets", "0"),
        ("--max-received-bytes", "0"),
    ] {
        let mut args = vec![
            "l2solver-active",
            "vlan",
            "assess",
            "--interface",
            "test0",
            "--control-interface",
            "control0",
        ];
        if flag != "--target" {
            args.extend(["--target", "192.0.2.20"]);
        }
        if flag != "--expected-mac" {
            args.extend(["--expected-mac", "02:00:00:00:00:02"]);
        }
        args.extend([flag, value]);
        assert!(
            Cli::try_parse_from(args).is_err(),
            "{flag} accepted {value}"
        );
    }
}
