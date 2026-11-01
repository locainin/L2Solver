use std::error::Error;

use clap::Parser;

use crate::{ActiveCommand, Cli, HsrpCommand, VrrpCommand};

#[test]
fn cancelled_first_hop_commands_stop_before_interface_discovery() -> Result<(), Box<dyn Error>> {
    for protocol in ["vrrp", "hsrp"] {
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
        let outcome = crate::execute(
            &cli.active,
            &std::sync::atomic::AtomicBool::new(true),
            &mut output,
        )?;
        assert_eq!(outcome, crate::ActiveOutcome::Cancelled);
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            value.pointer("/tx/attempted"),
            Some(&serde_json::Value::Bool(false))
        );
        assert_eq!(
            value
                .pointer("/cleanup/state")
                .and_then(serde_json::Value::as_str),
            Some("not_started")
        );
    }
    Ok(())
}

#[test]
fn discovery_failures_for_first_hop_commands_expose_only_code_and_stage()
-> Result<(), Box<dyn Error>> {
    for protocol in ["vrrp", "hsrp"] {
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
        let Err(error) = crate::execute(
            &cli.active,
            &std::sync::atomic::AtomicBool::new(false),
            &mut output,
        ) else {
            return Err("missing interface must fail".into());
        };
        assert_eq!(error.code(), "not_found");
        assert_eq!(error.stage(), "discovery");
        assert!(!error.to_string().contains("l2s-no-test"));
        assert!(!format!("{error:?}").contains("l2s-no-test"));
    }
    Ok(())
}

#[test]
fn vrrp_and_hsrp_require_an_explicit_interface_and_bounded_session() {
    for operation in ["vrrp", "hsrp"] {
        assert!(Cli::try_parse_from(["l2solver-active", operation, "observe"]).is_err());
        for flag in [
            "--timeout-ms",
            "--max-received-packets",
            "--max-received-bytes",
        ] {
            assert!(
                Cli::try_parse_from([
                    "l2solver-active",
                    operation,
                    "observe",
                    "--interface",
                    "test0",
                    flag,
                    "0",
                ])
                .is_err(),
                "{operation} accepted {flag}=0"
            );
        }
    }
}

#[test]
fn vrrp_defaults_to_no_raw_data_and_validates_the_selected_router_id() -> Result<(), Box<dyn Error>>
{
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "vrrp",
        "observe",
        "--interface",
        "test0",
        "--vrid",
        "42",
    ])?;
    let ActiveCommand::Vrrp {
        command: VrrpCommand::Observe(options),
    } = cli.active.command
    else {
        return Err("expected VRRP observation".into());
    };
    assert_eq!(options.vrid.map(std::num::NonZeroU8::get), Some(42));
    assert!(!options.observe.include_raw);
    for invalid in ["0", "256"] {
        assert!(
            Cli::try_parse_from([
                "l2solver-active",
                "vrrp",
                "observe",
                "--interface",
                "test0",
                "--vrid",
                invalid,
            ])
            .is_err(),
            "VRRP accepted VRID {invalid}"
        );
    }
    Ok(())
}

#[test]
fn hsrp_accepts_both_group_boundaries_and_requires_opt_in_for_raw_data()
-> Result<(), Box<dyn Error>> {
    for group in ["0", "255"] {
        let cli = Cli::try_parse_from([
            "l2solver-active",
            "hsrp",
            "observe",
            "--interface",
            "test0",
            "--group",
            group,
            "--include-raw",
        ])?;
        let ActiveCommand::Hsrp {
            command: HsrpCommand::Observe(options),
        } = cli.active.command
        else {
            return Err("expected HSRP observation".into());
        };
        assert_eq!(options.group, Some(group.parse()?));
        assert!(options.observe.include_raw);
    }
    assert!(
        Cli::try_parse_from([
            "l2solver-active",
            "hsrp",
            "observe",
            "--interface",
            "test0",
            "--group",
            "256",
        ])
        .is_err()
    );
    let cli = Cli::try_parse_from(["l2solver-active", "hsrp", "observe", "--interface", "test0"])?;
    let ActiveCommand::Hsrp {
        command: HsrpCommand::Observe(options),
    } = cli.active.command
    else {
        return Err("expected HSRP observation".into());
    };
    assert!(options.group.is_none());
    assert!(!options.observe.include_raw);
    Ok(())
}
