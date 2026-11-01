use std::error::Error;

use clap::Parser;

use crate::{ActiveCommand, Cli, MplsCommand, ObserveCommand};

#[test]
fn receive_only_observers_require_an_interface_and_explicit_raw_opt_in()
-> Result<(), Box<dyn Error>> {
    for protocol in ["dtp", "vtp", "isl"] {
        assert!(Cli::try_parse_from(["l2solver-active", protocol, "observe"]).is_err());
        let cli = Cli::try_parse_from([
            "l2solver-active",
            protocol,
            "observe",
            "--interface",
            "test0",
        ])?;
        let options = match cli.active.command {
            ActiveCommand::Dtp {
                command: ObserveCommand::Observe(options),
            }
            | ActiveCommand::Vtp {
                command: ObserveCommand::Observe(options),
            }
            | ActiveCommand::Isl {
                command: ObserveCommand::Observe(options),
            } => options,
            _ => return Err("expected receive-only observation".into()),
        };
        assert!(!options.include_raw);
        let cli = Cli::try_parse_from([
            "l2solver-active",
            protocol,
            "observe",
            "--interface",
            "test0",
            "--include-raw",
        ])?;
        let options = match cli.active.command {
            ActiveCommand::Dtp {
                command: ObserveCommand::Observe(options),
            }
            | ActiveCommand::Vtp {
                command: ObserveCommand::Observe(options),
            }
            | ActiveCommand::Isl {
                command: ObserveCommand::Observe(options),
            } => options,
            _ => return Err("expected receive-only observation".into()),
        };
        assert!(options.include_raw);
    }
    Ok(())
}

#[test]
fn mpls_selected_top_label_is_limited_to_twenty_bits() -> Result<(), Box<dyn Error>> {
    for (label, expected) in [("0", 0), ("1048575", 1_048_575)] {
        let cli = Cli::try_parse_from([
            "l2solver-active",
            "mpls",
            "observe",
            "--interface",
            "test0",
            "--expected-top-label",
            label,
        ])?;
        let ActiveCommand::Mpls {
            command: MplsCommand::Observe(options),
        } = cli.active.command
        else {
            return Err("expected MPLS observation".into());
        };
        assert_eq!(options.expected_top_label, Some(expected));
        assert!(!options.observe.include_raw);
    }
    assert!(
        Cli::try_parse_from([
            "l2solver-active",
            "mpls",
            "observe",
            "--interface",
            "test0",
            "--expected-top-label",
            "1048576",
        ])
        .is_err()
    );
    Ok(())
}
