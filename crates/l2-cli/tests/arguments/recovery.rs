use l2_cli::arguments::{
    CacheCommand, Command, CompletionShell, ProgressMode, RecoveryProfile, parse_byte_size,
    parse_from,
};
use std::path::Path;

#[test]
fn recovery_commands_reject_unknown_options_before_an_input() {
    let kinds = ["extract", "export", "refine"].map(|command| {
        parse_from(["l2solver", command, "--bogus"])
            .err()
            .map(|error| error.kind())
    });
    assert_eq!(kinds, [Some(clap::error::ErrorKind::UnknownArgument); 3]);
}

#[test]
fn recovery_commands_identify_unknown_options_when_an_input_follows()
-> Result<(), Box<dyn std::error::Error>> {
    for command in ["extract", "export", "refine"] {
        let error = parse_from(["l2solver", command, "--bogus", "input.bin"])
            .err()
            .ok_or("the unknown option was accepted")?;
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        assert!(error.to_string().contains("--bogus"), "{command}: {error}");
    }
    Ok(())
}

#[test]
fn extraction_accepts_standard_input_for_both_command_names()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["extract", "export"] {
        let Command::Export(options) = parse_from(["l2solver", name, "-", "-o", "results"])? else {
            return Err(format!("{name} did not select capture extraction").into());
        };
        assert_eq!(options.capture, Path::new("-"), "{name}");
        assert_eq!(options.output.as_deref(), Some(Path::new("results")));
    }
    Ok(())
}

#[test]
fn recovery_commands_accept_hyphenated_input_names_after_separator()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["extract", "export", "refine"] {
        let parsed = parse_from(["l2solver", name, "--", "-input.bin"])?;
        let path = match &parsed {
            Command::Export(options) => &options.capture,
            Command::Refine(options) => &options.input,
            _ => return Err(format!("{name} selected an unexpected command").into()),
        };
        assert_eq!(path, Path::new("-input.bin"), "{name}");
    }
    Ok(())
}

#[test]
fn extraction_uses_shared_recovery_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let Command::Export(options) = parse_from(["l2solver", "extract", "traffic.pcapng"])? else {
        return Err("extract did not select capture extraction".into());
    };

    assert_eq!(options.capture, Path::new("traffic.pcapng"));
    assert_eq!(options.recovery.profile, RecoveryProfile::Normal);
    assert_eq!(options.recovery.progress, ProgressMode::Auto);
    assert_eq!(options.recovery.jobs, None);
    assert_eq!(options.recovery.memory_limit, 512 * 1024 * 1024);
    assert_eq!(options.recovery.cache_max_bytes, 2 * 1024 * 1024 * 1024);
    assert!(!options.recovery.refresh);
    assert!(!options.recovery.no_cache);
    assert!(!options.recovery.strict_cache);
    assert!(!options.recovery.quiet);
    assert_eq!(options.recovery.verbosity, 0);
    Ok(())
}

#[test]
fn extraction_parses_recovery_controls_and_binary_byte_units()
-> Result<(), Box<dyn std::error::Error>> {
    let Command::Export(options) = parse_from([
        "l2solver",
        "extract",
        "traffic.pcapng",
        "--profile",
        "deep",
        "--refresh",
        "--no-cache",
        "--strict-cache",
        "--progress",
        "json",
        "--jobs",
        "7",
        "--quiet",
        "--verbose",
        "-v",
        "--memory-limit",
        "768MiB",
        "--cache-max-bytes",
        "3GiB",
    ])?
    else {
        return Err("extract did not select capture extraction".into());
    };

    assert_eq!(options.recovery.profile, RecoveryProfile::Deep);
    assert_eq!(options.recovery.progress, ProgressMode::Json);
    assert_eq!(options.recovery.jobs, Some(7));
    assert_eq!(options.recovery.memory_limit, 768 * 1024 * 1024);
    assert_eq!(options.recovery.cache_max_bytes, 3 * 1024 * 1024 * 1024);
    assert!(options.recovery.refresh);
    assert!(options.recovery.no_cache);
    assert!(options.recovery.strict_cache);
    assert!(options.recovery.quiet);
    assert_eq!(options.recovery.verbosity, 2);
    Ok(())
}

#[test]
fn recovery_workers_must_be_nonzero() {
    let result = parse_from(["l2solver", "extract", "traffic.pcapng", "--jobs", "0"]);

    assert!(result.is_err());
}

#[test]
fn each_progress_mode_maps_to_its_typed_value() -> Result<(), Box<dyn std::error::Error>> {
    for (name, expected) in [
        ("auto", ProgressMode::Auto),
        ("always", ProgressMode::Always),
        ("never", ProgressMode::Never),
        ("json", ProgressMode::Json),
    ] {
        let Command::Export(options) =
            parse_from(["l2solver", "extract", "traffic.pcapng", "--progress", name])?
        else {
            return Err("extract did not select capture extraction".into());
        };
        assert_eq!(options.recovery.progress, expected, "{name}");
    }
    Ok(())
}

#[test]
fn byte_size_parser_accepts_binary_decimal_and_raw_byte_counts() {
    assert_eq!(parse_byte_size("512MiB"), Ok(536_870_912));
    assert_eq!(parse_byte_size("1GB"), Ok(1_000_000_000));
    assert_eq!(parse_byte_size("1tB"), Ok(1_000_000_000_000));
    assert_eq!(parse_byte_size("1TiB"), Ok(1_099_511_627_776));
    assert_eq!(parse_byte_size("4096"), Ok(4096));
    assert!(parse_byte_size("2XB").is_err());
    assert!(parse_byte_size("18446744073709551615KiB").is_err());
}

#[test]
fn refine_maps_all_requested_controls_to_one_typed_command()
-> Result<(), Box<dyn std::error::Error>> {
    let Command::Refine(options) = parse_from([
        "l2solver",
        "refine",
        "unknown.bin",
        "--output",
        "refined-results",
        "--dry-run",
        "--salvage",
        "--profile",
        "fast",
    ])?
    else {
        return Err("refine did not select the refinement command".into());
    };

    assert_eq!(options.input, Path::new("unknown.bin"));
    assert_eq!(
        options.output.as_deref(),
        Some(Path::new("refined-results"))
    );
    assert!(options.dry_run);
    assert!(options.salvage);
    assert_eq!(options.recovery.profile, RecoveryProfile::Fast);
    Ok(())
}

#[test]
fn cache_subcommands_have_typed_options() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        parse_from(["l2solver", "cache", "stats"])?,
        Command::Cache(CacheCommand::Stats)
    ));
    assert!(matches!(
        parse_from(["l2solver", "cache", "prune", "--max-bytes", "512MiB"])?,
        Command::Cache(CacheCommand::Prune {
            max_bytes: Some(536_870_912)
        })
    ));
    assert!(matches!(
        parse_from(["l2solver", "cache", "clear"])?,
        Command::Cache(CacheCommand::Clear)
    ));
    Ok(())
}

#[test]
fn completion_shell_names_are_typed() -> Result<(), Box<dyn std::error::Error>> {
    for (name, shell) in [
        ("bash", CompletionShell::Bash),
        ("zsh", CompletionShell::Zsh),
        ("fish", CompletionShell::Fish),
    ] {
        assert!(matches!(
            parse_from(["l2solver", "completions", name])?,
            Command::Completions(found) if found == shell
        ));
    }
    Ok(())
}

#[test]
fn recovery_profiles_use_stable_snake_case_serialization() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(serde_json::to_value(RecoveryProfile::Fast)?, "fast");
    assert_eq!(serde_json::to_value(RecoveryProfile::Normal)?, "normal");
    assert_eq!(serde_json::to_value(RecoveryProfile::Deep)?, "deep");
    Ok(())
}
