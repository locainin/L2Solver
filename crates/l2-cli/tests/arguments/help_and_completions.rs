use l2_cli::arguments::{self, CompletionShell};
use std::{fs, io, io::Write, process::Command};

#[test]
fn empty_invocation_shows_full_help_and_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver")).output()?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout)?;
    for detail in [
        "Usage: l2solver",
        "extract",
        "refine",
        "cache",
        "completions",
        "Examples:",
        "Exit status:",
    ] {
        assert!(help.contains(detail), "missing {detail} from help:\n{help}");
    }
    assert!(!help.contains("Developer:"));
    Ok(())
}

#[test]
fn empty_extract_and_hidden_export_show_help_and_succeed() -> Result<(), Box<dyn std::error::Error>>
{
    for spelling in ["extract", "export"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .arg(spelling)
            .output()?;

        assert_eq!(output.status.code(), Some(0), "{spelling}");
        assert!(output.stderr.is_empty(), "{spelling}");
        let help = String::from_utf8(output.stdout)?;
        assert!(help.contains("Usage: l2solver"), "{spelling}: {help}");
        assert!(help.contains("--profile"), "{spelling}: {help}");
        assert!(help.contains("Examples:"), "{spelling}: {help}");
    }
    Ok(())
}

#[test]
fn unknown_and_incomplete_commands_fail_with_usage_status() -> Result<(), Box<dyn std::error::Error>>
{
    for arguments in [&["not-a-command"][..], &["extract", "--jobs", "2"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(arguments)
            .output()?;

        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(!output.stderr.is_empty(), "{arguments:?}");
    }
    Ok(())
}

#[test]
fn unknown_recovery_options_before_input_return_usage_status()
-> Result<(), Box<dyn std::error::Error>> {
    let mut outputs = Vec::new();
    for command in ["extract", "export", "refine"] {
        for flag in ["--bogus", "-z"] {
            for with_input in [false, true] {
                let mut process = Command::new(env!("CARGO_BIN_EXE_l2solver"));
                process.args([command, flag]);
                if with_input {
                    process.arg("input.bin");
                }
                outputs.push((command, flag, with_input, process.output()?));
            }
        }
    }
    let statuses: Vec<_> = outputs
        .iter()
        .map(|(command, flag, with_input, output)| {
            (*command, *flag, *with_input, output.status.code())
        })
        .collect();
    assert!(
        statuses.iter().all(|(_, _, _, status)| *status == Some(2)),
        "unexpected status codes: {statuses:?}"
    );
    for (command, flag, with_input, output) in outputs {
        assert!(output.stdout.is_empty(), "{command} {flag} {with_input}");
        let error = String::from_utf8(output.stderr)?;
        assert!(
            error.contains("Usage:"),
            "{command} {flag} {with_input}: {error}"
        );
        assert!(
            error.contains(flag),
            "{command} {flag} {with_input}: {error}"
        );
    }
    Ok(())
}

#[test]
fn recovery_commands_reject_an_output_option_without_a_value()
-> Result<(), Box<dyn std::error::Error>> {
    for command in ["extract", "export", "refine"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args([command, "-o"])
            .output()?;
        assert_eq!(output.status.code(), Some(2), "{command}");
        assert!(output.stdout.is_empty(), "{command}");
        assert!(!output.stderr.is_empty(), "{command}");
    }
    Ok(())
}

#[test]
fn separator_allows_real_hyphenated_inputs_for_recovery_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    fs::write(
        temporary.path().join("-input.pcap"),
        include_bytes!("../../../../tests/pcaps/lldp.pcap"),
    )?;
    fs::write(temporary.path().join("-input.bin"), b"ordinary file input")?;

    for command in ["extract", "export"] {
        let destination = temporary.path().join(command);
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .current_dir(temporary.path())
            .env("PATH", temporary.path())
            .args([command, "--no-cache", "--progress", "never", "-o"])
            .arg(&destination)
            .args(["--", "-input.pcap"])
            .output()?;
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(destination.join("manifest.json").is_file(), "{command}");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .current_dir(temporary.path())
        .args([
            "refine",
            "--dry-run",
            "--no-cache",
            "--progress",
            "never",
            "--",
            "-input.bin",
        ])
        .output()?;
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "refine: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Would refine"));
    Ok(())
}

#[test]
fn refine_help_describes_supported_inputs_and_owned_results()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["refine", "--help"])
        .output()?;

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for detail in [
        "ordinary file or export directory",
        ".bin",
        "without requiring a PCAP",
        "INPUT.refined",
        "manifest",
        "summary",
        "larger inputs stay in place",
        "bounded PNG and ZIP ranges",
        "--strict-cache",
        "--dry-run",
        "--salvage",
        "supported partial archive members",
        "matching owned result",
        "atomically replaces",
        "Unrelated existing paths are refused",
    ] {
        assert!(
            help.contains(detail),
            "missing {detail} from refine help:\n{help}"
        );
    }
    let normalized = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("Use -- before a filename starting with -"));
    Ok(())
}

#[test]
fn each_completion_shell_receives_a_script_with_public_commands()
-> Result<(), Box<dyn std::error::Error>> {
    for shell in [
        CompletionShell::Bash,
        CompletionShell::Zsh,
        CompletionShell::Fish,
    ] {
        let mut output = Vec::new();
        arguments::generate_completions(shell, &mut output)?;
        let script = String::from_utf8(output)?;

        assert!(!script.is_empty(), "{shell:?}");
        assert!(script.contains("extract"), "{shell:?}");
        assert!(script.contains("refine"), "{shell:?}");
        assert!(script.contains("cache"), "{shell:?}");
    }
    Ok(())
}

#[test]
fn completion_generation_propagates_writer_errors() {
    struct ClosedWriter;

    impl Write for ClosedWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("closed"))
        }
    }

    assert!(arguments::generate_completions(CompletionShell::Bash, &mut ClosedWriter).is_err());
}
