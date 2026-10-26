use l2_cli::arguments::{self, CompletionShell};
use std::{io, io::Write, process::Command};

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
