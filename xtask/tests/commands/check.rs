use std::ffi::OsStr;

use super::specifications;

#[test]
fn check_commands_keep_execution_order() {
    let commands = specifications();
    let subcommands = commands
        .iter()
        .map(|command| command.arguments().first().map(AsRef::as_ref))
        .collect::<Vec<Option<&OsStr>>>();

    assert_eq!(
        subcommands,
        [
            "fmt", "deny", "deny", "check", "clippy", "clippy", "clippy", "nextest", "test",
        ]
        .map(|command| Some(OsStr::new(command)))
    );
}

#[test]
fn covers_frozen_dependency_audits() {
    let commands = specifications();
    let dependency_audits = commands
        .iter()
        .filter(|command| command.arguments().first().is_some_and(|arg| arg == "deny"))
        .collect::<Vec<_>>();
    let expected: &[&[&str]] = &[
        &["deny", "--frozen", "check"],
        &[
            "deny",
            "--frozen",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "check",
        ],
    ];

    assert_eq!(dependency_audits.len(), expected.len());
    for (command, arguments) in dependency_audits.into_iter().zip(expected) {
        assert_eq!(command.program(), "cargo");
        assert_eq!(command.arguments(), *arguments);
    }
}

#[test]
fn preserves_workspace_coverage() {
    let commands = specifications();
    let workspace_commands = commands
        .iter()
        .filter(|command| command.arguments().iter().any(|arg| arg == "--workspace"))
        .collect::<Vec<_>>();
    let expected: &[&[&str]] = &[
        &[
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--offline",
            "--locked",
        ],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--offline",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &[
            "nextest",
            "run",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--offline",
            "--locked",
            "--status-level",
            "skip",
            "--final-status-level",
            "skip",
        ],
        &[
            "test",
            "--workspace",
            "--all-features",
            "--doc",
            "--offline",
            "--locked",
        ],
    ];

    assert_eq!(workspace_commands.len(), expected.len());
    for (command, arguments) in workspace_commands.into_iter().zip(expected) {
        assert_eq!(command.program(), "cargo");
        assert_eq!(command.arguments(), *arguments);
    }
}

#[test]
fn covers_offline_cli() {
    let commands = specifications();
    assert!(commands.iter().any(|command| {
        command.program() == "cargo"
            && command.arguments()
                == [
                    "clippy",
                    "--package",
                    "l2-cli",
                    "--all-targets",
                    "--no-default-features",
                    "--offline",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ]
    }));
}

#[test]
fn covers_locked_fuzz() {
    let commands = specifications();
    assert!(commands.iter().any(|command| {
        command.program() == "cargo"
            && command.arguments()
                == [
                    "clippy",
                    "--manifest-path",
                    "fuzz/Cargo.toml",
                    "--all-targets",
                    "--offline",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ]
    }));
}
