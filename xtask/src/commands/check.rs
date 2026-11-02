//! Ordered Cargo invocations used by the repository check gate

use std::path::Path;

use crate::{dependency_policy, process::CommandSpec};

const WORKSPACE_OPTIONS: &[&str] = &[
    "--workspace",
    "--all-targets",
    "--all-features",
    "--offline",
    "--locked",
];

pub(super) fn run(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("checking workspace dependency policy");
    dependency_policy::check(root)?;
    for specification in specifications() {
        super::run(root, &specification)?;
    }
    Ok(())
}

fn specifications() -> [CommandSpec; 9] {
    [
        CommandSpec::new("cargo").args(["fmt", "--all", "--", "--check"]),
        // Frozen audits cover both independently resolved lockfiles without network access
        CommandSpec::new("cargo").args(["deny", "--frozen", "check"]),
        CommandSpec::new("cargo").args([
            "deny",
            "--frozen",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "check",
        ]),
        CommandSpec::new("cargo")
            .arg("check")
            .args(WORKSPACE_OPTIONS.iter().copied()),
        clippy(WORKSPACE_OPTIONS),
        // Feature-gated code also needs the minimal CLI build checked
        clippy(&[
            "--package",
            "l2-cli",
            "--all-targets",
            "--no-default-features",
            "--offline",
            "--locked",
        ]),
        // The excluded fuzz package owns a separate manifest and lockfile
        clippy(&[
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all-targets",
            "--offline",
            "--locked",
        ]),
        // Nextest runs the normal suite once; doctests remain a separate gate
        CommandSpec::new("cargo")
            .args(["nextest", "run"])
            .args(WORKSPACE_OPTIONS.iter().copied())
            .args(["--status-level", "skip", "--final-status-level", "skip"]),
        // Nextest does not execute documentation examples
        CommandSpec::new("cargo").args([
            "test",
            "--workspace",
            "--all-features",
            "--doc",
            "--offline",
            "--locked",
        ]),
    ]
}

fn clippy(options: &[&str]) -> CommandSpec {
    // Keep every build variant under the same strict warning policy
    CommandSpec::new("cargo")
        .arg("clippy")
        .args(options.iter().copied())
        .args(["--", "-D", "warnings"])
}

#[cfg(test)]
#[path = "../../tests/commands/check.rs"]
mod tests;
