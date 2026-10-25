//! Generate shell completion scripts from the active command grammar

use super::CompletionShell;
use clap_complete::Generator;
use std::io::{self, Write};

/// Write a completion script for one supported shell
///
/// # Errors
/// Returns an error when the output writer cannot accept the generated script
pub fn generate_completions(shell: CompletionShell, output: &mut impl Write) -> io::Result<()> {
    let mut command = super::command();
    let shell = match shell {
        CompletionShell::Bash => clap_complete::Shell::Bash,
        CompletionShell::Zsh => clap_complete::Shell::Zsh,
        CompletionShell::Fish => clap_complete::Shell::Fish,
    };

    // The parser command tree is the single source of completion names and options
    let binary_name = command.get_name().to_owned();
    command.set_bin_name(binary_name);
    command.build();
    shell.try_generate(&command, output)
}
