//! Entry point for `cargo xtask`

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let command = match xtask::args::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let root = match xtask::commands::workspace_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            return ExitCode::from(1);
        }
    };
    match xtask::commands::execute(&root, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            ExitCode::from(1)
        }
    }
}
