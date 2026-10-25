use clap::error::ErrorKind;
use l2_cli::arguments::{Command, WorkbenchCommand, parse};
use std::ffi::OsString;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;
pub type NumericDefault = (&'static str, String);

fn arguments(values: &[&str]) -> Vec<OsString> {
    std::iter::once("workbench")
        .chain(values.iter().copied())
        .map(OsString::from)
        .collect()
}

pub fn workbench(values: &[&str]) -> Result<WorkbenchCommand, Box<dyn std::error::Error>> {
    let Command::Workbench(command) = parse(&arguments(values))? else {
        return Err("workbench command was not selected".into());
    };
    Ok(command)
}

pub fn reject_zero(values: &[&str], defaults: &[NumericDefault]) {
    for (option, _) in defaults {
        let mut values = values.to_vec();
        // Keep the valid command intact so only the selected budget changes
        values.extend([*option, "0"]);
        assert!(
            parse(&arguments(&values)).is_err(),
            "accepted zero for {option} in {values:?}"
        );
    }
}

pub fn help_defaults(values: &[&str], defaults: &[NumericDefault]) -> TestResult {
    let mut values = values.to_vec();
    values.push("--help");
    let Err(error) = parse(&arguments(&values)) else {
        return Err("help request unexpectedly selected a command".into());
    };
    assert_eq!(error.kind(), ErrorKind::DisplayHelp);
    let help = error.to_string();

    for (option, value) in defaults {
        let mut lines = help
            .lines()
            .skip_while(|line| line.split_whitespace().next() != Some(*option));
        let Some(first) = lines.next() else {
            return Err(format!("help is missing {option}:\n{help}").into());
        };
        // Search one option block so another flag cannot supply the expected number
        let block = std::iter::once(first)
            .chain(lines.take_while(|line| !line.trim_start().starts_with('-')))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            block.contains(&format!("[default: {value}]")),
            "wrong default for {option}: {block}"
        );
    }
    Ok(())
}
