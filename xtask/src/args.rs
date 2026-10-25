//! Argument parsing for repository maintenance tasks

use std::{ffi::OsString, fmt};

/// Maximum review number accepted in an output filename
pub const MAX_REVIEW_NUMBER: u32 = 10_000;

/// Supported repository maintenance commands
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Check,
    FuzzSmoke,
    FuzzRelease,
    Mutate,
    Profile,
    CorpusMinimize,
    PackageReview { number: u32 },
}

/// A command-line parse failure
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    Usage(String),
    NonUnicode,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(reason) => write!(formatter, "{reason}\n\n{}", usage()),
            Self::NonUnicode => write!(formatter, "arguments must be valid Unicode\n\n{}", usage()),
        }
    }
}

impl std::error::Error for ParseError {}

/// Public command usage text
#[must_use]
pub const fn usage() -> &'static str {
    "Usage:\n  cargo xtask check\n  cargo xtask fuzz-smoke\n  cargo xtask fuzz-release\n  cargo xtask mutate\n  cargo xtask profile\n  cargo xtask corpus-minimize\n  cargo xtask package-review <N>"
}

/// Parse `cargo xtask` arguments after the executable name
///
/// # Errors
///
/// Returns [`ParseError::Usage`] for an unknown command or invalid positional
/// arguments, and [`ParseError::NonUnicode`] when an operating-system argument
/// cannot be represented as Unicode
pub fn parse<I, S>(arguments: I) -> Result<Command, ParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let values = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
    match values.as_slice() {
        [] => Err(ParseError::Usage(String::from("a command is required"))),
        [command] => parse_single(command),
        [command, number] if command == "package-review" => parse_review(number),
        [command, ..] if command == "package-review" => Err(ParseError::Usage(String::from(
            "package-review accepts exactly one review number",
        ))),
        _ => Err(ParseError::Usage(String::from(
            "commands do not accept positional arguments",
        ))),
    }
}

fn parse_single(value: &OsString) -> Result<Command, ParseError> {
    match value.to_str().ok_or(ParseError::NonUnicode)? {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "check" => Ok(Command::Check),
        "fuzz-smoke" => Ok(Command::FuzzSmoke),
        "fuzz-release" => Ok(Command::FuzzRelease),
        "mutate" => Ok(Command::Mutate),
        "profile" => Ok(Command::Profile),
        "corpus-minimize" => Ok(Command::CorpusMinimize),
        "package-review" => Err(ParseError::Usage(String::from(
            "package-review requires a review number",
        ))),
        _ => Err(ParseError::Usage(String::from("unknown xtask command"))),
    }
}

fn parse_review(value: &OsString) -> Result<Command, ParseError> {
    let text = value.to_str().ok_or(ParseError::NonUnicode)?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseError::Usage(String::from(
            "review number must be a positive decimal integer",
        )));
    }
    let number = text.parse::<u32>().map_err(|_| {
        ParseError::Usage(String::from(
            "review number must be a positive decimal integer",
        ))
    })?;
    if !(1..=MAX_REVIEW_NUMBER).contains(&number) {
        return Err(ParseError::Usage(format!(
            "review number must be between 1 and {MAX_REVIEW_NUMBER}"
        )));
    }
    Ok(Command::PackageReview { number })
}
