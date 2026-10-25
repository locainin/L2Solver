//! Safe child-process execution without a shell

use std::{
    ffi::{OsStr, OsString},
    fmt,
    path::Path,
    process::{Command, Output},
};

/// A process invocation represented as an executable and separate arguments
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    program: OsString,
    arguments: Vec<OsString>,
}

impl CommandSpec {
    /// Build a process invocation
    #[must_use]
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
        }
    }

    /// Append one argument without shell interpretation
    #[must_use]
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Append several arguments without shell interpretation
    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    /// Return the executable for inspection and tests
    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Return the separate arguments for inspection and tests
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

/// Failure while starting or running a maintenance process
#[derive(Debug)]
pub enum ProcessError {
    Io {
        program: String,
        source: std::io::Error,
    },
    Failed {
        program: String,
        code: Option<i32>,
    },
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { program, source } => write!(formatter, "could not run {program}: {source}"),
            Self::Failed { program, code } => {
                write!(formatter, "{program} exited unsuccessfully")?;
                if let Some(code) = code {
                    write!(formatter, " with status {code}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ProcessError {}

/// Run one command in the workspace with network access disabled for Cargo
///
/// # Errors
///
/// Returns [`ProcessError::Io`] when the executable cannot be started, or
/// [`ProcessError::Failed`] when it exits unsuccessfully
pub fn run(root: &Path, specification: &CommandSpec) -> Result<(), ProcessError> {
    let program = program_name(specification);
    let status = command(root, specification)
        .status()
        .map_err(|source| ProcessError::Io {
            program: program.clone(),
            source,
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProcessError::Failed {
            program,
            code: status.code(),
        })
    }
}

/// Run one command and retain its standard output for structured checks
///
/// # Errors
///
/// Returns [`ProcessError::Io`] when the executable cannot be started, or
/// [`ProcessError::Failed`] when it exits unsuccessfully
pub fn output(root: &Path, specification: &CommandSpec) -> Result<Output, ProcessError> {
    let program = program_name(specification);
    let output = command(root, specification)
        .output()
        .map_err(|source| ProcessError::Io {
            program: program.clone(),
            source,
        })?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ProcessError::Failed {
            program,
            code: output.status.code(),
        })
    }
}

fn command(root: &Path, specification: &CommandSpec) -> Command {
    let mut command = Command::new(&specification.program);
    command
        .args(&specification.arguments)
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never");
    command
}

fn program_name(specification: &CommandSpec) -> String {
    specification.program.to_string_lossy().into_owned()
}
