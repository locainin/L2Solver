//! Typed operation and output failures for the active command boundary

use std::{
    fmt,
    io::{self, Write},
};

use serde::Serialize;

use super::{OutputFormat, diagnostic::io_error_code};

/// A native active operation or its output could not be completed
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A bounded presentation buffer could not be reserved
    Allocation,
    /// Read-only interface discovery failed
    Discovery(io::Error),
    /// An interface has no suitable or unambiguous source address
    Scope(io::Error),
    /// The privileged helper could not be opened or closed
    Helper(io::Error),
    /// A requested probe or its resource limits were invalid
    Plan(l2_active::PlanError),
    /// A DHCP discovery request could not be prepared
    DhcpPlan(l2_active::dhcp::DhcpError),
    /// Fresh transaction entropy was unavailable
    Entropy(io::Error),
    /// A fixed native request could not be encoded
    Encoding(io::Error),
    /// The discovered Ethernet address cannot identify a unicast endpoint
    Address(l2_onpath::ModelError),
    /// Probe preparation failed before transmission
    Run(l2_active::RunError),
    /// Preparation failed and the helper did not confirm closure
    Cleanup {
        preparation: l2_active::RunError,
        close: io::Error,
    },
    /// Cancellation handling could not be installed
    Signal(ctrlc::Error),
    /// Human-readable output could not be written
    Output(io::Error),
    /// Structured output could not be written
    Json(serde_json::Error),
    /// An observer failed without exposing untrusted diagnostic text
    CodesOnly {
        /// Stable category of the original error
        code: &'static str,
        /// Stage that reported the original error
        stage: &'static str,
    },
}

impl Error {
    /// Return a stable machine-readable error category
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::CodesOnly { code, .. } => code,
            Self::Allocation | Self::DhcpPlan(l2_active::dhcp::DhcpError::Allocation) => {
                "allocation_failed"
            }
            Self::Discovery(error)
            | Self::Scope(error)
            | Self::Helper(error)
            | Self::Output(error) => io_error_code(error),
            Self::Plan(_)
            | Self::Address(_)
            | Self::DhcpPlan(l2_active::dhcp::DhcpError::InvalidServerAllowlist) => "invalid_scope",
            Self::DhcpPlan(_) | Self::Encoding(_) | Self::Run(_) => "preparation_failed",
            Self::Entropy(_) => "entropy_unavailable",
            Self::Cleanup { .. } => "cleanup_unconfirmed",
            Self::Signal(_) => "signal_setup_failed",
            Self::Json(_) => "output_failed",
        }
    }

    /// Return the operation stage that reported the failure
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::CodesOnly { stage, .. } => stage,
            Self::Discovery(_) => "discovery",
            Self::Scope(_) | Self::Address(_) => "scope",
            Self::Helper(_) | Self::Cleanup { .. } => "helper",
            Self::Plan(_)
            | Self::DhcpPlan(_)
            | Self::Entropy(_)
            | Self::Encoding(_)
            | Self::Run(_) => "preparation",
            Self::Signal(_) => "cancellation",
            Self::Allocation | Self::Output(_) | Self::Json(_) => "output",
        }
    }

    pub(crate) fn codes_only(self) -> Self {
        Self::CodesOnly {
            code: self.code(),
            stage: self.stage(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => output.write_str("could not reserve report storage"),
            Self::Discovery(error) => write!(output, "interface discovery failed: {error}"),
            Self::Scope(error) => write!(output, "interface scope is invalid: {error}"),
            Self::Helper(error) if error.kind() == io::ErrorKind::PermissionDenied => write!(
                output,
                "active helper failed: {error}; check execute permissions and CAP_NET_RAW on the trusted helper"
            ),
            Self::Helper(error) => write!(output, "active helper failed: {error}"),
            Self::Plan(error) => write!(output, "probe plan failed: {error}"),
            Self::DhcpPlan(error) => write!(output, "DHCP plan failed: {error}"),
            Self::Entropy(error) => write!(output, "transaction entropy failed: {error}"),
            Self::Encoding(error) => write!(output, "request encoding failed: {error}"),
            Self::Address(error) => write!(output, "interface address is invalid: {error}"),
            Self::Run(error) => write!(output, "probe preparation failed: {error}"),
            Self::Cleanup { preparation, close } => write!(
                output,
                "probe preparation failed: {preparation}; helper cleanup was not confirmed: {close}"
            ),
            Self::Signal(error) => {
                write!(output, "could not install cancellation handler: {error}")
            }
            Self::Output(error) => write!(output, "could not write output: {error}"),
            Self::Json(error) => write!(output, "could not write JSON: {error}"),
            Self::CodesOnly { code, .. } => write!(output, "active operation failed ({code})"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation | Self::CodesOnly { .. } => None,
            Self::Discovery(error)
            | Self::Scope(error)
            | Self::Helper(error)
            | Self::Entropy(error)
            | Self::Encoding(error)
            | Self::Output(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::DhcpPlan(error) => Some(error),
            Self::Address(error) => Some(error),
            Self::Run(error) => Some(error),
            Self::Cleanup { close, .. } => Some(close),
            Self::Signal(error) => Some(error),
            Self::Json(error) => Some(error),
        }
    }
}

#[derive(Serialize)]
struct ErrorReport {
    status: &'static str,
    code: &'static str,
    stage: &'static str,
    message: String,
}

/// Render one operation error using the same format in both CLI entry points
///
/// # Errors
/// Returns an output error when the diagnostic stream cannot be written
pub fn write_error(error: &Error, format: OutputFormat, output: &mut impl Write) -> io::Result<()> {
    match format {
        OutputFormat::Text => writeln!(output, "error: {}", error.to_string().escape_debug()),
        OutputFormat::Json => {
            let report = ErrorReport {
                status: "error",
                code: error.code(),
                stage: error.stage(),
                message: error.to_string(),
            };
            serde_json::to_writer(&mut *output, &report).map_err(io::Error::other)?;
            writeln!(output)
        }
    }
}
