//! Operator-facing commands for native Layer-2 assessments

#![forbid(unsafe_code)]

#[cfg(all(test, target_os = "linux"))]
#[path = "../../l2-active/tests/support/mod.rs"]
mod test_support;

mod arguments;
#[cfg(target_os = "linux")]
mod arp_output;
mod capabilities;
#[cfg(target_os = "linux")]
mod dhcp_output;
mod dhcp_probe;
mod diagnostic;
#[cfg(target_os = "linux")]
mod dot1x_output;
mod dot1x_probe;
mod error;
mod execution;
mod interface_capabilities;
#[cfg(target_os = "linux")]
mod listen_output;
mod listen_probe;
mod mac;
#[cfg(target_os = "linux")]
mod ndp_output;
mod ndp_probe;
mod pipe;
mod preflight;
mod probe;
mod process;
#[cfg(target_os = "linux")]
mod report_common;
#[cfg(target_os = "linux")]
mod session_options;

pub use arguments::{
    ActiveArgs, ActiveCommand, ArpCommand, ArpProbeArgs, Cli, DhcpCommand, DhcpProbeArgs,
    Dot1xCommand, Dot1xProbeArgs, InterfaceArgs, ListenArgs, ListenCommand, NdpCommand,
    NdpProbeArgs, OutputFormat, SessionArgs,
};
pub use error::{Error, write_error};
pub use execution::{ActiveOutcome, execute};
pub use pipe::BrokenPipeWriter;
pub use process::execute_process;
