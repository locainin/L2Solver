//! Operator-facing commands for native Layer-2 assessments

#![forbid(unsafe_code)]

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/cli/fixture_assert.rs"]
mod fixture_assert;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/first_hop/mod.rs"]
mod first_hop_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/mpls/mod.rs"]
mod mpls_tests;

#[cfg(test)]
#[path = "../tests/observer_arguments/mod.rs"]
mod observer_argument_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/observer_session/mod.rs"]
mod observer_session_tests;

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
mod ethernet_view;
mod execution;
#[cfg(target_os = "linux")]
mod first_hop_output;
mod first_hop_probe;
mod interface_capabilities;
mod interface_view;
mod isl_probe;
#[cfg(target_os = "linux")]
mod listen_output;
mod listen_probe;
mod mac;
#[cfg(target_os = "linux")]
mod mpls_output;
mod mpls_probe;
#[cfg(target_os = "linux")]
mod ndp_output;
mod ndp_probe;
#[cfg(target_os = "linux")]
mod neighbor_output;
mod observer_arguments;
#[cfg(target_os = "linux")]
mod observer_session;
mod pipe;
mod preflight;
mod probe;
mod process;
#[cfg(target_os = "linux")]
mod report_common;
#[cfg(target_os = "linux")]
mod safe_json;
#[cfg(target_os = "linux")]
mod session_options;
mod switching_probe;
mod vlan_arguments;
mod vlan_assessment;

pub use arguments::{
    ActiveArgs, ActiveCommand, ArpCommand, ArpProbeArgs, Cli, DhcpCommand, DhcpProbeArgs,
    Dot1xCommand, Dot1xProbeArgs, InterfaceArgs, ListenArgs, ListenCommand, NdpCommand,
    NdpProbeArgs, OutputFormat, SessionArgs,
};
pub use error::{Error, write_error};
pub use execution::{ActiveOutcome, execute};
pub use observer_arguments::{
    HsrpCommand, HsrpObserveArgs, MplsCommand, MplsObserveArgs, ObserveArgs, ObserveCommand,
    VrrpCommand, VrrpObserveArgs,
};
pub use pipe::BrokenPipeWriter;
pub use process::execute_process;
pub use vlan_arguments::{VlanAssessmentArgs, VlanCommand};
