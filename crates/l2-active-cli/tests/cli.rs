#[path = "cli/arguments.rs"]
mod arguments;
#[path = "cli/cancellation.rs"]
mod cancellation;
#[path = "cli/capabilities.rs"]
mod capabilities;
#[path = "cli/dhcp.rs"]
mod dhcp;
#[path = "cli/dot1x.rs"]
mod dot1x;
#[path = "cli/errors.rs"]
mod errors;
#[cfg(target_os = "linux")]
#[path = "first_hop/namespace_cli.rs"]
mod first_hop;
#[cfg(target_os = "linux")]
#[path = "cli/helper_artifact.rs"]
mod helper_artifact;
#[path = "cli/helper_timeout.rs"]
mod helper_timeout;
#[path = "cli/listen.rs"]
mod listen;
#[cfg(target_os = "linux")]
#[path = "cli/mpls.rs"]
mod mpls;
#[cfg(target_os = "linux")]
#[path = "cli/namespace.rs"]
mod namespace;
#[path = "cli/ndp.rs"]
mod ndp;
#[path = "cli/output.rs"]
mod output;
#[cfg(target_os = "linux")]
#[path = "switching/namespace_cli.rs"]
mod switching;
#[cfg(target_os = "linux")]
#[path = "cli/vlan.rs"]
mod vlan;
#[path = "cli/vlan_assessment_args.rs"]
mod vlan_assessment_args;
