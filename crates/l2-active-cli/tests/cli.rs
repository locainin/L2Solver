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
#[path = "cli/helper_timeout.rs"]
mod helper_timeout;
#[path = "cli/listen.rs"]
mod listen;
#[cfg(target_os = "linux")]
#[path = "cli/namespace.rs"]
mod namespace;
#[path = "cli/ndp.rs"]
mod ndp;
#[path = "cli/output.rs"]
mod output;
