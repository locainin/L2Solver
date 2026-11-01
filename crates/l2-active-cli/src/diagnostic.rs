//! Stable categories for operating-system failure reports

use std::io;

pub fn io_error_code(error: &io::Error) -> &'static str {
    if error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<l2_active_linux::VlanScopeChanged>)
    {
        "scope_changed"
    } else {
        io_code(error.kind())
    }
}

pub const fn io_code(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::Unsupported => "unsupported",
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::InvalidInput => "invalid_input",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::Interrupted => "cancelled",
        io::ErrorKind::NetworkUnreachable => "network_unreachable",
        io::ErrorKind::HostUnreachable => "host_unreachable",
        _ => "io_error",
    }
}
