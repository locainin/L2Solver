//! Stable categories for operating-system failure reports

use std::io;

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
