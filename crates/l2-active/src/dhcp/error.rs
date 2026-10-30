//! Admission failures before any DHCP transmission

use std::fmt;

/// A bounded DHCP discovery request could not be prepared
#[derive(Debug)]
#[non_exhaustive]
pub enum DhcpError {
    /// An allowlist is empty, too large, duplicated, or contains a non-host address
    InvalidServerAllowlist,
    /// Bounded allowlist storage could not be reserved
    Allocation,
    /// The fixed DHCP request could not be encoded
    Encoding,
}

impl fmt::Display for DhcpError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::InvalidServerAllowlist => "invalid DHCP server allowlist",
            Self::Allocation => "cannot reserve DHCP allowlist storage",
            Self::Encoding => "cannot encode DHCP discovery request",
        })
    }
}

impl std::error::Error for DhcpError {}
