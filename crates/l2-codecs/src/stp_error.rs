//! Errors returned by the passive STP and RSTP decoder

use std::fmt;

/// Fixed wire sections used in STP truncation diagnostics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpContext {
    /// The optional IEEE 802.2 LLC header
    LlcHeader,
    /// Protocol identifier, version, and BPDU type
    CommonHeader,
    /// Configuration BPDU bridge, port, and timer fields
    ConfigurationBody,
    /// RSTP version-one extension length field
    RapidExtension,
}

/// Structural and support-boundary failures from [`crate::decode_stp`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpError {
    /// The supplied input exceeds the bounded decoder policy
    FrameTooLong { length: usize, max: usize },
    /// A fixed wire section ended before all required bytes were available
    Truncated {
        context: StpContext,
        needed: usize,
        available: usize,
    },
    /// An explicitly supplied LLC header is not the STP LLC encapsulation
    InvalidLlc { dsap: u8, ssap: u8, control: u8 },
    /// The BPDU protocol identifier is not the IEEE spanning-tree identifier
    InvalidProtocolIdentifier { value: u16 },
    /// The version is outside the implemented STP/RSTP baseline
    UnsupportedVersion { value: u8 },
    /// The BPDU type is not implemented for the selected version
    UnsupportedType { version: u8, value: u8 },
    /// A recognized BPDU advertises an extension outside this baseline
    UnsupportedExtension { version: u8, length: u8 },
}

impl fmt::Display for StpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::LlcHeader => "LLC header",
            Self::CommonHeader => "BPDU header",
            Self::ConfigurationBody => "configuration BPDU body",
            Self::RapidExtension => "RSTP extension",
        };
        f.write_str(name)
    }
}

impl fmt::Display for StpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(f, "STP input is {length} bytes, maximum is {max}")
            }
            Self::Truncated {
                context,
                needed,
                available,
            } => write!(
                f,
                "truncated {context}: need {needed} bytes, have {available}"
            ),
            Self::InvalidLlc {
                dsap,
                ssap,
                control,
            } => write!(
                f,
                "unsupported STP LLC header DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x}, control 0x{control:02x}"
            ),
            Self::InvalidProtocolIdentifier { value } => {
                write!(f, "invalid STP protocol identifier 0x{value:04x}")
            }
            Self::UnsupportedVersion { value } => {
                write!(f, "unsupported STP protocol version {value}")
            }
            Self::UnsupportedType { version, value } => {
                write!(
                    f,
                    "unsupported STP BPDU type 0x{value:02x} for version {version}"
                )
            }
            Self::UnsupportedExtension { version, length } => write!(
                f,
                "unsupported STP version {version} extension length {length}"
            ),
        }
    }
}

impl std::error::Error for StpError {}
