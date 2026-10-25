//! Errors from bounded PCAPNG evidence generation

use l2_capture::InterfaceId;
use std::{fmt, io};

/// Failure returned before or during PCAPNG evidence generation
#[derive(Debug)]
pub enum WriterError {
    Io(io::Error),
    OutputLimitTooSmall { configured: u64, minimum: u64 },
    OutputLimitTooLarge { configured: u64, maximum: u64 },
    OutputLimitExceeded { attempted: u64, limit: u64 },
    InvalidSnaplen { snaplen: u32, maximum: u32 },
    InterfaceLimitExceeded { limit: usize },
    DuplicateInterface { source: InterfaceId },
    UnknownInterface { source: InterfaceId },
    PacketLimitExceeded { limit: u32 },
    CapturedLengthExceedsSnaplen { captured: u32, snaplen: u32 },
    MissingTimestamp,
    TimestampConfigurationMismatch,
    LinkTypeConfigurationMismatch,
    UnsupportedVlanMetadata,
    LinuxInterfaceIdentityMismatch,
    CollectionReportNotReserved,
    UnrepresentablePacketFlags,
    LengthOverflow,
    Terminated,
    Finished,
}

impl fmt::Display for WriterError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(output, "PCAPNG output failed: {error}"),
            Self::OutputLimitTooSmall {
                configured,
                minimum,
            } => write!(
                output,
                "PCAPNG output limit {configured} is smaller than the {minimum}-byte section header"
            ),
            Self::OutputLimitTooLarge {
                configured,
                maximum,
            } => write!(
                output,
                "PCAPNG output limit {configured} exceeds the absolute maximum {maximum}"
            ),
            Self::OutputLimitExceeded { attempted, limit } => write!(
                output,
                "PCAPNG output would reach {attempted} bytes and exceed the {limit}-byte limit"
            ),
            Self::InvalidSnaplen { snaplen, maximum } => write!(
                output,
                "PCAPNG snapshot length {snaplen} exceeds the maximum {maximum}"
            ),
            Self::InterfaceLimitExceeded { limit } => {
                write!(output, "PCAPNG interface count exceeds the limit {limit}")
            }
            Self::DuplicateInterface { source } => write!(
                output,
                "capture interface {}:{} is already registered",
                source.section, source.index
            ),
            Self::UnknownInterface { source } => write!(
                output,
                "capture interface {}:{} is not registered",
                source.section, source.index
            ),
            Self::PacketLimitExceeded { limit } => {
                write!(output, "PCAPNG packet count exceeds the limit {limit}")
            }
            Self::CapturedLengthExceedsSnaplen { captured, snaplen } => write!(
                output,
                "captured length {captured} exceeds interface snapshot length {snaplen}"
            ),
            Self::MissingTimestamp => {
                output.write_str("PCAPNG enhanced packet requires a source timestamp")
            }
            Self::TimestampConfigurationMismatch => output.write_str(
                "packet timestamp resolution or offset differs from its registered interface",
            ),
            Self::LinkTypeConfigurationMismatch => {
                output.write_str("packet link type differs from its registered interface")
            }
            Self::UnsupportedVlanMetadata => output
                .write_str("out-of-band VLAN metadata has no enabled lossless PCAPNG encoding"),
            Self::LinuxInterfaceIdentityMismatch => output
                .write_str("packet Linux interface identity differs from its registered interface"),
            Self::CollectionReportNotReserved => {
                output.write_str("PCAPNG section has no reserved collection declaration")
            }
            Self::UnrepresentablePacketFlags => output.write_str(
                "packet direction and FCS state cannot both be represented by epb_flags",
            ),
            Self::LengthOverflow => output.write_str("PCAPNG block length overflowed"),
            Self::Terminated => {
                output.write_str("PCAPNG writer is terminal after an output failure")
            }
            Self::Finished => output.write_str("PCAPNG writer is already finished"),
        }
    }
}

impl std::error::Error for WriterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for WriterError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
