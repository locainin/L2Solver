//! Errors returned while opening or streaming a classic PCAP savefile

use l2_capture::{FrameError, MetadataError};
use std::{fmt, io};

/// Failure cases exposed by the bounded classic PCAP reader
#[derive(Debug)]
pub enum Error {
    /// The underlying reader failed
    Io(io::Error),
    /// A required header or packet payload ended before its declared size
    UnexpectedEof {
        /// Part of the savefile that was incomplete
        section: &'static str,
        /// Number of bytes required for the section
        expected: usize,
        /// Number of bytes received before EOF
        received: usize,
    },
    /// A recognized savefile format is not implemented by this crate
    UnsupportedFormat {
        /// Human-readable format name
        name: &'static str,
    },
    /// The magic number is not a supported classic PCAP magic
    UnsupportedMagic {
        /// Four bytes read at the beginning of the savefile
        magic: [u8; 4],
    },
    /// The savefile is not classic PCAP version 2.4
    UnsupportedVersion {
        /// File format major version
        major: u16,
        /// File format minor version
        minor: u16,
    },
    /// The snapshot length is outside the bounded Ethernet reader policy
    InvalidSnaplen {
        /// Snapshot length from the global header
        snaplen: u32,
    },
    /// Caller-supplied reader limits exceed an absolute ceiling
    InvalidCaptureLimits {
        /// Requested maximum input byte count
        max_input_bytes: u64,
        /// Requested maximum packet record count
        max_records: u32,
    },
    /// Link-layer metadata bits were supplied alongside the link type
    UnsupportedLinkMetadata {
        /// Full network field, including the metadata bits
        value: u32,
    },
    /// A packet contains more captured bytes than the file snapshot length
    InvalidCapturedLength {
        /// Captured packet length from the record header
        captured: u32,
        /// Snapshot length from the global header
        snaplen: u32,
    },
    /// A packet claims fewer original bytes than were captured
    InvalidOriginalLength {
        /// Captured packet length from the record header
        captured: u32,
        /// Original packet length from the record header
        original: u32,
    },
    /// The subsecond timestamp value is outside its unit's valid range
    InvalidTimestampFraction {
        /// Raw microsecond or nanosecond value
        fraction: u32,
        /// Whether the savefile uses nanosecond timestamps
        nanoseconds: bool,
    },
    /// A conversion needed for a bounded allocation could not be represented
    LengthOverflow {
        /// Length that could not be represented safely
        length: u32,
    },
    /// Reading another section would exceed the total input budget
    InputLimitExceeded {
        /// Total input that would have been processed
        attempted: u64,
        /// Maximum total input accepted by the reader
        limit: u64,
    },
    /// The savefile contains more records than the reader policy permits
    RecordLimitExceeded {
        /// Maximum number of records accepted by the reader
        limit: u32,
    },
    /// The underlying reader violated the `Read` contract
    ReaderContractViolation {
        /// Number of bytes reported by the reader
        returned: usize,
        /// Number of bytes available in the supplied buffer
        requested: usize,
    },
    /// A reader that already failed cannot be resumed at an unknown boundary
    ReaderTerminated,
    /// A fixed internal header could not be split into the requested field
    InvalidHeaderLayout,
    /// The input returned `Interrupted` too many times without making progress
    InterruptedLimitExceeded {
        /// Maximum consecutive interruptions permitted by the reader policy
        limit: u32,
    },
    /// A PCAPNG block is smaller than its general header or a required body
    InvalidBlockLength {
        /// Block type read from the input
        block_type: u32,
        /// Declared block length
        length: u32,
    },
    /// A PCAPNG block is larger than the bounded allocation policy
    BlockLengthExceeded {
        /// Block type read from the input
        block_type: u32,
        /// Declared block length
        length: u32,
        /// Maximum block length accepted by the reader
        limit: usize,
    },
    /// A PCAPNG block length is not aligned to a 32-bit boundary
    BlockLengthNotAligned {
        /// Block type read from the input
        block_type: u32,
        /// Declared block length
        length: u32,
    },
    /// The repeated PCAPNG trailer length differs from the header length
    BlockLengthMismatch {
        /// Block type read from the input
        block_type: u32,
        /// Length in the block header
        declared: u32,
        /// Length in the block trailer
        trailing: u32,
    },
    /// The PCAPNG byte-order magic is neither supported endian marker
    InvalidByteOrderMagic {
        /// Four-byte magic interpreted as a host-order integer
        magic: u32,
    },
    /// The PCAPNG section version is not understood
    UnsupportedPcapNgVersion {
        /// Section major version
        major: u16,
        /// Section minor version
        minor: u16,
    },
    /// A finite PCAPNG section length is outside the supported streaming model
    UnsupportedSectionLength {
        /// Signed section length from the section header
        length: i64,
    },
    /// A negative or unaligned PCAPNG section length is invalid
    InvalidSectionLength {
        /// Signed section length from the section header
        length: i64,
    },
    /// The first PCAPNG block was not a section header
    SectionHeaderRequired,
    /// The current PCAPNG section contains too many interface descriptions
    InterfaceLimitExceeded {
        /// Maximum interfaces accepted in one section
        limit: u32,
    },
    /// An enhanced packet refers to an interface not declared in its section
    UnknownInterface {
        /// Section containing the reference
        section: u32,
        /// Interface index referenced by the packet
        index: u32,
    },
    /// A simple packet appeared before its implicit interface description
    SimplePacketWithoutInterface,
    /// A known PCAPNG option appeared more than once in a block
    DuplicateOption {
        /// Block type containing the duplicate
        block_type: u32,
        /// Repeated option code
        code: u16,
    },
    /// A PCAPNG option list exceeded its bounded entry count
    OptionLimitExceeded {
        /// Maximum option records accepted in one block
        limit: u32,
    },
    /// An option appeared after the option-list terminator
    OptionAfterTerminator {
        /// Block type containing the invalid option list
        block_type: u32,
    },
    /// A PCAPNG option has an invalid value length
    InvalidOptionLength {
        /// Block type containing the option
        block_type: u32,
        /// Option code
        code: u16,
        /// Actual value length
        length: usize,
        /// Required exact length, when the option is fixed-size
        expected: Option<usize>,
        /// Required minimum length, when the option is variable-size
        minimum: Option<usize>,
    },
    /// The interface FCS length is not an integral number of octets
    UnsupportedFcsLength {
        /// FCS length declared in bits by the PCAPNG interface option
        bits: u8,
    },
    /// The enhanced packet flags contain a reserved or invalid value
    InvalidPacketFlags {
        /// Raw flags word from the packet options
        flags: u32,
    },
    /// A recognized source-declared Linux identity has invalid components
    InvalidLinuxInterfaceIdentity,
    /// A recognized collection declaration is malformed or repeated
    InvalidCollectionReport,
    /// A packet exceeded a canonical frame invariant
    Frame(FrameError),
    /// Source metadata failed its canonical boundary checks
    Metadata(MetadataError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::InvalidCaptureLimits {
            max_input_bytes,
            max_records,
        } = self
        {
            return write!(
                f,
                "capture limits exceed the absolute ceilings: {max_input_bytes} bytes and {max_records} records"
            );
        }
        if let Some(result) = format_classic(self, f) {
            return result;
        }
        if let Some(result) = format_pcapng(self, f) {
            return result;
        }
        f.write_str("unrecognized capture reader error")
    }
}

fn format_classic(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    if let Some(result) = format_classic_file(error, f) {
        return Some(result);
    }
    format_classic_record(error, f)
}

fn format_classic_file(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    let result = match error {
        Error::Io(error) => write!(f, "PCAP input/output error: {error}"),
        Error::UnexpectedEof {
            section,
            expected,
            received,
        } => write!(
            f,
            "unexpected end of input in {section}: expected {expected} bytes, received {received}"
        ),
        Error::UnsupportedFormat { name } => write!(f, "unsupported capture format: {name}"),
        Error::UnsupportedMagic { magic } => write!(
            f,
            "unsupported PCAP magic {:02x}{:02x}{:02x}{:02x}",
            magic[0], magic[1], magic[2], magic[3]
        ),
        Error::UnsupportedVersion { major, minor } => write!(
            f,
            "unsupported PCAP version {major}.{minor}; only 2.4 is supported"
        ),
        Error::InvalidSnaplen { snaplen } => {
            write!(
                f,
                "invalid PCAP snapshot length {snaplen}; expected a nonzero u32"
            )
        }
        Error::UnsupportedLinkMetadata { value } => write!(
            f,
            "unsupported link-layer metadata in network field 0x{value:08x}"
        ),
        _ => return None,
    };
    Some(result)
}

fn format_classic_record(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    let result = match error {
        Error::InvalidCapturedLength { captured, snaplen } => write!(
            f,
            "captured packet length {captured} exceeds snapshot length {snaplen}"
        ),
        Error::InvalidOriginalLength { captured, original } => write!(
            f,
            "captured packet length {captured} exceeds original length {original}"
        ),
        Error::InvalidTimestampFraction {
            fraction,
            nanoseconds,
        } => {
            let unit = if *nanoseconds {
                "nanoseconds"
            } else {
                "microseconds"
            };
            let limit = if *nanoseconds {
                1_000_000_000
            } else {
                1_000_000
            };
            write!(
                f,
                "invalid timestamp {fraction} {unit}; expected a value below {limit}"
            )
        }
        Error::LengthOverflow { length } => {
            write!(f, "packet length {length} cannot be represented safely")
        }
        Error::InputLimitExceeded { attempted, limit } => write!(
            f,
            "PCAP input budget exceeded: {attempted} bytes would be processed (limit {limit})"
        ),
        Error::RecordLimitExceeded { limit } => {
            write!(f, "PCAP record limit exceeded: maximum {limit} records")
        }
        Error::ReaderContractViolation {
            returned,
            requested,
        } => write!(
            f,
            "input reader returned {returned} bytes for a {requested}-byte buffer"
        ),
        Error::ReaderTerminated => f.write_str("PCAP reader is terminated after a previous error"),
        Error::InvalidHeaderLayout => f.write_str("invalid fixed PCAP header layout"),
        Error::InterruptedLimitExceeded { limit } => {
            write!(
                f,
                "input reader returned Interrupted {limit} consecutive times"
            )
        }
        _ => return None,
    };
    Some(result)
}

fn format_pcapng(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    if let Some(result) = format_pcapng_section(error, f) {
        return Some(result);
    }
    format_pcapng_packet(error, f)
}

fn format_pcapng_section(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    let result = match error {
        Error::InvalidBlockLength { block_type, length } => {
            write!(
                f,
                "PCAPNG block 0x{block_type:08x} has invalid length {length}"
            )
        }
        Error::BlockLengthExceeded {
            block_type,
            length,
            limit,
        } => write!(
            f,
            "PCAPNG block 0x{block_type:08x} length {length} exceeds limit {limit}"
        ),
        Error::BlockLengthNotAligned { block_type, length } => write!(
            f,
            "PCAPNG block 0x{block_type:08x} length {length} is not 4-byte aligned"
        ),
        Error::BlockLengthMismatch {
            block_type,
            declared,
            trailing,
        } => write!(
            f,
            "PCAPNG block 0x{block_type:08x} length mismatch: header {declared}, trailer {trailing}"
        ),
        Error::InvalidByteOrderMagic { magic } => {
            write!(f, "invalid PCAPNG byte-order magic 0x{magic:08x}")
        }
        Error::UnsupportedPcapNgVersion { major, minor } => write!(
            f,
            "unsupported PCAPNG section version {major}.{minor}; supported versions are 1.0 and 1.2"
        ),
        Error::UnsupportedSectionLength { length } => write!(
            f,
            "finite PCAPNG section length {length} is unsupported by the streaming reader"
        ),
        Error::InvalidSectionLength { length } => {
            write!(f, "invalid PCAPNG section length {length}")
        }
        Error::SectionHeaderRequired => {
            f.write_str("PCAPNG input must begin with a section header block")
        }
        _ => return None,
    };
    Some(result)
}

fn format_pcapng_packet(error: &Error, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
    let result = match error {
        Error::InterfaceLimitExceeded { limit } => write!(
            f,
            "PCAPNG section contains more than {limit} interface descriptions"
        ),
        Error::UnknownInterface { section, index } => write!(
            f,
            "PCAPNG packet references unknown interface {index} in section {section}"
        ),
        Error::SimplePacketWithoutInterface => {
            f.write_str("PCAPNG simple packet has no interface description")
        }
        Error::DuplicateOption { block_type, code } => write!(
            f,
            "PCAPNG block 0x{block_type:08x} repeats known option {code}"
        ),
        Error::OptionLimitExceeded { limit } => {
            write!(f, "PCAPNG option list exceeds the {limit}-entry limit")
        }
        Error::OptionAfterTerminator { block_type } => write!(
            f,
            "PCAPNG block 0x{block_type:08x} contains an option after opt_endofopt"
        ),
        Error::InvalidOptionLength {
            block_type,
            code,
            length,
            expected,
            minimum,
        } => format_option_length(
            f,
            *block_type,
            *code,
            *length,
            expected.as_ref(),
            minimum.as_ref(),
        ),
        Error::UnsupportedFcsLength { bits } => write!(
            f,
            "unsupported PCAPNG FCS length {bits} bits; the reader requires whole octets"
        ),
        Error::InvalidPacketFlags { flags } => {
            write!(f, "invalid PCAPNG enhanced-packet flags 0x{flags:08x}")
        }
        Error::InvalidLinuxInterfaceIdentity => {
            f.write_str("invalid Linux identity in PCAPNG interface description")
        }
        Error::InvalidCollectionReport => {
            f.write_str("invalid or duplicate PCAPNG collection declaration")
        }
        Error::Frame(error) => write!(f, "invalid captured frame: {error}"),
        Error::Metadata(error) => write!(f, "invalid capture metadata: {error}"),
        _ => return None,
    };
    Some(result)
}

fn format_option_length(
    f: &mut fmt::Formatter<'_>,
    block_type: u32,
    code: u16,
    length: usize,
    expected: Option<&usize>,
    minimum: Option<&usize>,
) -> fmt::Result {
    match (expected, minimum) {
        (Some(expected), _) => write!(
            f,
            "PCAPNG block 0x{block_type:08x} option {code} has length {length}; expected {expected}"
        ),
        (_, Some(minimum)) => write!(
            f,
            "PCAPNG block 0x{block_type:08x} option {code} has length {length}; expected at least {minimum}"
        ),
        (None, None) => write!(
            f,
            "PCAPNG block 0x{block_type:08x} option {code} has invalid length {length}"
        ),
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Metadata(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FrameError> for Error {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<MetadataError> for Error {
    fn from(error: MetadataError) -> Self {
        Self::Metadata(error)
    }
}
