//! Capture metadata types shared by file and live backends

use crate::{LinkType, LinuxInterfaceIdentity};
use core::fmt;

/// Largest FCS length representable by PCAPNG's one-byte bit-count field
///
/// The `if_fcslen` option stores bits in an unsigned byte. A canonical status
/// accepts only complete octets, so 248 bits is the largest valid declaration
pub const MAX_FCS_LENGTH: u8 = u8::MAX / 8;

/// Largest timestamp exponent representable by PCAPNG's one-byte resolution field
///
/// The high bit selects the radix and the remaining seven bits store the exponent
pub const MAX_TIMESTAMP_RESOLUTION_EXPONENT: u8 = 0x7f;

/// Validation failures for source-provided capture metadata
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MetadataError {
    /// A present FCS declaration is outside the whole-octet PCAPNG range
    InvalidFcsLength {
        /// Candidate FCS length in bytes
        length: u8,
        /// Largest representable whole-octet FCS length
        max: u8,
    },
    /// A timestamp resolution exponent is outside PCAPNG's seven-bit field
    InvalidTimestampResolution {
        /// Timestamp radix, either decimal ten or binary two
        radix: u8,
        /// Candidate exponent
        exponent: u8,
        /// Largest representable exponent
        max: u8,
    },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFcsLength { length, max } => write!(
                formatter,
                "invalid FCS length {length} bytes; expected 1..={max}"
            ),
            Self::InvalidTimestampResolution {
                radix,
                exponent,
                max,
            } => write!(
                formatter,
                "invalid base-{radix} timestamp exponent {exponent}; expected 0..={max}"
            ),
        }
    }
}

impl std::error::Error for MetadataError {}

/// A section-scoped interface identifier from a capture format
///
/// # Invariants
///
/// `section` identifies the PCAPNG section and `index` identifies an interface
/// within that section. The pair is ordered so event and report output stays deterministic
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InterfaceId {
    /// Section number in file order, starting at zero
    pub section: u32,
    /// Interface description index within the section, starting at zero
    pub index: u32,
}

/// Logical byte offsets needed to revalidate packet evidence in its capture source
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureLocator {
    /// Classic PCAP record framing and captured-data offsets
    ClassicPcap {
        record_offset: u64,
        data_offset: u64,
    },
    /// PCAPNG block framing and captured-data offsets
    PcapNg {
        block_offset: u64,
        data_offset: u64,
        block_type: u32,
    },
}

/// Direction metadata supplied by a capture source
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    /// The source did not provide direction information
    #[default]
    Unknown,
    /// The frame entered the captured interface
    Inbound,
    /// The frame left the captured interface
    Outbound,
}

/// Frame-check-sequence information supplied by a capture source
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FcsStatus {
    /// The source did not provide FCS information
    #[default]
    Unknown,
    /// The capture excludes the FCS bytes
    Absent,
    /// The source declares an FCS of the specified byte length; retained bytes are not implied
    Present {
        /// Number of FCS bytes declared by the source
        length: FcsLength,
    },
}

impl FcsStatus {
    /// Construct a present FCS declaration after checking the PCAPNG field range
    /// # Errors
    /// Returns [`MetadataError::InvalidFcsLength`] for zero or a value above
    /// [`MAX_FCS_LENGTH`]
    pub const fn present(length: u8) -> Result<Self, MetadataError> {
        match FcsLength::new(length) {
            Ok(length) => Ok(Self::Present { length }),
            Err(error) => Err(error),
        }
    }

    /// Return the declared FCS length, if the source declared one
    #[must_use]
    pub const fn length(self) -> Option<u8> {
        match self {
            Self::Present { length } => Some(length.get()),
            Self::Unknown | Self::Absent => None,
        }
    }
}

/// A checked nonzero FCS length in bytes
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FcsLength(u8);

impl FcsLength {
    /// Construct a checked FCS length from a source byte count
    /// # Errors
    /// Returns [`MetadataError::InvalidFcsLength`] for zero or a value above
    /// [`MAX_FCS_LENGTH`]
    pub const fn new(length: u8) -> Result<Self, MetadataError> {
        if length == 0 || length > MAX_FCS_LENGTH {
            return Err(MetadataError::InvalidFcsLength {
                length,
                max: MAX_FCS_LENGTH,
            });
        }
        Ok(Self(length))
    }

    /// Return the FCS length in bytes
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Timestamp unit resolution used by a capture format
///
/// The fields stay private so every value passes through a checked constructor
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimestampResolution {
    radix: u8,
    exponent: u8,
}

impl TimestampResolution {
    /// One timestamp tick is one microsecond
    pub const MICROSECOND: Self = Self {
        radix: 10,
        exponent: 6,
    };

    /// One timestamp tick is one nanosecond
    pub const NANOSECOND: Self = Self {
        radix: 10,
        exponent: 9,
    };

    /// Construct a decimal timestamp resolution after checking its seven-bit exponent
    /// # Errors
    /// Returns [`MetadataError::InvalidTimestampResolution`] above the PCAPNG field range
    pub const fn decimal(exponent: u8) -> Result<Self, MetadataError> {
        if exponent > MAX_TIMESTAMP_RESOLUTION_EXPONENT {
            return Err(MetadataError::InvalidTimestampResolution {
                radix: 10,
                exponent,
                max: MAX_TIMESTAMP_RESOLUTION_EXPONENT,
            });
        }
        Ok(Self {
            radix: 10,
            exponent,
        })
    }

    /// Construct a binary timestamp resolution after checking its seven-bit exponent
    /// # Errors
    /// Returns [`MetadataError::InvalidTimestampResolution`] above the PCAPNG field range
    pub const fn binary(exponent: u8) -> Result<Self, MetadataError> {
        if exponent > MAX_TIMESTAMP_RESOLUTION_EXPONENT {
            return Err(MetadataError::InvalidTimestampResolution {
                radix: 2,
                exponent,
                max: MAX_TIMESTAMP_RESOLUTION_EXPONENT,
            });
        }
        Ok(Self { radix: 2, exponent })
    }

    /// Return the source radix used by this resolution
    #[must_use]
    pub const fn radix(self) -> u8 {
        self.radix
    }

    /// Return the source exponent
    #[must_use]
    pub const fn exponent(self) -> u8 {
        self.exponent
    }
}

/// Provenance of a capture timestamp
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimestampSource {
    /// Timestamp read from a capture file
    CaptureFile,
    /// Timestamp provenance was not supplied
    #[default]
    Unknown,
}

/// A timestamp retained without converting away its source resolution
/// # Invariants
///
/// `ticks` is the exact unsigned value read from the source. `offset_seconds`
/// is kept separately so consumers can choose when and how to apply it
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureTimestamp {
    ticks: u64,
    resolution: TimestampResolution,
    offset_seconds: i64,
    source: TimestampSource,
}

impl CaptureTimestamp {
    /// Construct a timestamp from an already checked source resolution
    #[must_use]
    pub const fn new(
        ticks: u64,
        resolution: TimestampResolution,
        offset_seconds: i64,
        source: TimestampSource,
    ) -> Self {
        Self {
            ticks,
            resolution,
            offset_seconds,
            source,
        }
    }

    /// Return the exact source tick count
    #[must_use]
    pub const fn ticks(self) -> u64 {
        self.ticks
    }

    /// Return the checked source resolution
    #[must_use]
    pub const fn resolution(self) -> TimestampResolution {
        self.resolution
    }

    /// Return the signed source offset in seconds
    #[must_use]
    pub const fn offset_seconds(self) -> i64 {
        self.offset_seconds
    }

    /// Return the timestamp provenance
    #[must_use]
    pub const fn source(self) -> TimestampSource {
        self.source
    }
}

/// VLAN metadata supplied separately from captured frame bytes
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VlanAuxData {
    /// VLAN tag protocol identifier
    pub tpid: u16,
    /// VLAN tag control information
    pub tci: u16,
}

/// Metadata associated with one captured frame
///
/// # Invariants
///
/// `link_type` identifies the source data-link layout and is never inferred from
/// retained bytes or interface names
/// `original_len` is the number of bytes present before capture truncation
/// Retained bytes are held by [`crate::CapturedFrame`] and must not exceed this value
/// Lengths derived from retained bytes are intentionally not duplicated here
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CaptureMetadata {
    interface: InterfaceId,
    linux_interface: Option<LinuxInterfaceIdentity>,
    link_type: LinkType,
    original_len: u32,
    locator: Option<CaptureLocator>,
    timestamp: Option<CaptureTimestamp>,
    direction: Direction,
    vlan: Option<VlanAuxData>,
    fcs: FcsStatus,
}

impl CaptureMetadata {
    /// Construct canonical Ethernet metadata from checked timestamp and FCS values
    ///
    /// Sources with another link type must apply [`Self::with_link_type`]
    #[must_use]
    pub const fn new(
        interface: InterfaceId,
        original_len: u32,
        locator: Option<CaptureLocator>,
        timestamp: Option<CaptureTimestamp>,
        direction: Direction,
        vlan: Option<VlanAuxData>,
        fcs: FcsStatus,
    ) -> Self {
        Self {
            interface,
            linux_interface: None,
            link_type: LinkType::Ethernet,
            original_len,
            locator,
            timestamp,
            direction,
            vlan,
            fcs,
        }
    }

    /// Construct Ethernet metadata for a source that only knows the interface and wire length
    #[must_use]
    pub const fn unknown(interface: InterfaceId, original_len: u32) -> Self {
        Self::new(
            interface,
            original_len,
            None,
            None,
            Direction::Unknown,
            None,
            FcsStatus::Unknown,
        )
    }

    /// Return the source interface identifier
    #[must_use]
    pub const fn interface(&self) -> InterfaceId {
        self.interface
    }

    /// Return the Linux source identity declared by a backend or capture file
    #[must_use]
    pub const fn linux_interface(&self) -> Option<LinuxInterfaceIdentity> {
        self.linux_interface
    }

    /// Attach a Linux source declaration; its authority depends on acquisition
    #[must_use]
    pub const fn with_linux_interface(self, linux_interface: LinuxInterfaceIdentity) -> Self {
        Self {
            linux_interface: Some(linux_interface),
            ..self
        }
    }

    /// Return the checked data-link identity supplied by the capture source
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Set the checked data-link identity while retaining all other metadata
    #[must_use]
    pub const fn with_link_type(self, link_type: LinkType) -> Self {
        Self { link_type, ..self }
    }

    /// Return the source-reported original wire length
    #[must_use]
    pub const fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Return the source locator, when available
    #[must_use]
    pub const fn locator(&self) -> Option<CaptureLocator> {
        self.locator
    }

    /// Return the source timestamp, when available
    #[must_use]
    pub const fn timestamp(&self) -> Option<CaptureTimestamp> {
        self.timestamp
    }

    /// Return source direction metadata
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Return out-of-band VLAN metadata, when available
    #[must_use]
    pub const fn vlan(&self) -> Option<VlanAuxData> {
        self.vlan
    }

    /// Return source FCS metadata
    #[must_use]
    pub const fn fcs(&self) -> FcsStatus {
        self.fcs
    }
}
