use core::fmt;

use serde::Serialize;

/// Default maximum compressed ZIP artifact size
pub const MAX_ZIP_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum central-directory entry count processed
pub const MAX_ZIP_ENTRIES: usize = 4_096;
/// Default maximum declared expanded bytes from one member
pub const MAX_ZIP_ENTRY_EXPANDED_BYTES: usize = 16 * 1024 * 1024;
/// Default maximum declared expanded bytes charged by one archive parser
pub const MAX_ZIP_TOTAL_EXPANDED_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum nested archive depth
pub const MAX_ZIP_DEPTH: usize = 4;

/// Caller-selected resource budgets for parsing one ZIP archive
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipArtifactLimits {
    /// Maximum bytes in the supplied compressed archive
    pub max_archive_bytes: usize,
    /// Maximum central-directory entry count processed
    pub max_entries: usize,
    /// Maximum declared expanded bytes from one member
    pub max_entry_expanded_bytes: usize,
    /// Maximum declared expanded bytes charged in one archive parse
    pub max_total_expanded_bytes: usize,
    /// Maximum nested archive depth, where a top-level archive has depth zero
    pub max_depth: usize,
}

impl Default for ZipArtifactLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: MAX_ZIP_ARCHIVE_BYTES,
            max_entries: MAX_ZIP_ENTRIES,
            max_entry_expanded_bytes: MAX_ZIP_ENTRY_EXPANDED_BYTES,
            max_total_expanded_bytes: MAX_ZIP_TOTAL_EXPANDED_BYTES,
            max_depth: MAX_ZIP_DEPTH,
        }
    }
}

/// Why a ZIP entry was recorded without expanded bytes
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZipArtifactOmissionReason {
    /// The entry uses encryption and no decryption key was supplied
    Encrypted,
    /// The entry uses a compression method other than stored or deflate
    UnsupportedCompression { method: u16 },
    /// The entry's declared expanded size is above its individual ceiling
    EntryExpandedByteLimit,
    /// The entry would exceed the archive's remaining expanded-byte budget
    TotalExpandedByteLimit,
    /// The entry would exceed a shared operation-wide expanded-byte budget
    OperationExpandedByteLimit,
    /// The archive contains more entries than the configured count ceiling
    EntryCountLimit,
    /// The archive is nested deeper than the configured depth ceiling
    DepthLimit,
    /// Member bytes could not be validated after the archive structure was accepted
    EntryDataFailure {
        /// Zero-based position in the archive's central directory
        index: usize,
        /// Failed member-data validation step
        failure: ZipEntryDataFailure,
    },
}

/// A counted reason for omitting one or more archive entries
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ZipArtifactOmission {
    /// Reason for omitting the entry or entries
    pub reason: ZipArtifactOmissionReason,
    /// Number of entries omitted for this reason
    pub count: usize,
}

/// Central-directory metadata retained for one ZIP entry
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ZipArtifactEntryMetadata {
    /// Zero-based position in the archive's central directory
    pub index: usize,
    /// Name bytes exactly as stored by the archive
    pub raw_name: Vec<u8>,
    /// Whether the member name marks a directory
    pub is_directory: bool,
    /// ZIP compression method number
    pub compression_method: u16,
    /// Whether the archive marks the entry as encrypted
    pub encrypted: bool,
    /// Compressed member size recorded in the central directory
    pub compressed_size: u64,
    /// Expanded member size recorded in the central directory
    pub expanded_size: u64,
    /// CRC-32 recorded in the central directory
    pub crc32: u32,
    /// Offset of the member's local file header
    pub local_header_offset: u64,
    /// Unix mode bits when present in the archive
    pub unix_mode: Option<u32>,
}

/// One ZIP member with its metadata, retained bytes, or omission reason
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ZipArtifactEntry {
    /// Member metadata copied from the archive
    pub metadata: ZipArtifactEntryMetadata,
    /// Expanded member bytes after size and CRC checks
    pub content: Option<Vec<u8>>,
    /// Why this member has no expanded bytes
    pub omission: Option<ZipArtifactOmissionReason>,
}

/// Facts and retained members from one ZIP artifact
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ZipArtifactReport {
    /// SHA-256 of the exact compressed archive bytes
    pub archive_sha256: String,
    /// Number of compressed archive bytes supplied to the parser
    pub archive_size: usize,
    /// Current nested archive depth, where a top-level archive has depth zero
    pub depth: usize,
    /// Number of entries declared by the central directory
    pub entry_count: usize,
    /// Number of entries whose expanded bytes were retained
    pub extracted_entry_count: usize,
    /// Successfully expanded bytes from this archive
    pub expanded_byte_count: usize,
    /// Declared member bytes charged before extraction, including failed validations
    pub expanded_work_byte_count: usize,
    /// Number of entries omitted by limits, unsupported features, or member-data failures
    pub omitted_entry_count: usize,
    /// Entry metadata and content when the archive is within its depth and count budgets
    pub entries: Vec<ZipArtifactEntry>,
    /// Counts of entries omitted by limits, unsupported features, or member-data failures
    pub omissions: Vec<ZipArtifactOmission>,
}

/// Why ZIP member bytes failed validation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZipEntryDataFailure {
    /// The local header or member data could not be read
    InvalidEntryHeader,
    /// Reading compressed or expanded bytes failed
    ReadFailure,
    /// Deflate data could not be decoded
    DecompressionFailure,
    /// Expanded length, compressed length, or stream boundary disagreed with metadata
    SizeMismatch,
    /// A data descriptor did not uniquely match the central-directory CRC and sizes
    DataDescriptorMismatch,
    /// A data descriptor overlapped another member's local header or compressed bytes
    DataDescriptorOverlap,
    /// Expanded bytes did not match the central-directory CRC-32
    CrcMismatch,
    /// A bounded member-output allocation could not be reserved
    AllocationFailure,
}

/// Invalid archive structure or resource request
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZipArtifactError {
    /// The compressed archive exceeded the configured archive ceiling
    ArchiveTooLarge { length: usize, maximum: usize },
    /// The supplied bytes do not form a valid ZIP archive
    InvalidArchive,
    /// More than one structurally plausible end record ends at the object boundary
    AmbiguousEndRecords,
    /// The central-directory count does not fit the report's platform-sized field
    EntryCountOutOfRange { count: u64 },
    /// A required operational budget is zero
    InvalidLimits { field: &'static str },
    /// A bounded report or metadata allocation could not be reserved
    AllocationFailure,
}

impl fmt::Display for ZipArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "ZIP archive has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidArchive => formatter.write_str("invalid ZIP archive"),
            Self::AmbiguousEndRecords => {
                formatter.write_str("ZIP archive has ambiguous end records")
            }
            Self::EntryCountOutOfRange { count } => write!(
                formatter,
                "ZIP archive has {count} entries, which cannot be represented on this platform"
            ),
            Self::InvalidLimits { field } => {
                write!(formatter, "ZIP limit {field} must be positive")
            }
            Self::AllocationFailure => formatter.write_str("ZIP report allocation failed"),
        }
    }
}

impl std::error::Error for ZipArtifactError {}
