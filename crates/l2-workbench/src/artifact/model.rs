use core::fmt;

use serde::{Deserialize, Serialize};

/// Executable container format recognized by the bounded header parser
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// ELF executable, shared object, or object image
    Elf,
    /// Portable Executable image
    PortableExecutable,
}

/// Exact file range used to support a parsed value
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileRange {
    /// Zero-based offset in the supplied artifact
    pub offset: usize,
    /// Number of source bytes in this range
    pub length: usize,
}

/// One file-backed virtual address mapping
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileMapping {
    /// First virtual address in the mapped range
    pub address: u64,
    /// First raw file byte in the mapped range
    pub file_offset: usize,
    /// Number of file-backed bytes
    pub file_size: usize,
    /// Format-specific section or segment flags
    pub flags: u64,
    /// Whether the format marks this file-backed range executable
    pub executable: bool,
}

/// Executable entry value stated by the file header
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntryPoint {
    /// Literal virtual address from the parsed header
    pub address: u64,
    /// File offset for the entry byte when it maps to retained source bytes
    pub file_offset: Option<usize>,
}

/// One validated section or segment record
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactSection {
    /// Decoded section or segment name
    pub name: String,
    /// First virtual address, when the format provides one
    pub address: u64,
    /// File offset when the section has file-backed bytes
    pub file_offset: Option<usize>,
    /// Number of file-backed bytes
    pub file_size: usize,
    /// Number of bytes in memory, when distinct from file size
    pub memory_size: usize,
    /// Format-specific flags
    pub flags: u64,
}

/// Literal kind of symbol or import reference
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactReferenceKind {
    /// A symbol name retained from a symbol or export table
    Symbol,
    /// A function or object name retained from an import table
    Import,
}

/// One literal name and its exact source table ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactReference {
    /// Literal name decoded from the bounded table
    pub name: String,
    /// Raw dependency name when the format supplies a library association
    pub library: Option<String>,
    /// Exact dependency-name bytes when the format supplies a library name
    pub library_range: Option<FileRange>,
    /// Name or import table record
    pub kind: ArtifactReferenceKind,
    /// Exact table record bytes supporting this name
    pub record_range: FileRange,
    /// Exact name bytes supporting the displayed literal
    pub name_range: Option<FileRange>,
    /// Address value when supplied by the symbol or export table
    pub address: Option<u64>,
}

/// Parsed image facts tied to the exact supplied byte string
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactReport {
    /// Recognized file format
    pub format: ArtifactFormat,
    /// Content hash of the exact supplied bytes
    pub sha256: String,
    /// Numeric machine identifier from the file header
    pub machine: u16,
    /// Human-readable architecture label derived from the machine field
    pub architecture: String,
    /// Parsed 32- or 64-bit class
    pub bitness: u8,
    /// Literal executable entry point, when present
    pub entrypoint: Option<EntryPoint>,
    /// Validated section and segment records
    pub sections: Vec<ArtifactSection>,
    /// Validated file-backed virtual address mappings
    pub mappings: Vec<FileMapping>,
    /// Literal symbols and imports with source ranges
    pub references: Vec<ArtifactReference>,
    /// Limits on interpreting static image metadata
    pub limitations: Vec<&'static str>,
}

impl ArtifactReport {
    /// Map one complete virtual address range to raw source bytes
    ///
    /// # Errors
    /// Returns an error if no single file-backed mapping contains the range or
    /// if more than one mapping could support it
    pub fn file_offset_for_address(
        &self,
        address: u64,
        length: usize,
    ) -> Result<usize, ArtifactError> {
        self.find_file_offset(address, length, false)
    }

    /// Map one complete address range only when the image marks it executable
    ///
    /// # Errors
    /// Returns an error if no unique executable file mapping contains the range
    pub fn executable_file_offset_for_address(
        &self,
        address: u64,
        length: usize,
    ) -> Result<usize, ArtifactError> {
        self.find_file_offset(address, length, true)
    }

    fn find_file_offset(
        &self,
        address: u64,
        length: usize,
        executable_only: bool,
    ) -> Result<usize, ArtifactError> {
        let length_u64 = u64::try_from(length)
            .map_err(|_| ArtifactError::UnmappedAddress { address, length })?;
        let mut offsets = self.mappings.iter().filter_map(|mapping| {
            if executable_only && !mapping.executable {
                return None;
            }
            let displacement = address.checked_sub(mapping.address)?;
            let end = displacement.checked_add(length_u64)?;
            let file_size = u64::try_from(mapping.file_size).ok()?;
            if end <= file_size {
                usize::try_from(displacement)
                    .ok()
                    .and_then(|delta| mapping.file_offset.checked_add(delta))
            } else {
                None
            }
        });
        let first = offsets
            .next()
            .ok_or(ArtifactError::UnmappedAddress { address, length })?;
        if offsets.next().is_some() {
            return Err(ArtifactError::AmbiguousAddress { address });
        }
        Ok(first)
    }
}

/// Tool identity attached to one imported static analysis report
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisTool {
    /// Stable tool name
    pub name: String,
    /// Exact version text supplied by the caller
    pub version: String,
}

/// One r2 function whose reported address maps to exact source bytes
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisFunction {
    /// Function name reported by r2
    pub name: String,
    /// Virtual address reported by r2
    pub address: u64,
    /// Raw file offset resolved through PE/ELF mappings
    pub file_offset: usize,
    /// Number of exact source bytes retained for this function
    pub code_length: usize,
    /// Exact function bytes as lowercase hexadecimal text
    pub code_bytes_hex: String,
    /// SHA-256 of the exact function bytes
    pub code_sha256: String,
    /// Static cross-reference facts whose source lies in this function
    pub external_observations: Vec<ExternalObservation>,
}

/// Why one tool-reported function was not bound to exact source bytes
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRejectionReason {
    /// The tool reported no bytes for the function
    EmptyRange,
    /// The tool-reported function exceeded the per-function byte ceiling
    FunctionSizeLimit,
    /// Retaining the function would exceed the receipt's aggregate code budget
    AggregateCodeLimit,
    /// The complete function range does not map to file-backed executable bytes
    UnmappedAddress,
    /// More than one executable mapping could support the function range
    AmbiguousAddress,
    /// The reported virtual address range overflows its address space
    AddressRangeOverflow,
    /// The resolved file range did not fit the supplied artifact bytes
    SourceRangeUnavailable,
}

/// One tool-reported function omitted from verified source-byte evidence
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RejectedFunction {
    /// Function name reported by r2
    pub name: String,
    /// Virtual address reported by r2
    pub address: u64,
    /// Function length reported by r2
    pub length: u64,
    /// Bounded reason the function was not retained
    pub reason: FunctionRejectionReason,
}

/// One static cross-reference emitted by the analysis tool
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalObservation {
    /// Source virtual address reported by r2
    pub from_address: u64,
    /// Source file offset when it maps to a retained file byte
    pub source_file_offset: Option<usize>,
    /// Target virtual address reported by r2
    pub target_address: u64,
    /// Reference type reported by r2
    pub reference_type: String,
    /// Target label reported by r2 when available
    pub reference_name: Option<String>,
}

/// One literal import record reported by r2
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisImport {
    /// Symbol ordinal reported by r2
    pub ordinal: Option<u64>,
    /// Binding label reported by r2
    pub binding: Option<String>,
    /// Symbol type reported by r2
    pub symbol_type: Option<String>,
    /// Literal imported symbol name reported by r2
    pub name: String,
}

/// Source-bound import, function, and xref facts from a read-only r2 run
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnalysisReceipt {
    /// Tool identity and version text supplied for this report
    pub tool: AnalysisTool,
    /// SHA-256 of the exact original artifact bytes
    pub source_sha256: String,
    /// Whether every reported function was bound to exact source bytes
    pub complete: bool,
    /// r2 entrypoint records resolved to exact file offsets
    pub entrypoints: Vec<EntryPoint>,
    /// r2 functions resolved to exact source byte ranges
    pub functions: Vec<AnalysisFunction>,
    /// Reported functions omitted because their bytes could not be bounded and verified
    pub rejected_functions: Vec<RejectedFunction>,
    /// Literal imported names reported by r2
    pub imports: Vec<AnalysisImport>,
    /// Xrefs that do not map to exactly one retained function
    pub unassociated_observations: Vec<ExternalObservation>,
    /// Static-analysis limitations
    #[serde(skip_deserializing)]
    pub limitations: Vec<&'static str>,
}

/// Malformed, unsupported, or out-of-bounds executable metadata
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// The input does not have a supported executable signature
    UnsupportedFormat,
    /// The artifact exceeds the in-memory inspection ceiling
    ArtifactTooLarge { length: usize, maximum: usize },
    /// A source range was truncated or outside the supplied file
    InvalidRange {
        offset: usize,
        length: usize,
        total: usize,
    },
    /// A table count or record size exceeded a configured bound
    LimitExceeded { field: &'static str, maximum: usize },
    /// A required header field has an unsupported or invalid value
    InvalidHeader { field: &'static str },
    /// A name table entry was not a bounded NUL-terminated string
    InvalidName { offset: usize },
    /// A virtual address does not map to source bytes
    UnmappedAddress { address: u64, length: usize },
    /// More than one load range maps an address ambiguously
    AmbiguousAddress { address: u64 },
    /// The expected original artifact hash differs from exact input bytes
    SourceHashMismatch,
    /// One r2 output payload exceeded the JSON budget
    R2JsonTooLarge { length: usize, maximum: usize },
    /// One r2 JSON payload or required record was malformed
    InvalidR2Json { field: &'static str },
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => formatter.write_str("unsupported executable format"),
            Self::ArtifactTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "artifact has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidRange {
                offset,
                length,
                total,
            } => write!(
                formatter,
                "file range {offset}+{length} is outside {total} source bytes"
            ),
            Self::LimitExceeded { field, maximum } => {
                write!(formatter, "artifact {field} exceeds maximum {maximum}")
            }
            Self::InvalidHeader { field } => write!(formatter, "invalid executable {field}"),
            Self::InvalidName { offset } => {
                write!(formatter, "invalid bounded name at file offset {offset}")
            }
            Self::UnmappedAddress { address, length } => write!(
                formatter,
                "virtual range {address:#x}+{length} is not file-backed"
            ),
            Self::AmbiguousAddress { address } => {
                write!(
                    formatter,
                    "virtual address {address:#x} has multiple file mappings"
                )
            }
            Self::SourceHashMismatch => {
                formatter.write_str("analysis source hash does not match the supplied bytes")
            }
            Self::R2JsonTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "r2 JSON has {length} bytes; maximum is {maximum}"
                )
            }
            Self::InvalidR2Json { field } => write!(formatter, "invalid r2 JSON {field}"),
        }
    }
}

impl std::error::Error for ArtifactError {}
