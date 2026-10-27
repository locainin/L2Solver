use std::{error::Error, fmt, io};

use crate::job::MemoryError;

/// Errors returned by persistent cache operations
#[derive(Debug)]
#[non_exhaustive]
pub enum CacheError {
    /// The shared live-memory budget could not admit cache work
    Memory(MemoryError),
    /// The filesystem rejected a cache operation
    Io(io::Error),
    /// `SQLite` rejected a cache operation
    Database(Box<dyn Error + Send + Sync>),
    /// Cache metadata could not be encoded or decoded
    Json(Box<dyn Error + Send + Sync>),
    /// A cache directory or file was replaced or is not a regular object
    UnsafePath(&'static str),
    /// The cache database was created by an incompatible version
    IncompatibleSchema(u32),
    /// The cache database belongs to another application
    IncompatibleDatabase,
    /// `SQLite` reported that its database file is corrupt
    CorruptDatabase,
    /// A cached entry failed its manifest or metadata checks
    CorruptEntry(String),
    /// A saved job checkpoint failed its schema or JSON checks
    CorruptCheckpoint,
    /// Another process currently holds a conflicting entry lease
    LockBusy,
    /// Cache initialization or quota maintenance stayed busy past its retry window
    CacheBusy,
    /// A cache entry's serialized metadata exceeded its size limit
    MetadataTooLarge {
        /// Maximum serialized metadata size
        limit_bytes: usize,
        /// Actual serialized metadata size
        actual_bytes: usize,
    },
    /// An input used to build a cache identity is invalid
    InvalidInput(&'static str),
    /// A source changed while its fingerprint or digest was being calculated
    SourceChanged,
    /// A source or cache size cannot be represented by the stored metadata
    SizeOverflow,
    /// An entry cannot fit without evicting protected cache data
    QuotaExceeded {
        /// Configured limit for indexed stage files
        limit_bytes: u64,
        /// Minimum bytes needed after safe eviction
        required_bytes: u64,
    },
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => write!(formatter, "cache memory admission failed: {error}"),
            Self::Io(error) => write!(formatter, "cache filesystem error: {error}"),
            Self::Database(error) => write!(formatter, "cache database error: {error}"),
            Self::Json(error) => write!(formatter, "cache metadata error: {error}"),
            Self::UnsafePath(message) => write!(formatter, "unsafe cache path: {message}"),
            Self::IncompatibleSchema(version) => {
                write!(formatter, "unsupported cache schema version {version}")
            }
            Self::IncompatibleDatabase => formatter.write_str(
                "cache database schema is unrecognized or incomplete; preserve it and use a new state path",
            ),
            Self::CorruptDatabase => formatter.write_str("cache database is corrupt"),
            Self::CorruptEntry(message) => write!(formatter, "cached entry is corrupt: {message}"),
            Self::CorruptCheckpoint => formatter.write_str("saved job checkpoint is corrupt"),
            Self::LockBusy => formatter.write_str("cache entry is currently in use"),
            Self::CacheBusy => {
                formatter.write_str("cache maintenance stayed busy; retry the operation")
            }
            Self::MetadataTooLarge {
                limit_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "cache metadata has {actual_bytes} bytes; maximum is {limit_bytes} bytes"
            ),
            Self::InvalidInput(message) => write!(formatter, "invalid cache input: {message}"),
            Self::SourceChanged => formatter.write_str("source changed while it was fingerprinted"),
            Self::SizeOverflow => formatter.write_str("cache size exceeded its supported range"),
            Self::QuotaExceeded {
                limit_bytes,
                required_bytes,
            } => write!(
                formatter,
                "cache stage needs at least {required_bytes} bytes under a {limit_bytes}-byte quota"
            ),
        }
    }
}

impl Error for CacheError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Database(error) | Self::Json(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for CacheError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CacheError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(Box::new(error))
    }
}

impl From<rusqlite::Error> for CacheError {
    fn from(error: rusqlite::Error) -> Self {
        match &error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
                ) =>
            {
                Self::CorruptDatabase
            }
            _ => Self::Database(Box::new(error)),
        }
    }
}

/// Result type for persistent cache operations
pub type Result<T> = std::result::Result<T, CacheError>;

impl From<MemoryError> for CacheError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}
