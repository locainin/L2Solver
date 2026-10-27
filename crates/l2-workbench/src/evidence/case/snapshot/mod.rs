//! Exact Case snapshots split by wire format, reader, writer, and bounded I/O

mod format;
mod io;
mod reader;
mod writer;

use serde::{Deserialize, Serialize};

/// Caller-selected physical and expanded-byte limits for one exact Case snapshot
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseSnapshotLimits {
    maximum_storage_bytes: u64,
    maximum_decoded_bytes: u64,
}

impl CaseSnapshotLimits {
    /// Set separate physical-storage and expanded-data bounds
    #[must_use]
    pub const fn new(maximum_storage_bytes: u64, maximum_decoded_bytes: u64) -> Self {
        Self {
            maximum_storage_bytes,
            maximum_decoded_bytes,
        }
    }

    /// Return the maximum combined compressed graph and raw blob-pack bytes
    #[must_use]
    pub const fn maximum_storage_bytes(self) -> u64 {
        self.maximum_storage_bytes
    }

    /// Return the maximum expanded graph and retained blob bytes
    #[must_use]
    pub const fn maximum_decoded_bytes(self) -> u64 {
        self.maximum_decoded_bytes
    }
}

/// Measured bytes written by one Case snapshot encoding
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSnapshotUsage {
    /// Physical bytes in the compressed graph stream
    pub graph_bytes: u64,
    /// Expanded JSONL bytes in the graph stream
    pub graph_decoded_bytes: u64,
    /// Exact raw blob bytes in the content pack
    pub blob_pack_bytes: u64,
}
