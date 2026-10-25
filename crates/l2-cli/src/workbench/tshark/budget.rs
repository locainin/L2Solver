use serde::Serialize;
use std::{fs::Metadata, path::PathBuf};

/// Resource budget for temporary `TShark` object export and directory discovery
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ObjectExportBudget {
    /// Maximum temporary object bytes observed while `TShark` is running
    pub temporary_bytes: u64,
    /// Maximum non-directory entries observed while `TShark` is running
    pub temporary_files: u64,
}

impl ObjectExportBudget {
    /// Match the default artifact byte and count ceilings during temporary extraction
    pub const DEFAULT: Self = Self {
        temporary_bytes: 512 * 1024 * 1024,
        temporary_files: 16_384,
    };
}

impl Default for ObjectExportBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Highest object-tree byte and file totals counted during `TShark` export scans
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ObjectExportUsage {
    pub temporary_bytes_peak: u64,
    pub temporary_files_peak: u64,
    pub temporary_tree_entries_peak: u64,
    pub protocol_directory_count: u64,
    /// Whether the latest tree scan visited every entry before finishing
    pub temporary_scan_complete: bool,
}

/// Completion state for temporary `TShark` object generation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ObjectExportStatus {
    Complete,
    Partial,
}

/// Resource that caused temporary object export to stop
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ObjectExportResource {
    Bytes,
    Files,
    TreeEntries,
}

impl ObjectExportResource {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Bytes => "temporary bytes",
            Self::Files => "temporary files",
            Self::TreeEntries => "temporary tree entries",
        }
    }
}

/// A temporary output budget exceeded by an observed `TShark` directory state
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObjectExportLimit {
    pub resource: ObjectExportResource,
    pub maximum: u64,
    pub observed: u64,
    pub usage: ObjectExportUsage,
    pub stable_objects: Vec<StableObject>,
}

/// One regular object unchanged across consecutive complete tree scans
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StableObject {
    pub relative_path: PathBuf,
    pub snapshot: ObjectFileSnapshot,
}

/// POSIX identity and timestamps used to reject objects changed during partial cleanup
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObjectFileSnapshot {
    length: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl ObjectFileSnapshot {
    pub(super) fn from_metadata(metadata: &Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            if !metadata.file_type().is_file() || metadata.nlink() != 1 {
                return None;
            }
            Some(Self {
                length: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }

    pub(super) fn matches(self, metadata: &Metadata) -> bool {
        Self::from_metadata(metadata) == Some(self)
    }

    pub(super) fn matches_after_move(self, metadata: &Metadata) -> bool {
        let Some(current) = Self::from_metadata(metadata) else {
            return false;
        };
        #[cfg(unix)]
        {
            self.length == current.length
                && self.device == current.device
                && self.inode == current.inode
                && self.modified_seconds == current.modified_seconds
                && self.modified_nanoseconds == current.modified_nanoseconds
        }
        #[cfg(not(unix))]
        {
            let _ = current;
            false
        }
    }
}

impl ObjectExportLimit {
    pub(super) const fn new(
        resource: ObjectExportResource,
        maximum: u64,
        observed: u64,
        usage: ObjectExportUsage,
    ) -> Self {
        Self {
            resource,
            maximum,
            observed,
            usage,
            stable_objects: Vec::new(),
        }
    }

    pub(super) fn describe(&self) -> String {
        format!(
            "`TShark` object export stopped after observing {} above its budget of {} (observed {}; tree-entry limits stop at the first extra entry, while byte and file totals may overshoot between scans)",
            self.resource.label(),
            self.maximum,
            self.observed
        )
    }
}
