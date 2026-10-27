use crate::job::{JobSnapshot, cache::key::StageKey};

/// Version of the serialized [`JobSnapshot`] checkpoint representation
///
/// Version 4 adds tagged cohort and publication transition examples
/// Versions 1 through 3 remain readable with their earlier snapshot shapes
pub const JOB_SNAPSHOT_VERSION: u32 = 4;

pub(super) const fn supports_job_snapshot_version(version: u32) -> bool {
    matches!(version, 1 | 2 | 3 | JOB_SNAPSHOT_VERSION)
}

/// Whether a cached stage contains its complete result or only resumable work
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StageStatus {
    /// The stage reached a terminal result, including a valid empty result
    Complete,
    /// The stage stopped before producing a terminal result
    Partial,
}

impl StageStatus {
    pub(super) const fn to_database(self) -> i64 {
        match self {
            Self::Complete => 1,
            Self::Partial => 2,
        }
    }

    pub(super) const fn from_database(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Complete),
            2 => Some(Self::Partial),
            _ => None,
        }
    }
}

/// Which stage states are eligible for a cache lookup
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CacheReadPolicy {
    /// Return a terminal result only
    CompleteOnly,
    /// Return terminal and resumable results, keeping their statuses distinct
    AllowPartial,
}

/// Whether a saved job checkpoint is active or finished
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CheckpointStatus {
    /// The job can resume from this checkpoint
    Active,
    /// The job reached a terminal state
    Complete,
}

impl CheckpointStatus {
    pub(super) const fn to_database(self) -> i64 {
        match self {
            Self::Active => 1,
            Self::Complete => 2,
        }
    }

    pub(super) const fn from_database(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::Active),
            2 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// A durable progress snapshot associated with its stage key and job status
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Checkpoint {
    /// Stable key for the work represented by this snapshot
    pub key: StageKey,
    /// Whether the saved job may resume
    pub status: CheckpointStatus,
    /// Version used to encode the snapshot field
    pub snapshot_version: u32,
    /// The canonical job progress snapshot
    pub snapshot: JobSnapshot,
}

/// Counts, storage use, and quota pressure for one cache
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct CacheStats {
    /// Number of indexed stage results
    pub entries: u64,
    /// Indexed stage and active execution bytes plus in-flight reservations
    pub entry_bytes: u64,
    /// Bytes above the configured limit because leases or checkpoints prevent eviction
    pub over_limit_bytes: u64,
    /// Number of saved job checkpoints
    pub checkpoints: u64,
}

/// Results from an LRU prune or clear operation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PruneReport {
    /// Number of stage entries removed
    pub removed_entries: u64,
    /// Bytes removed from indexed stage directories
    pub removed_bytes: u64,
    /// Entries retained because another process has an open lease or reader
    pub skipped_locked: u64,
    /// Entries retained by active durable checkpoints
    pub skipped_checkpoints: u64,
    /// Stage, active execution, and reserved bytes remaining after pruning
    pub remaining_bytes: u64,
}
