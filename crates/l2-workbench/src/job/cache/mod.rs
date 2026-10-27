//! Versioned persistent cache for recovery stages and job checkpoints

mod database;
mod entry;
mod error;
mod execution;
mod filesystem;
mod fingerprint;
mod key;
mod manager;
mod manifest;
mod model;
mod retired;

pub use entry::{CacheEntry, Lease};
pub use error::{CacheError, Result};
pub use execution::{ActiveExecution, ExecutionCheckpointLimits, ExecutionWriter};
pub use fingerprint::{FileTimestamp, SourceFingerprint, SourceIdentity};
pub use key::StageKey;
pub use manager::Cache;
pub use model::{
    CacheReadPolicy, CacheStats, Checkpoint, CheckpointStatus, JOB_SNAPSHOT_VERSION, PruneReport,
    StageStatus,
};
/// JSON value used for cache entry receipts
pub use serde_json::Value;
