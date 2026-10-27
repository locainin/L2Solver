//! Inspect, reuse, and atomically publish owned extraction and refinement directories

mod bounded;
mod manifest;
mod publish;
mod reuse;
mod stamp;

use l2_workbench::job::cache::SourceIdentity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, path::Path};

pub use stamp::OutputFileStamp;

/// The result workflow that owns a directory
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultKind {
    /// Capture extraction output
    Extract,
    /// Artifact refinement output
    Refine,
}

/// Stable identity for the algorithm and settings that produced one result
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResultIdentity {
    /// The workflow that produced the result
    pub kind: ResultKind,
    /// Version of the result-producing algorithm
    pub algorithm_version: u32,
    /// Strong or fast identity for the source inputs
    #[serde(deserialize_with = "bounded::deserialize_source_identity")]
    pub source: SourceIdentity,
    /// Canonically encoded algorithm settings
    #[serde(deserialize_with = "bounded::deserialize_settings")]
    pub settings: Value,
}

/// Reusable output from an owned result directory
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReusedResult {
    /// Whether the stored run completed every requested component
    pub complete: bool,
    /// Output file receipts verified against the directory
    pub artifacts: Vec<OutputFileStamp>,
}

/// A safely inspected result destination held until reuse or publication
pub struct ResultDirectory {
    path: std::path::PathBuf,
    kind: ResultKind,
    state: manifest::DirectoryState,
}

impl ResultDirectory {
    /// Safely inspect an absent or owned result destination
    ///
    /// Existing unrelated directories, unsafe entries, and incompatible owned results fail
    /// during inspection so callers can decide before reading their inputs
    ///
    /// # Errors
    /// Returns an error when the destination is unsafe, unrelated, corrupt, or owned by another
    /// result workflow
    pub fn inspect(path: &Path, kind: ResultKind) -> Result<Self, Box<dyn Error>> {
        manifest::inspect(path, kind)
    }

    /// Return a matching owned result after checking its identity and file receipts
    ///
    /// Only a destination that was absent during inspection returns `None`. Partial results are
    /// reported with `complete == false`, so they cannot be mistaken for complete negative work
    ///
    /// # Errors
    /// Returns an actionable conflict for a legacy or incompatible result and an error when the
    /// directory, source, or one of its output files changed after inspection
    pub fn reuse(
        &self,
        identity: &ResultIdentity,
        current_input: Option<&Path>,
        strict: bool,
    ) -> Result<Option<ReusedResult>, Box<dyn Error>> {
        reuse::reuse(self, identity, current_input, strict)
    }

    pub(crate) fn reuse_refinement(
        &self,
        identity: &ResultIdentity,
        labels: &[String],
        strict: bool,
        strong_source: impl FnOnce() -> Result<SourceIdentity, Box<dyn Error>>,
    ) -> Result<Option<ReusedResult>, Box<dyn Error>> {
        reuse::reuse_refinement(self, identity, labels, strict, strong_source)
    }

    /// Write a result into a private staging directory and atomically publish it
    ///
    /// The callback builds all user-visible files. A receipt is appended to the staged manifest
    /// only after the callback succeeds; publication then creates a new destination or atomically
    /// replaces the inspected directory
    ///
    /// # Errors
    /// Returns an error if the job is cancelled, the writer fails, the result is malformed, or
    /// atomic publication cannot be completed
    pub fn publish<T>(
        self,
        identity: &ResultIdentity,
        job: &l2_workbench::job::Job,
        writer: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        publish::publish(self, identity, job, writer)
    }
}

#[cfg(test)]
#[path = "../../tests/result_directory/mod.rs"]
mod tests;
