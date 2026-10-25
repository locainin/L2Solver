use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{hashing::is_sha256_digest, sha256};

use super::{
    error::{CacheError, Result},
    fingerprint::SourceIdentity,
};

const KEY_FORMAT_VERSION: u32 = 1;

/// Stable identity for one algorithm stage and its declared inputs
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[non_exhaustive]
pub struct StageKey {
    digest: String,
    stage: String,
}

#[derive(Serialize)]
struct KeyMaterial<'a> {
    format_version: u32,
    stage: &'a str,
    stage_version: u32,
    algorithm: &'a str,
    policy: &'a Value,
    source: &'a SourceIdentity,
    dependencies: Vec<&'a str>,
}

impl StageKey {
    /// Builds a key from stable stage inputs and canonical JSON policy data
    ///
    /// The policy is serialized by `serde_json` in stable map order. Progress, job state,
    /// output paths, and produced results are not part of the key
    ///
    /// # Errors
    /// Returns an error when the stage or algorithm name is empty or too long, or when key
    /// material cannot be serialized
    pub fn new(
        stage: impl Into<String>,
        stage_version: u32,
        algorithm: impl Into<String>,
        policy: &Value,
        source: &SourceIdentity,
        dependencies: &[Self],
    ) -> Result<Self> {
        let stage = stage.into();
        let algorithm = algorithm.into();
        validate_name(&stage, "stage")?;
        validate_name(&algorithm, "algorithm")?;
        source.validate()?;

        let material = KeyMaterial {
            format_version: KEY_FORMAT_VERSION,
            stage: &stage,
            stage_version,
            algorithm: &algorithm,
            policy,
            source,
            dependencies: dependencies.iter().map(Self::as_str).collect(),
        };
        let canonical = serde_json::to_vec(&material)?;
        Ok(Self {
            digest: sha256(&canonical),
            stage,
        })
    }

    /// Returns the lowercase SHA-256 key used in cache directories and database rows
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.digest
    }

    /// Returns the stage label included in the key material
    #[must_use]
    pub fn stage(&self) -> &str {
        &self.stage
    }

    pub(super) fn validate(&self) -> Result<()> {
        if !is_sha256_digest(&self.digest) {
            return Err(CacheError::InvalidInput("stage key digest is invalid"));
        }
        validate_name(&self.stage, "stage")
    }
}

fn validate_name(name: &str, kind: &'static str) -> Result<()> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(CacheError::InvalidInput(match kind {
            "stage" => "stage name must be 1 to 128 printable bytes",
            _ => "algorithm name must be 1 to 128 printable bytes",
        }));
    }
    Ok(())
}
