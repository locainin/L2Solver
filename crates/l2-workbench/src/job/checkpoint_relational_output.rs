//! Opt-in compact checkpoint encoding for one relational output
//!
//! Admit the complete encoded document, parser scratch, and decoded state before deserializing.
//! The caller must separately verify session membership, source ranges, hashes, and work.
//! Ordinary `RelationalAppliedOutput` serialization is unchanged.

use crate::protocol::{RelationalAppliedOutput, RelationalOutputMapping, RelationalSessionId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Remote fields are checked against the public output type at compile time
#[derive(Serialize, Deserialize)]
#[serde(remote = "RelationalAppliedOutput", deny_unknown_fields)]
struct SavedOutput {
    session: RelationalSessionId,
    session_order: u64,
    seed_sample: u64,
    payload_mappings: Vec<RelationalOutputMapping>,
    #[serde(with = "crate::serialization::base64")]
    bytes: Vec<u8>,
    parser_validation_deferred: bool,
    work_bytes: usize,
}

/// Encode one relational output with canonical Base64 bytes
///
/// # Errors
/// Returns an error if the serializer cannot write the output
pub fn serialize<S>(output: &RelationalAppliedOutput, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    SavedOutput::serialize(output, serializer)
}

/// Decode one compact relational output after caller-side memory admission
///
/// # Errors
/// Returns an error for malformed output, noncanonical bytes, or allocation failure
pub fn deserialize<'de, D>(deserializer: D) -> Result<RelationalAppliedOutput, D::Error>
where
    D: Deserializer<'de>,
{
    SavedOutput::deserialize(deserializer)
}
