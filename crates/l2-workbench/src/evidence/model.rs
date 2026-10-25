use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A byte blob stored once under its canonical content digest
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    /// `sha256:` followed by 64 lowercase hexadecimal digits
    pub id: String,
    /// Exact retained source bytes
    #[serde(
        rename = "bytes_base64",
        serialize_with = "super::bounded::serialize_blob_bytes",
        deserialize_with = "super::bounded::deserialize_blob_bytes"
    )]
    pub bytes: Vec<u8>,
}

/// One source identity; labels preserve alternate names for identical bytes
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Content-derived source identity
    pub id: String,
    /// First bounded basename associated with this source
    pub label: String,
    /// Other bounded basenames associated with the same content hash
    #[serde(deserialize_with = "deserialize_source_aliases")]
    pub aliases: Vec<String>,
    /// Caller-supplied source category
    pub kind: String,
    /// Original source length, even if no blob is retained
    pub length: u64,
    /// Optional id of the complete retained source bytes
    pub blob: Option<String>,
}

/// A typed observation or derivation result linked to exact evidence ranges
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// One-based canonical node identifier
    pub id: u64,
    /// Caller-supplied observation kind
    pub kind: String,
    /// Optional retained source blob containing the observation
    pub blob: Option<String>,
    /// Exact ranges in source files that support this node
    #[serde(deserialize_with = "deserialize_node_ranges")]
    pub ranges: Vec<SourceRange>,
    /// Bounded structured details describing the observation
    pub details: Value,
}

/// An absolute byte range in a source file or capture
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRange {
    /// Content-derived source identity
    pub source: String,
    /// Optional one-based packet index within a capture source
    pub packet: Option<u64>,
    /// Zero-based absolute offset in the source file
    pub offset: u64,
    /// Number of source bytes covered by this range
    pub length: u64,
}

/// Output position paired with a literal interval in a source file
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteMapping {
    pub offset: usize,
    pub range: SourceRange,
}

/// The evidence relation recorded between two graph nodes
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    /// Identifier of the first node
    pub from: u64,
    /// Identifier of the second node
    pub to: u64,
    /// Bounded relation name, such as `same_value` or `derived_from`
    pub relation: String,
    /// How the relation is supported by retained observations
    pub status: EvidenceStatus,
    /// Short factual explanation for the relation status
    pub reason: String,
}

/// Explicit evidential state for an observation or interpretation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// The relation was directly observed in the retained input
    Observed,
    /// The relation is a candidate explanation that remains unverified
    Hypothesis,
    /// All stated constraints were satisfied by the tested samples
    ConstraintSatisfied,
    /// At least one tested sample contradicted a stated constraint
    ConstraintFailed,
    /// Available evidence cannot resolve the relation
    Unresolved,
}

fn deserialize_source_aliases<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    super::bounded::deserialize_vec::<D, String, { super::case::MAX_SOURCE_ALIASES }>(deserializer)
}

fn deserialize_node_ranges<'de, D>(deserializer: D) -> Result<Vec<SourceRange>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    super::bounded::deserialize_vec::<D, SourceRange, { super::case::MAX_NODE_RANGES }>(
        deserializer,
    )
}
