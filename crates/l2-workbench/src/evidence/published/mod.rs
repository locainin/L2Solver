//! Streaming publication records and their canonical evidence representation

mod canonical;
mod canonical_json;
mod details_budget;
mod format;
mod reader;
mod schema;
mod scratch;
mod writer;

pub use reader::decode_published_evidence;
pub use writer::write_published_case;

/// Bounds applied independently to the input stream, canonical output, and each normalized record
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedEvidenceLimits {
    maximum_stream_bytes: u64,
    maximum_record_bytes: usize,
}

impl PublishedEvidenceLimits {
    /// Set maximum stream bytes and the maximum length of one normalized JSONL record
    #[must_use]
    pub const fn new(maximum_stream_bytes: u64, maximum_record_bytes: usize) -> Self {
        Self {
            maximum_stream_bytes,
            maximum_record_bytes,
        }
    }
}

/// Case identity and byte counts from one normalized publication
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedCaseUsage {
    /// Identity derived from the canonical version-two record and selected ordinal
    pub case_id: String,
    /// Normalized JSONL length
    pub encoded_bytes: u64,
}
