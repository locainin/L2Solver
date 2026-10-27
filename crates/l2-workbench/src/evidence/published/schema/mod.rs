//! Shared per-receipt JSON shapes and streaming reconstruction

mod reader;
mod writer;

pub(super) use reader::DecodedSchemaJson;
pub(super) use writer::SchemaJson;

// Bound shape metadata independently of receipt size
const MAX_SCHEMAS: usize = 1024;
const MAX_SCHEMA_BYTES: usize = 512 * 1024;
const MAX_SCHEMA_FIELDS: usize = 4096;

// Encoded containers add two JSON levels plus the outer record envelope
const MAX_SCHEMA_SOURCE_DEPTH: usize = 56;

pub(super) fn within_depth(bytes: &[u8]) -> bool {
    super::canonical_json::nesting_depth(bytes, MAX_SCHEMA_SOURCE_DEPTH).is_some()
}
