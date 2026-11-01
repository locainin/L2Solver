//! Bounded extraction of stored and deflated ZIP members

mod admission;
mod model;
mod parse;
mod view;

pub use model::{
    MAX_ZIP_ARCHIVE_BYTES, MAX_ZIP_DEPTH, MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_EXPANDED_BYTES,
    MAX_ZIP_TOTAL_EXPANDED_BYTES, ZipArtifactEntry, ZipArtifactEntryMetadata, ZipArtifactError,
    ZipArtifactLimits, ZipArtifactOmission, ZipArtifactOmissionReason, ZipArtifactReport,
    ZipEntryDataFailure, ZipMemoryError, ZipReadError, ZipReaderBudget, ZipReaderLimits,
};
pub(in crate::artifact) use parse::has_zip_end_record_with_memory;
pub use parse::{
    has_zip_end_record, inspect_zip, inspect_zip_at_depth, inspect_zip_at_depth_with_memory,
    inspect_zip_at_depth_with_operation_budget, inspect_zip_from_reader_with_source_sha256,
    inspect_zip_from_reader_with_source_sha256_and_memory, inspect_zip_with_limits,
};
