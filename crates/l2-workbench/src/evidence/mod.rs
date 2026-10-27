//! Bounded provenance graph for retained source bytes and explicit observations

mod bounded;
mod case;
mod error;
mod model;
mod preflight;
mod receipt_verification;
mod scan;

// Receipt generation and validation use the same reserved kind and selection rule
pub(crate) const FLOW_SELECTION_KIND: &str = "index_flow_selection";
pub(crate) const FLOW_SELECTION_PREDICATE: &str =
    "source_interface_vlan_bidirectional_unfragmented_transport_tuple";

pub use case::{
    Case, CaseIdentity, CaseResourceLimits, CaseResourceUsage, CaseSnapshotLimits,
    CaseSnapshotUsage, CheckedByteMappingCursor, MAX_BLOB_TOTAL_BYTES, MAX_BLOBS,
    MAX_CASE_JSON_BYTES, MAX_EDGES, MAX_LIMITATION_BYTES, MAX_LIMITATIONS, MAX_NODE_DETAILS_BYTES,
    MAX_NODE_KIND_BYTES, MAX_NODE_RANGES, MAX_NODES, MAX_REASON_BYTES, MAX_RELATION_BYTES,
    MAX_SOURCE_ALIASES, MAX_SOURCE_LABEL_BYTES, MAX_SOURCES, MAX_TOTAL_DETAILS_BYTES,
    MAX_TOTAL_SOURCE_RANGES, SCHEMA_VERSION, clip_byte_mappings,
};
pub use error::EvidenceError;
pub use model::{Blob, ByteMapping, Edge, EvidenceStatus, Node, Source, SourceRange};
pub use receipt_verification::{
    IndexFlowSelectionVerification, ReceiptVerificationError, ReceiptVerificationLimits,
    verify_index_flow_selection,
};
pub use scan::{
    DEFAULT_IMPORT_SCAN_BYTES, ImportScanMode, ImportScanOptions, ImportScanReport,
    MAX_ASCII_PREVIEW_BYTES, MAX_IMPORT_FINDINGS, MIN_ASCII_STRING_BYTES,
};
