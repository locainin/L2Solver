//! File-signature observations at format-defined offsets

mod catalogue;
mod evidence;
mod model;
mod scan;

pub use evidence::signature_evidence_matches_start;
pub use model::{
    FileSignatureCatalogue, FileSignatureEvidence, FileSignatureMatch, FileSignatureMatchKind,
    FileSignatureReport,
};
pub use scan::scan_file_signatures;
pub(in crate::artifact) use scan::{count_file_signature_matches, matches_zip_signature};

pub use catalogue::{ELF_MAGIC, MZ_MAGIC};

/// Evidence wording shared by every graph edge from a byte object to a signature match
pub const FILE_SIGNATURE_RELATION_REASON: &str = "The retained bytes satisfy a supported exact or explicitly masked signature pattern at its declared object-relative offset";
