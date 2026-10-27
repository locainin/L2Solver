//! Select and atomically publish retained byte artifacts

mod archives;
mod naming;
mod provenance;
mod publish;
mod selection;
mod signatures;
mod validation;

pub use provenance::ArtifactProvenance;
pub use provenance::ReconstructionStatus;
pub use publish::{artifact_node_count, publish_artifact_directory, write_artifacts_into};
pub use selection::{AnalyzerValidationReceipt, select_artifacts_with_analyzer_receipts};
pub use selection::{SelectedArtifact, select_artifacts};
pub use validation::StructuralValidation;
#[cfg(test)]
pub use validation::StructuralValidationStatus;
pub use validation::validated_extension;

#[cfg(test)]
use super::expand::encode_hex;
#[cfg(test)]
use archives::add_validated_archive_members;
#[cfg(test)]
use publish::validate_flat_file_name;
#[cfg(test)]
use selection::select_artifacts_with_cache;
#[cfg(test)]
use validation::SelectionWorkCache;

#[cfg(test)]
#[path = "../../../tests/workbench/artifact_export.rs"]
mod tests;
