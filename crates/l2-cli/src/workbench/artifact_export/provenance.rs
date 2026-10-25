//! Describe selected artifact validation and reconstruction evidence

use super::validation::{StructuralValidation, StructuralValidationStatus};
use l2_workbench::evidence::Node;
use serde::{Serialize, Serializer};

/// Source metadata retained alongside one exported object
pub struct ArtifactProvenance {
    pub id: u64,
    pub kind: String,
    pub archive_path: Option<String>,
    pub completion_basis: Option<String>,
    pub reconstruction_status: ReconstructionStatus,
    pub structural_validation: StructuralValidation,
    pub extension_evidence_node: Option<u64>,
}

impl ArtifactProvenance {
    pub const fn validated_as(&self) -> Option<&'static str> {
        match &self.structural_validation {
            StructuralValidation::Validated { format, .. } => Some(format),
            StructuralValidation::NotChecked
            | StructuralValidation::Rejected { .. }
            | StructuralValidation::BoundaryUnproven { .. }
            | StructuralValidation::Unsupported { .. }
            | StructuralValidation::Omitted { .. }
            | StructuralValidation::Unknown { .. } => None,
        }
    }

    pub const fn validation_evidence_node(&self) -> Option<u64> {
        match &self.structural_validation {
            StructuralValidation::Validated { evidence_node, .. } => *evidence_node,
            StructuralValidation::NotChecked
            | StructuralValidation::Rejected { .. }
            | StructuralValidation::BoundaryUnproven { .. }
            | StructuralValidation::Unsupported { .. }
            | StructuralValidation::Omitted { .. }
            | StructuralValidation::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionStatus {
    Complete,
    Incomplete,
    Unknown,
}

impl ReconstructionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Serialize)]
struct ArtifactProvenanceRecord<'a> {
    id: u64,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_basis: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validated_as: Option<&'a str>,
    structural_validation_status: StructuralValidationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    structural_validation_format: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    structural_validation_evidence_node: Option<u64>,
    reconstruction_status: ReconstructionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_evidence_node: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extension_evidence_node: Option<u64>,
}

impl Serialize for ArtifactProvenance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let validation = &self.structural_validation;
        ArtifactProvenanceRecord {
            id: self.id,
            kind: &self.kind,
            archive_path: self.archive_path.as_deref(),
            completion_basis: self.completion_basis.as_deref(),
            validated_as: self.validated_as(),
            structural_validation_status: validation.status(),
            structural_validation_format: validation.format(),
            structural_validation_evidence_node: (validation.status()
                != StructuralValidationStatus::Validated)
                .then_some(validation.evidence_node())
                .flatten(),
            reconstruction_status: self.reconstruction_status,
            validation_evidence_node: (validation.status()
                == StructuralValidationStatus::Validated)
                .then_some(self.validation_evidence_node())
                .flatten(),
            extension_evidence_node: self.extension_evidence_node,
        }
        .serialize(serializer)
    }
}

pub(super) fn reconstruction_status(node: &Node) -> ReconstructionStatus {
    let completion = ["group_complete", "assembly_complete"]
        .map(|field| node.details.get(field).and_then(serde_json::Value::as_bool));
    if completion.contains(&Some(false)) {
        ReconstructionStatus::Incomplete
    } else if completion == [Some(true), Some(true)] {
        ReconstructionStatus::Complete
    } else {
        ReconstructionStatus::Unknown
    }
}
