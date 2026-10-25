use crate::evidence::{
    EvidenceError, MAX_BLOBS, MAX_EDGES, MAX_LIMITATIONS, MAX_NODES, MAX_TOTAL_DETAILS_BYTES,
    MAX_TOTAL_SOURCE_RANGES,
};

use super::RecoveryResource;

/// Return the recovery resource for a recoverable aggregate Case quota failure
///
/// Per-node limits, arithmetic overflow, and evidence integrity failures remain fatal
#[must_use]
pub fn classify_case_evidence_quota(error: &EvidenceError) -> Option<RecoveryResource> {
    match error {
        EvidenceError::QuotaExceeded { field, maximum } => match (*field, *maximum) {
            ("blobs", MAX_BLOBS) => Some(RecoveryResource::EvidenceBlobs),
            // usize::MAX denotes the unlimited blob budget, which cannot be exceeded
            ("blob bytes", maximum) if maximum > 0 && maximum < usize::MAX => {
                Some(RecoveryResource::EvidenceBlobBytes)
            }
            ("source ranges", MAX_TOTAL_SOURCE_RANGES) => {
                Some(RecoveryResource::EvidenceSourceRanges)
            }
            ("limitations", MAX_LIMITATIONS) => Some(RecoveryResource::EvidenceLimitations),
            ("nodes", MAX_NODES) => Some(RecoveryResource::EvidenceNodes),
            ("edges", MAX_EDGES) => Some(RecoveryResource::EvidenceEdges),
            _ => None,
        },
        EvidenceError::TotalDetailsTooLarge { length, maximum }
            if *length != usize::MAX
                && *length > *maximum
                && *maximum == MAX_TOTAL_DETAILS_BYTES =>
        {
            Some(RecoveryResource::EvidenceTotalDetailsBytes)
        }
        // Per-node limits, overflow sentinels, and all non-quota failures stay fatal
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/recovery/evidence_quota.rs"]
mod tests;
