use crate::evidence::{
    EvidenceError, MAX_BLOBS, MAX_EDGES, MAX_LIMITATIONS, MAX_NODE_RANGES, MAX_NODES,
    MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES,
};
use crate::recovery::{RecoveryResource, classify_case_evidence_quota};

fn quota(field: &'static str, maximum: usize) -> EvidenceError {
    EvidenceError::QuotaExceeded { field, maximum }
}

#[test]
fn aggregate_case_quota_errors_map_to_canonical_resources() {
    let mapped = [
        (quota("blobs", MAX_BLOBS), RecoveryResource::EvidenceBlobs),
        (quota("blob bytes", 24), RecoveryResource::EvidenceBlobBytes),
        (
            EvidenceError::TotalDetailsTooLarge {
                length: MAX_TOTAL_DETAILS_BYTES + 1,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            },
            RecoveryResource::EvidenceTotalDetailsBytes,
        ),
        (
            quota("source ranges", MAX_TOTAL_SOURCE_RANGES),
            RecoveryResource::EvidenceSourceRanges,
        ),
        (
            quota("limitations", MAX_LIMITATIONS),
            RecoveryResource::EvidenceLimitations,
        ),
        (quota("nodes", MAX_NODES), RecoveryResource::EvidenceNodes),
        (quota("edges", MAX_EDGES), RecoveryResource::EvidenceEdges),
    ];

    for (error, expected) in mapped {
        assert_eq!(classify_case_evidence_quota(&error), Some(expected));
    }
}

#[test]
fn per_node_limits_and_overflow_sentinels_remain_fatal() {
    let fatal = [
        quota("node source ranges", MAX_NODE_RANGES),
        quota("blob bytes", usize::MAX),
        EvidenceError::ArithmeticOverflow {
            field: "blob bytes",
        },
        EvidenceError::ArithmeticOverflow {
            field: "source ranges",
        },
        EvidenceError::ArithmeticOverflow {
            field: "limitations",
        },
        EvidenceError::ArithmeticOverflow { field: "nodes" },
        EvidenceError::InconsistentResourceCount {
            field: "blob bytes",
        },
        EvidenceError::InconsistentResourceCount {
            field: "source ranges",
        },
        EvidenceError::NodeDetailsTooLarge {
            length: 4_097,
            maximum: 4_096,
        },
        EvidenceError::TotalDetailsTooLarge {
            length: usize::MAX,
            maximum: MAX_TOTAL_DETAILS_BYTES,
        },
    ];

    for error in fatal {
        assert_eq!(classify_case_evidence_quota(&error), None, "{error:?}");
    }
}

#[test]
fn only_canonical_case_quota_fields_and_limits_are_recoverable() {
    let fatal = [
        quota("source aliases", 256),
        quota("unknown", 10),
        quota("blobs", MAX_BLOBS - 1),
        quota("blob bytes", 0),
        quota("source ranges", MAX_TOTAL_SOURCE_RANGES - 1),
        quota("limitations", MAX_LIMITATIONS - 1),
        quota("nodes", MAX_NODES - 1),
        quota("edges", MAX_EDGES - 1),
        EvidenceError::TotalDetailsTooLarge {
            length: 5,
            maximum: 5,
        },
        EvidenceError::InvalidSourceRange,
        EvidenceError::InvalidJson,
    ];

    for error in fatal {
        assert_eq!(classify_case_evidence_quota(&error), None, "{error:?}");
    }
}

#[test]
fn integrity_reference_schema_text_allocation_and_io_errors_remain_fatal() {
    let fatal = [
        EvidenceError::UnsupportedSchema {
            found: 2,
            expected: 1,
        },
        EvidenceError::CaseTooLarge {
            length: 11,
            maximum: 10,
        },
        EvidenceError::WriteFailed,
        EvidenceError::InvalidDigest,
        EvidenceError::HashMismatch,
        EvidenceError::HashCollision,
        EvidenceError::InvalidText { field: "node kind" },
        EvidenceError::SourceMetadataConflict,
        EvidenceError::MissingReference { kind: "blob" },
        EvidenceError::InvalidNodeId,
        EvidenceError::OrphanBlob,
        EvidenceError::InvalidResourceLimit {
            field: "blob bytes",
        },
        EvidenceError::AllocationFailed {
            field: "blob bytes",
        },
    ];

    for error in fatal {
        assert_eq!(classify_case_evidence_quota(&error), None, "{error:?}");
    }
}
