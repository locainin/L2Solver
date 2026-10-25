use super::{RecoveryInput, same_origin_context};
use crate::recovery::{RecoveryResource, RecoveryResult, RecoveryResultEvidenceContract};
use std::collections::HashSet;

fn input(origins: &[u64]) -> RecoveryInput {
    RecoveryInput {
        blob_id: "same blob".to_owned(),
        origin_node_ids: origins.to_vec(),
        origin_node_id_set: origins.iter().copied().collect::<HashSet<_>>(),
    }
}

#[test]
fn context_sets_match_exactly() {
    assert!(!same_origin_context(&[input(&[1])], &[input(&[2])]));
    assert!(same_origin_context(&[input(&[2, 1])], &[input(&[1, 2])]));
    assert!(!same_origin_context(
        &[input(&[1]), input(&[2])],
        &[input(&[2]), input(&[1])]
    ));
}

#[test]
fn result_evidence_contract_covers_every_result_variant() {
    use crate::evidence::EvidenceStatus;

    let cases = [
        (
            RecoveryResult::ObservedValidation { node_id: 11 },
            Some(RecoveryResultEvidenceContract {
                node_id: 11,
                relation: "recovery_result",
                status: EvidenceStatus::ConstraintSatisfied,
                requires_blob: false,
            }),
        ),
        (
            RecoveryResult::Derived {
                evidence_node_id: 12,
            },
            Some(RecoveryResultEvidenceContract {
                node_id: 12,
                relation: "derived_from",
                status: EvidenceStatus::Observed,
                requires_blob: true,
            }),
        ),
        (
            RecoveryResult::Hypothesis { node_id: 13 },
            Some(RecoveryResultEvidenceContract {
                node_id: 13,
                relation: "recovery_result",
                status: EvidenceStatus::Hypothesis,
                requires_blob: false,
            }),
        ),
        (
            RecoveryResult::Rejected { node_id: 14 },
            Some(RecoveryResultEvidenceContract {
                node_id: 14,
                relation: "recovery_result",
                status: EvidenceStatus::ConstraintFailed,
                requires_blob: false,
            }),
        ),
        (RecoveryResult::Unsupported, None),
        (RecoveryResult::Omitted, None),
        (
            RecoveryResult::ResourceExhausted {
                resource: RecoveryResource::CandidateCount,
                limit: 3,
                used: 3,
                requested: 1,
            },
            None,
        ),
    ];

    for (result, expected) in cases {
        assert_eq!(result.evidence_link_contract(), expected, "{result:?}");
    }
}
