//! Report atomic publication outcomes without changing their operational result

use crate::publish::DirectoryPublishError;
use l2_workbench::job::{
    Job, RecoveryPublicationSample, RecoveryPublicationSourceBasis, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
    cache::SourceIdentity,
};

pub fn initial_sample(source: Option<&SourceIdentity>) -> RecoveryPublicationSample {
    let source_set_sha256 = match source {
        Some(SourceIdentity::Sha256(digest)) => l2_workbench::parse_sha256_digest(digest),
        _ => None,
    };
    RecoveryPublicationSample {
        source_set_sha256,
        source_basis: if source_set_sha256.is_some() {
            RecoveryPublicationSourceBasis::RequestedIdentity
        } else {
            RecoveryPublicationSourceBasis::Unavailable
        },
        artifact: None,
        artifact_count: None,
    }
}

pub fn record_result<T>(
    job: &Job,
    result: &Result<T, DirectoryPublishError>,
    sample: RecoveryPublicationSample,
) {
    let outcome = match result {
        Ok(_) => RecoveryTransitionOutcome::Published,
        Err(DirectoryPublishError::BeforePublication(_)) => {
            RecoveryTransitionOutcome::PublicationFailed
        }
        Err(DirectoryPublishError::PublishedDurabilityUncertain(_)) => {
            RecoveryTransitionOutcome::PublishedDurabilityUncertain
        }
        Err(DirectoryPublishError::PublishedReplacementUncertain { .. }) => {
            RecoveryTransitionOutcome::PublishedReplacementUncertain
        }
    };
    record(job, outcome, sample);
}

pub fn record(
    job: &Job,
    outcome: RecoveryTransitionOutcome,
    sample: RecoveryPublicationSample,
) {
    // A diagnostic failure cannot change whether the atomic commit happened
    let _ = job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome,
        sample: Some(RecoveryTransitionSample::Publication(sample)),
    });
}
