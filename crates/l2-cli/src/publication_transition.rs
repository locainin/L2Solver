//! Report atomic publication outcomes without changing their operational result

use crate::{arguments::ProgressMode, publish::DirectoryPublishError};
use l2_workbench::job::{
    Job, RecoveryPublicationSample, RecoveryPublicationSourceBasis, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
    cache::SourceIdentity,
};
use std::{
    io::{self, Write},
    path::Path,
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

pub fn retained_notice(path: &Path, progress: ProgressMode) {
    // Publication has committed, so a closed diagnostic stream cannot undo its outcome
    let mut diagnostic = io::stderr().lock();
    if progress == ProgressMode::Json {
        let mut event = serde_json::Map::new();
        event.insert("type".into(), "retained_output".into());
        event.insert("path".into(), path.display().to_string().into());
        event.insert("disk_retention".into(), "until_explicit_removal".into());
        #[cfg(unix)]
        if path.to_str().is_none() {
            use std::os::unix::ffi::OsStrExt;
            event.insert(
                "path_bytes".into(),
                serde_json::json!(path.as_os_str().as_bytes()),
            );
        }
        let _ = writeln!(diagnostic, "{}", serde_json::Value::Object(event));
    } else {
        #[expect(
            clippy::unnecessary_debug_formatting,
            reason = "Debug preserves non-Unicode path bytes"
        )]
        let display = if path.to_str().is_some() {
            path.display().to_string().escape_debug().to_string()
        } else {
            format!("{:?}", path.as_os_str())
        };
        let _ = writeln!(
            diagnostic,
            "Previous output retained at {display}\nRetained output occupies disk space until explicitly removed"
        );
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

pub fn record(job: &Job, outcome: RecoveryTransitionOutcome, sample: RecoveryPublicationSample) {
    // A diagnostic failure cannot change whether the atomic commit happened
    let _ = job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Publication,
        outcome,
        sample: Some(RecoveryTransitionSample::Publication(sample)),
    });
}
