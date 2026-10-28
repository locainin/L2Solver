use super::{ResultDirectory, ResultIdentity, ResultKind, manifest, stamp::OutputFileStamp};
use l2_workbench::job::{Job, Phase, PhaseOutcome, cache::SourceIdentity};
use l2_workbench::job::{
    RecoveryArtifactSample, RecoveryPublicationSample, RecoveryPublicationSourceBasis,
    RecoveryTransitionOutcome,
};
use std::{cell::Cell, error::Error, io, path::Path};

pub(super) fn publish<T>(
    directory: ResultDirectory,
    identity: &ResultIdentity,
    job: &Job,
    writer: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let super::ResultDirectory { path, kind, state } = directory;
    let capture = PublicationCapture {
        started: Cell::new(false),
        sample: Cell::new(crate::publication_transition::initial_sample(Some(
            &identity.source,
        ))),
    };
    if kind != identity.kind {
        crate::publication_transition::record(
            job,
            RecoveryTransitionOutcome::PublicationFailed,
            capture.sample.get(),
        );
        return Err(manifest::actionable_conflict(
            "result identity uses a different workflow than the inspected destination",
        )
        .into());
    }
    job.check_cancelled()?;

    let mut writer = Some(writer);
    let mut value = None;
    let write_stage = |staging: &Path| -> Result<(), Box<dyn Error>> {
        let write = writer
            .take()
            .ok_or_else(|| io::Error::other("result writer was already consumed"))?;
        value = Some(write_result_stage(
            staging, kind, identity, job, write, &capture,
        )?);
        Ok(())
    };
    let before_commit = || -> Result<(), Box<dyn Error>> {
        // This hook runs after syncing and immediately before the destination rename
        job.check_cancelled()?;
        Ok(())
    };

    let publication = match state {
        manifest::DirectoryState::Missing => {
            crate::publish::create_directory_with_precommit(&path, write_stage, before_commit)
        }
        manifest::DirectoryState::Legacy { prepared }
        | manifest::DirectoryState::Owned { prepared, .. } => {
            if let Err(error) = prepared.check_location() {
                crate::publication_transition::record(
                    job,
                    RecoveryTransitionOutcome::PublicationFailed,
                    capture.sample.get(),
                );
                return Err(Box::new(error));
            }
            crate::publish::replace_directory_with_precommit(&prepared, write_stage, before_commit)
        }
    };

    crate::publication_transition::record_result(job, &publication, capture.sample.get());
    if let Err(error) = publication {
        if capture.started.get() {
            let outcome = if job.is_cancelled() {
                PhaseOutcome::Cancelled
            } else {
                PhaseOutcome::Failed
            };
            job.finish(Phase::Publication, outcome)?;
        }
        return Err(Box::new(error));
    }
    job.finish(Phase::Publication, PhaseOutcome::Completed)?;
    value.ok_or_else(|| io::Error::other("result writer completed without a value").into())
}

struct PublicationCapture {
    started: Cell<bool>,
    sample: Cell<RecoveryPublicationSample>,
}

fn write_result_stage<T>(
    staging: &Path,
    kind: ResultKind,
    identity: &ResultIdentity,
    job: &Job,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
    capture: &PublicationCapture,
) -> Result<T, Box<dyn Error>> {
    let result = write(staging)?;
    // Mark publication only after the writer has produced all user-visible files
    job.check_cancelled()?;
    job.start(Phase::Publication, None)?;
    capture.started.set(true);
    let snapshot = job.snapshot()?;

    let parsed = manifest::parse_staged_manifest(staging, kind)?;
    validate_identity(identity, kind, parsed.source_identity_sha256.as_deref())?;
    let file_names = manifest::staged_output_files(staging, kind, &parsed)?;
    let output_files = file_names
        .iter()
        .map(|file| {
            let artifact = parsed
                .artifacts
                .iter()
                .find(|artifact| artifact.file == *file);
            OutputFileStamp::capture_path(
                staging,
                file,
                artifact.and_then(|artifact| artifact.sha256.as_deref()),
                artifact.is_some(),
            )
        })
        .collect::<io::Result<Vec<_>>>()?;
    let artifact = parsed.artifacts.first().and_then(|artifact| {
        output_files
            .iter()
            .find(|stamp| stamp.file == artifact.file)
            .and_then(|stamp| {
                stamp
                    .sha256
                    .as_deref()
                    .and_then(l2_workbench::parse_sha256_digest)
                    .map(|sha256| RecoveryArtifactSample {
                        sha256,
                        byte_length: stamp.byte_length,
                    })
            })
    });
    let source_set_sha256 = parsed
        .source_identity_sha256
        .as_deref()
        .and_then(l2_workbench::parse_sha256_digest);
    capture.sample.set(RecoveryPublicationSample {
        source_set_sha256,
        source_basis: if source_set_sha256.is_some() {
            RecoveryPublicationSourceBasis::StagedManifest
        } else {
            RecoveryPublicationSourceBasis::Unavailable
        },
        artifact,
        artifact_count: Some(
            u64::try_from(parsed.artifacts.len())
                .map_err(|_| io::Error::other("artifact count overflowed"))?,
        ),
    });
    let receipt = manifest::ResultReceipt {
        schema_version: if parsed.source_identity_sha256.is_some() {
            1
        } else {
            2
        },
        identity: identity.clone(),
        complete: parsed.complete,
        source_sha256s: parsed.source_sha256s,
        source_identity_sha256: parsed.source_identity_sha256,
        job: snapshot,
        output_files,
    };
    manifest::append_receipt(&staging.join("manifest.json"), &receipt)?;
    manifest::validate_staged_receipt(staging, kind)?;
    Ok(result)
}

fn validate_identity(
    identity: &ResultIdentity,
    kind: ResultKind,
    source_identity_sha256: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    if identity.kind != kind {
        return Err(manifest::actionable_conflict(
            "result identity uses a different workflow than its manifest",
        )
        .into());
    }
    match (&identity.source, source_identity_sha256) {
        (SourceIdentity::Unavailable, None) | (SourceIdentity::Fast(_), Some(_)) => Ok(()),
        (SourceIdentity::Sha256(digest), Some(expected)) if digest == expected => Ok(()),
        _ => Err(manifest::actionable_conflict(
            "result identity source differs from the generating manifest",
        )
        .into()),
    }
}
