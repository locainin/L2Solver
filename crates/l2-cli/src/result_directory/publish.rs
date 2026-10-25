use super::{ResultDirectory, ResultIdentity, ResultKind, manifest, stamp::OutputFileStamp};
use l2_workbench::job::{Job, Phase, PhaseOutcome, cache::SourceIdentity};
use std::{cell::Cell, error::Error, io, path::Path};

pub(super) fn publish<T>(
    directory: ResultDirectory,
    identity: &ResultIdentity,
    job: &Job,
    writer: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let super::ResultDirectory { path, kind, state } = directory;
    if kind != identity.kind {
        return Err(manifest::actionable_conflict(
            "result identity uses a different workflow than the inspected destination",
        )
        .into());
    }
    job.check_cancelled()?;

    let mut writer = Some(writer);
    let mut value = None;
    let publication_started = Cell::new(false);
    let write_stage = |staging: &Path| -> Result<(), Box<dyn Error>> {
        let write = writer
            .take()
            .ok_or_else(|| io::Error::other("result writer was already consumed"))?;
        let result = write(staging)?;

        // Record publication separately from analysis, beginning only after the writer succeeds
        job.check_cancelled()?;
        job.start(Phase::Publication, None)?;
        publication_started.set(true);
        let snapshot = job.snapshot()?;

        let parsed = manifest::parse_staged_manifest(staging, kind)?;
        validate_identity(identity, kind, &parsed.source_identity_sha256)?;
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
        let receipt = manifest::ResultReceipt {
            schema_version: 1,
            identity: identity.clone(),
            complete: parsed.complete,
            source_sha256s: parsed.source_sha256s.clone(),
            source_identity_sha256: parsed.source_identity_sha256.clone(),
            job: snapshot,
            output_files,
        };
        manifest::append_receipt(&staging.join("manifest.json"), &receipt)?;
        manifest::validate_staged_receipt(staging, kind)?;
        value = Some(result);
        Ok(())
    };
    let before_commit = || -> Result<(), Box<dyn Error>> {
        // This hook runs after syncing and immediately before the destination rename
        job.check_cancelled()?;
        Ok(())
    };

    let publication = match state {
        manifest::DirectoryState::Missing => {
            crate::publish::directory::create_directory_with_precommit(
                &path,
                write_stage,
                before_commit,
            )
        }
        manifest::DirectoryState::Legacy { prepared }
        | manifest::DirectoryState::Owned { prepared, .. } => {
            prepared.check_location()?;
            crate::publish::directory::replace_directory_with_precommit(
                prepared,
                write_stage,
                before_commit,
            )
        }
    };

    if let Err(error) = publication {
        if publication_started.get() {
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

fn validate_identity(
    identity: &ResultIdentity,
    kind: ResultKind,
    source_identity_sha256: &str,
) -> Result<(), Box<dyn Error>> {
    if identity.kind != kind {
        return Err(manifest::actionable_conflict(
            "result identity uses a different workflow than its manifest",
        )
        .into());
    }
    if let SourceIdentity::Sha256(digest) = &identity.source
        && digest != source_identity_sha256
    {
        return Err(manifest::actionable_conflict(
            "result identity source differs from the generating manifest",
        )
        .into());
    }
    Ok(())
}
