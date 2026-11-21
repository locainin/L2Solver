use super::{
    ResultDirectory, ResultIdentity, ResultKind, bounded, manifest,
    stamp::{OutputFileStamp, OutputHasher},
};
use l2_workbench::job::{Job, JobError, JobSnapshot, Phase, PhaseOutcome, cache::SourceIdentity};
use l2_workbench::job::{
    RecoveryArtifactSample, RecoveryPublicationSample, RecoveryPublicationSourceBasis,
    RecoveryTransitionOutcome,
};
use std::{
    cell::Cell,
    collections::BTreeMap,
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
};

pub(super) fn publish<T>(
    directory: ResultDirectory,
    identity: &ResultIdentity,
    job: &Job,
    writer: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<(T, Option<PathBuf>), Box<dyn Error>> {
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
                .map(|()| None)
        }
        manifest::DirectoryState::Legacy {
            prepared,
            manifest_identity,
        }
        | manifest::DirectoryState::Owned {
            prepared,
            manifest_identity,
            ..
        } => {
            if let Err(error) = prepared.check_location() {
                crate::publication_transition::record(
                    job,
                    RecoveryTransitionOutcome::PublicationFailed,
                    capture.sample.get(),
                );
                return Err(Box::new(error));
            }
            crate::publish::replace_directory_with_precommit(&prepared, write_stage, || {
                before_commit()?;
                // Recheck the ownership evidence after staging and before replacement
                manifest::verify_named_manifest(&prepared, manifest_identity)
            })
            .map(|((), retained)| Some(retained))
        }
    };

    crate::publication_transition::record_result(job, &publication, capture.sample.get());
    let retained = match publication {
        Ok(retained) => retained,
        Err(error) => return Err(publication_failure(job, capture.started.get(), error)),
    };
    if let Err(progress) = job.finish(Phase::Publication, PhaseOutcome::Completed) {
        return Err(Box::new(PublicationProgressError {
            primary: None,
            progress,
            retained,
        }));
    }
    Ok((
        value.ok_or_else(|| io::Error::other("result writer completed without a value"))?,
        retained,
    ))
}

fn publication_failure(
    job: &Job,
    started: bool,
    error: crate::publish::DirectoryPublishError,
) -> Box<dyn Error> {
    if started {
        let outcome = if job.is_cancelled() {
            PhaseOutcome::Cancelled
        } else {
            PhaseOutcome::Failed
        };
        if let Err(progress) = job.finish(Phase::Publication, outcome) {
            return Box::new(PublicationProgressError {
                primary: Some(Box::new(error)),
                progress,
                retained: None,
            });
        }
    }
    Box::new(error)
}

#[derive(Debug)]
pub struct PublicationProgressError {
    primary: Option<Box<dyn Error>>,
    progress: JobError,
    retained: Option<PathBuf>,
}

impl fmt::Display for PublicationProgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(primary) = &self.primary {
            write!(
                formatter,
                "{primary}; could not finish publication progress: {}",
                self.progress
            )
        } else if let Some(path) = &self.retained {
            #[expect(
                clippy::unnecessary_debug_formatting,
                reason = "Debug preserves non-Unicode path bytes"
            )]
            let path = if path.to_str().is_some() {
                path.display().to_string().escape_debug().to_string()
            } else {
                format!("{:?}", path.as_os_str())
            };
            write!(
                formatter,
                "output was published; previous output retained at {path}; could not finish publication progress: {}",
                self.progress
            )
        } else {
            write!(
                formatter,
                "output was published; could not finish publication progress: {}",
                self.progress
            )
        }
    }
}

impl Error for PublicationProgressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_deref().unwrap_or(&self.progress))
    }
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
    let parsed = manifest::parse_staged_manifest(staging, kind, job)?;
    validate_identity(identity, kind, parsed.source_identity_sha256.as_deref())?;
    let file_names = manifest::staged_output_files(staging, kind, &parsed)?;
    let output_files = {
        let mut hasher = OutputHasher::new(job);
        // Index the validated names once instead of scanning every artifact for each file
        let artifact_digests = parsed
            .artifacts
            .iter()
            .map(|artifact| (artifact.file.as_str(), artifact.sha256.as_deref()))
            .collect::<BTreeMap<_, _>>();
        file_names
            .iter()
            .map(|file| {
                OutputFileStamp::capture_path(
                    staging,
                    file,
                    artifact_digests.get(file.as_str()).copied().flatten(),
                    &mut hasher,
                )
            })
            .collect::<io::Result<Vec<_>>>()?
    };
    // Capture the completed digest reads after releasing their scratch buffer
    let snapshot = result_snapshot(job)?;
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
    manifest::append_receipt(&staging.join("manifest.json"), &receipt, job)?;
    manifest::validate_staged_receipt(staging, kind, job)?;
    Ok(result)
}

fn result_snapshot(job: &Job) -> Result<JobSnapshot, Box<dyn Error>> {
    let snapshot = job.snapshot()?;
    if bounded::job_snapshot_fits(&snapshot, job.memory_budget())? {
        return Ok(snapshot);
    }
    drop(snapshot);
    for retain_cohorts in [true, false] {
        // Each projection records details omitted solely from this receipt
        let snapshot = job.result_snapshot(retain_cohorts)?;
        if bounded::job_snapshot_fits(&snapshot, job.memory_budget())? {
            return Ok(snapshot);
        }
    }
    Err(io::Error::other("job snapshot exceeds the result receipt limits").into())
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
