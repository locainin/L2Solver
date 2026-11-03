use super::{
    ResultDirectory, ResultIdentity, ReusedResult,
    manifest::{DirectoryState, actionable_conflict},
};
use l2_workbench::job::{
    Counter, Job,
    cache::{SourceFingerprint, SourceIdentity},
};
use std::{error::Error, io, path::Path};

pub(super) fn reuse(
    directory: &ResultDirectory,
    identity: &ResultIdentity,
    current_input: Option<&Path>,
    strict: bool,
    job: &Job,
) -> Result<Option<ReusedResult>, Box<dyn Error>> {
    reuse_with_source_observer(directory, identity, current_input, strict, job, |_| {})
}

pub(super) fn reuse_with_source_observer(
    directory: &ResultDirectory,
    identity: &ResultIdentity,
    current_input: Option<&Path>,
    strict: bool,
    job: &Job,
    mut observe: impl FnMut(usize),
) -> Result<Option<ReusedResult>, Box<dyn Error>> {
    job.check_cancelled()?;
    let (prepared, manifest, receipt) = match &directory.state {
        DirectoryState::Missing => return Ok(None),
        DirectoryState::Legacy { .. } => {
            return Err(
                actionable_conflict("legacy extraction has no reusable result receipt").into(),
            );
        }
        DirectoryState::Owned {
            prepared,
            manifest,
            receipt,
        } => (prepared, manifest, receipt),
    };

    prepared.check_location()?;
    ensure_policy_matches(directory, identity, receipt)?;
    if receipt.source_identity_sha256.is_none() {
        return Err(actionable_conflict(
            "source identity is unavailable; use --refresh or a different output",
        )
        .into());
    }
    verify_source(
        &identity.source,
        receipt,
        current_input,
        strict,
        job,
        &mut observe,
    )?;

    verified_result(prepared, manifest, receipt, strict, job).map(Some)
}

pub(super) fn reuse_refinement(
    directory: &ResultDirectory,
    identity: &ResultIdentity,
    labels: &[String],
    strict: bool,
    job: &Job,
    strong_source: impl FnOnce() -> Result<SourceIdentity, Box<dyn Error>>,
) -> Result<Option<ReusedResult>, Box<dyn Error>> {
    job.check_cancelled()?;
    let (prepared, manifest, receipt) = match &directory.state {
        DirectoryState::Missing => return Ok(None),
        DirectoryState::Legacy { .. } => {
            return Err(
                actionable_conflict("legacy extraction has no reusable result receipt").into(),
            );
        }
        DirectoryState::Owned {
            prepared,
            manifest,
            receipt,
        } => (prepared, manifest, receipt),
    };
    prepared.check_location()?;
    ensure_policy_matches(directory, identity, receipt)?;
    if manifest.source_labels.len() != labels.len()
        || manifest
            .source_labels
            .iter()
            .zip(labels)
            .any(|(stored, current)| stored.as_deref() != Some(current.as_str()))
    {
        return Err(actionable_conflict(
            "refinement source labels differ from the existing result",
        )
        .into());
    }
    if receipt.source_identity_sha256.is_none()
        || matches!(identity.source, SourceIdentity::Unavailable)
    {
        return Err(actionable_conflict(
            "source identity is unavailable; use --refresh or a different output",
        )
        .into());
    }
    if !matches!(identity.source, SourceIdentity::Fast(_)) {
        return Err(invalid_source("refinement source hint is not a fast identity").into());
    }
    if strict || identity.source != receipt.identity.source {
        // Old strong receipts and changed metadata require the full ordered source digest
        let strong_identity = strong_source()?;
        verify_source(&strong_identity, receipt, None, true, job, &mut |_| {})?;
    }
    verified_result(prepared, manifest, receipt, strict, job).map(Some)
}

fn verified_result(
    prepared: &crate::publish::PreparedDirectoryReplacement,
    manifest: &super::manifest::OwnedManifest,
    receipt: &super::manifest::ResultReceipt,
    strict: bool,
    job: &Job,
) -> Result<ReusedResult, Box<dyn Error>> {
    let mut hasher = super::stamp::OutputHasher::new(job);
    for output in &receipt.output_files {
        output.verify(prepared, strict, &mut hasher)?;
    }
    prepared.check_location()?;
    Ok(ReusedResult {
        complete: manifest.complete,
        // Inspection already matched every declared artifact to one validated receipt
        artifact_count: manifest.artifacts.len(),
    })
}

fn ensure_policy_matches(
    directory: &ResultDirectory,
    identity: &ResultIdentity,
    receipt: &super::manifest::ResultReceipt,
) -> Result<(), Box<dyn Error>> {
    if identity.kind != directory.kind
        || identity.kind != receipt.identity.kind
        || identity.algorithm_version != receipt.identity.algorithm_version
        || identity.settings != receipt.identity.settings
    {
        return Err(actionable_conflict(
            "result policy or algorithm version differs from the existing output",
        )
        .into());
    }
    Ok(())
}

fn verify_source(
    source: &SourceIdentity,
    receipt: &super::manifest::ResultReceipt,
    current_input: Option<&Path>,
    strict: bool,
    job: &Job,
    observe: &mut impl FnMut(usize),
) -> Result<(), Box<dyn Error>> {
    if strict {
        let digest = if let Some(input) = current_input {
            let actual = hash_source(input, job, observe)?;
            source_digest(&actual)
                .map(str::to_owned)
                .ok_or_else(|| invalid_source("current input has no strong SHA-256 identity"))?
        } else {
            source_digest(source).map(str::to_owned).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "strict result reuse needs an input path or a strong source identity",
                )
            })?
        };
        if source_digest(source).is_some_and(|expected| expected != digest) {
            return Err(actionable_conflict(
                "source identity differs from the current input bytes",
            )
            .into());
        }
        if receipt.source_identity_sha256.as_deref() != Some(digest.as_str()) {
            return Err(actionable_conflict("source bytes differ from the existing result").into());
        }
        return Ok(());
    }

    if *source == receipt.identity.source {
        if let (SourceIdentity::Fast(expected), Some(input)) = (source, current_input) {
            let current = SourceFingerprint::fast_with_observer(input, |count| {
                observe_source_read(job, count, observe)
            })?;
            if &current != expected {
                return verify_source_by_digest(input, receipt, job, observe);
            }
        }
        return Ok(());
    }

    if let Some(digest) = source_digest(source)
        && receipt.source_identity_sha256.as_deref() == Some(digest)
    {
        return Ok(());
    }
    if let Some(input) = current_input {
        return verify_source_by_digest(input, receipt, job, observe);
    }
    Err(actionable_conflict("source identity differs from the existing result").into())
}

fn verify_source_by_digest(
    input: &Path,
    receipt: &super::manifest::ResultReceipt,
    job: &Job,
    observe: &mut impl FnMut(usize),
) -> Result<(), Box<dyn Error>> {
    let actual = hash_source(input, job, observe)?;
    let digest = source_digest(&actual)
        .ok_or_else(|| invalid_source("current input has no strong SHA-256 identity"))?;
    if receipt.source_identity_sha256.as_deref() == Some(digest) {
        Ok(())
    } else {
        Err(actionable_conflict("source bytes differ from the existing result").into())
    }
}

fn hash_source(
    input: &Path,
    job: &Job,
    observe: &mut impl FnMut(usize),
) -> Result<SourceIdentity, Box<dyn Error>> {
    Ok(SourceIdentity::sha256_file_with_check_and_observer(
        input,
        || job.check_cancelled().map_err(io::Error::other),
        |count| observe_source_read(job, count, observe),
    )?)
}

fn observe_source_read(job: &Job, count: usize, observe: &mut impl FnMut(usize)) -> io::Result<()> {
    // Count bytes that were actually read before honoring a new cancellation request
    job.increment(
        Counter::SourceReadBytes,
        u64::try_from(count).map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    observe(count);
    job.check_cancelled().map_err(io::Error::other)
}

fn source_digest(identity: &SourceIdentity) -> Option<&str> {
    match identity {
        SourceIdentity::Sha256(digest) => Some(digest),
        _ => None,
    }
}

fn invalid_source(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
