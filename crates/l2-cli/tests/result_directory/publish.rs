//! Explicit replacement preserves ownership checks even when the source changes

use super::{Fixture, TestResult};
use crate::result_directory::ResultKind;
use l2_workbench::job::{Job, cache::SourceIdentity};
use std::{fs, io};

#[cfg(target_os = "linux")]
fn existing_result(fixture: &Fixture, receipt: bool) -> TestResult {
    if receipt {
        fixture.publish("complete", b"existing")?;
    } else {
        fs::create_dir(&fixture.output)?;
        fixture.write_output(&fixture.output, "complete", b"existing")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_manifest_cannot_authorize_refresh() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    for receipt in [false, true] {
        for mode in [0o664, 0o646] {
            let fixture = Fixture::new()?;
            existing_result(&fixture, receipt)?;
            let manifest = fixture.output.join("manifest.json");
            let contents = fs::read(&manifest)?;
            fs::set_permissions(&manifest, fs::Permissions::from_mode(mode))?;

            let error = super::inspect(&fixture.output, ResultKind::Extract)
                .err()
                .ok_or("unsafe manifest authorized refresh")?;
            assert_eq!(
                error.downcast_ref::<io::Error>().map(io::Error::kind),
                Some(io::ErrorKind::PermissionDenied),
                "receipt={receipt}, mode={mode:o}: {error}"
            );
            assert_eq!(fs::read(manifest)?, contents);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_manifest_is_rejected_before_parsing() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new()?;
    fs::create_dir(&fixture.output)?;
    let manifest = fixture.output.join("manifest.json");
    fs::write(&manifest, b"invalid json")?;
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o664))?;

    let error = super::inspect(&fixture.output, ResultKind::Extract)
        .err()
        .ok_or("unsafe manifest was accepted")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied),
        "{error}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn refresh_rechecks_manifest_after_staging() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    for receipt in [false, true] {
        let fixture = Fixture::new()?;
        existing_result(&fixture, receipt)?;
        let manifest = fixture.output.join("manifest.json");
        let contents = fs::read(&manifest)?;
        let destination = super::inspect(&fixture.output, ResultKind::Extract)?;

        let error = destination
            .publish(&fixture.identity, &Job::new("refresh"), |staging| {
                // Model a permission change while the replacement is being prepared
                fs::set_permissions(&manifest, fs::Permissions::from_mode(0o664))?;
                fixture.write_output(staging, "complete", b"replacement")
            })
            .err()
            .ok_or("refresh accepted an unsafe manifest")?;
        assert!(error.to_string().contains("manifest.json"), "{error}");
        assert_eq!(fs::read(manifest)?, contents);
        assert_eq!(fs::read(fixture.output.join("artifact.bin"))?, b"existing");
    }
    Ok(())
}

#[test]
fn explicit_refresh_atomically_replaces_an_owned_result_from_another_source() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    fs::write(&fixture.input, b"different-capture-input")?;
    fixture.identity.source = SourceIdentity::sha256_file(&fixture.input)?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;

    // Ordinary reuse cannot reinterpret the old collection as a result of the new input
    assert!(
        destination
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                false,
                &Job::new("reuse")
            )
            .is_err()
    );
    destination.publish(
        &fixture.identity,
        &Job::new("explicit refresh"),
        |staging| fixture.write_output(staging, "complete", b"replacement-artifact"),
    )?;

    let replacement = super::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        replacement
            .reuse(
                &fixture.identity,
                Some(&fixture.input),
                true,
                &Job::new("reuse")
            )?
            .is_some_and(|result| result.complete)
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"replacement-artifact"
    );
    Ok(())
}

#[test]
fn failed_refresh_from_another_source_preserves_the_previous_collection() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    let previous_identity = fixture.identity.clone();
    let previous_manifest = fs::read(fixture.output.join("manifest.json"))?;
    fs::write(&fixture.input, b"different-capture-input")?;
    fixture.identity.source = SourceIdentity::sha256_file(&fixture.input)?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;

    let result = destination.publish(
        &fixture.identity,
        &Job::new("explicit refresh"),
        |staging| {
            fixture.write_output(staging, "partial", b"unfinished-replacement")?;
            Err::<(), _>(io::Error::other("replacement computation failed").into())
        },
    );

    assert!(result.is_err());
    assert_eq!(
        fs::read(fixture.output.join("manifest.json"))?,
        previous_manifest
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"previous-artifact"
    );
    // The output still has its original identity even though the input path now changed
    let previous = super::inspect(&fixture.output, ResultKind::Extract)?;
    assert!(
        previous
            .reuse(&previous_identity, None, true, &Job::new("reuse"))?
            .is_some_and(|result| result.complete)
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn published_progress_error_names_backup() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("refresh");
    let paused_job = job.clone();
    crate::publish::test_hooks::set_before_directory_exchange(move || {
        paused_job
            .finish(
                l2_workbench::job::Phase::Publication,
                l2_workbench::job::PhaseOutcome::Completed,
            )
            .map_err(io::Error::other)
    });

    let error = destination
        .publish(&fixture.identity, &job, |staging| {
            fixture.write_output(staging, "complete", b"replacement-artifact")
        })
        .err()
        .ok_or("finishing an already-finished phase must fail")?;
    assert!(
        error.to_string().contains("previous output retained at"),
        "{error}"
    );
    let retained = fs::read_dir(fixture.root.path())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".l2solver-"))
        })
        .ok_or("retained output was not found")?;
    assert!(error.to_string().contains(&retained.display().to_string()));
    assert_eq!(
        fs::read(retained.join("artifact.bin"))?,
        b"previous-artifact"
    );
    assert_eq!(
        crate::memory_error::find_map(error.as_ref(), |cause| cause
            .downcast_ref::<l2_workbench::job::JobError>()
            .copied()),
        Some(l2_workbench::job::JobError::PhaseNotInProgress(
            l2_workbench::job::Phase::Publication
        ))
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn progress_error_names_non_utf8_backup() -> TestResult {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let mut fixture = Fixture::new()?;
    let parent = fixture.root.path().join(OsStr::from_bytes(b"case-\xff"));
    fs::create_dir(&parent)?;
    fixture.output = parent.join("result");
    fixture.publish("complete", b"previous-artifact")?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("refresh");
    let paused_job = job.clone();
    crate::publish::test_hooks::set_before_directory_exchange(move || {
        paused_job
            .finish(
                l2_workbench::job::Phase::Publication,
                l2_workbench::job::PhaseOutcome::Completed,
            )
            .map_err(io::Error::other)
    });
    let error = destination
        .publish(&fixture.identity, &job, |staging| {
            fixture.write_output(staging, "complete", b"replacement-artifact")
        })
        .err()
        .ok_or("progress failure was not reported")?;
    assert!(error.to_string().contains(r"case-\xFF/"), "{error}");
    let retained = fs::read_dir(&parent)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .find(|path| path != &fixture.output)
        .ok_or("retained directory is missing")?;
    assert_eq!(
        fs::read(retained.join("artifact.bin"))?,
        b"previous-artifact"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn failed_publication_keeps_primary_error() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("refresh");
    let paused_job = job.clone();
    crate::publish::test_hooks::set_before_directory_exchange(move || {
        paused_job
            .finish(
                l2_workbench::job::Phase::Publication,
                l2_workbench::job::PhaseOutcome::Failed,
            )
            .map_err(io::Error::other)?;
        Err(io::Error::other("injected publication failure"))
    });

    let error = destination
        .publish(&fixture.identity, &job, |staging| {
            fixture.write_output(staging, "complete", b"replacement-artifact")
        })
        .err()
        .ok_or("publication unexpectedly succeeded")?;
    assert!(
        error.to_string().contains("injected publication failure"),
        "{error}"
    );
    assert!(error.to_string().contains("phase"), "{error}");
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"previous-artifact"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn cancellation_with_progress_error_stays_fatal() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"previous-artifact")?;
    let destination = super::inspect(&fixture.output, ResultKind::Extract)?;
    let job = Job::new("refresh");
    let paused_job = job.clone();
    crate::publish::test_hooks::set_before_directory_exchange(move || {
        paused_job
            .finish(
                l2_workbench::job::Phase::Publication,
                l2_workbench::job::PhaseOutcome::Cancelled,
            )
            .map_err(io::Error::other)?;
        paused_job.request_cancel();
        Err(io::Error::other(l2_workbench::job::JobError::Cancelled))
    });

    let error = destination
        .publish(&fixture.identity, &job, |staging| {
            fixture.write_output(staging, "complete", b"replacement-artifact")
        })
        .err()
        .ok_or("cancelled publication unexpectedly succeeded")?;
    assert!(error.is::<crate::result_directory::PublicationProgressError>());
    assert_eq!(
        crate::memory_error::find_map(error.as_ref(), |cause| cause
            .downcast_ref::<l2_workbench::job::JobError>()
            .copied()),
        Some(l2_workbench::job::JobError::Cancelled),
    );
    assert_eq!(
        fs::read(fixture.output.join("artifact.bin"))?,
        b"previous-artifact"
    );
    let options = crate::arguments::RecoveryOptions {
        quiet: true,
        ..crate::arguments::RecoveryOptions::default()
    };
    assert!(
        crate::recovery_job::run(&options, "failed cancellation", |_| Err(error)).is_err(),
        "a progress failure must not become an interrupted outcome"
    );
    Ok(())
}
