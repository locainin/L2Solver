use super::*;
use l2_workbench::job::JobError;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;

const CHILD_ENV: &str = "L2SOLVER_RECOVERY_OUTCOME_TEST_CHILD";

#[cfg(unix)]
fn unavailable_stderr() -> io::Result<Stdio> {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};

    let (reader, writer) = UnixStream::pair()?;
    drop(reader);
    let descriptor: OwnedFd = writer.into();
    Ok(Stdio::from(descriptor))
}

fn options() -> RecoveryOptions {
    RecoveryOptions {
        progress: ProgressMode::Never,
        quiet: true,
        ..RecoveryOptions::default()
    }
}

#[test]
fn multiple_cleanup_failures_keep_the_operation_failure_first() -> Result<(), Box<dyn Error>> {
    let original = io::Error::other("operation failure");
    let result = retain_cleanup_error::<bool>(
        Err(original.into()),
        Err(io::Error::other("renderer failure").into()),
        "renderer",
    );
    let result = retain_cleanup_error(
        result,
        Err(io::Error::other("monitor failure").into()),
        "monitor",
    );
    let error = result.err().ok_or("cleanup failures were lost")?;
    let message = error.to_string();
    assert!(message.starts_with("operation failure"), "{message}");
    assert!(message.contains("renderer failure"), "{message}");
    assert!(message.contains("monitor failure"), "{message}");
    assert!(crate::memory_error::any_cause(error.as_ref(), |cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.to_string() == "operation failure")
    }));
    Ok(())
}

#[test]
fn recovery_result_distinguishes_failures_from_cancellation() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(CHILD_ENV).is_none() {
        // The signal handler has one active job per process
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "recovery_job::outcome_tests::recovery_result_distinguishes_failures_from_cancellation",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }

    let options = options();
    check_operation_failures(&options)?;
    check_cancellation_results(&options)
}

fn check_operation_failures(options: &RecoveryOptions) -> Result<(), Box<dyn Error>> {
    #[cfg(unix)]
    {
        let error = run(options, "storage failure", |job| {
            job.request_cancel();
            Err(io::Error::from_raw_os_error(libc::ENOSPC).into())
        })
        .err()
        .ok_or("storage failure was hidden by cancellation")?;
        assert_eq!(
            error
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error),
            Some(libc::ENOSPC)
        );
    }

    let error = run(options, "job invariant failure", |job| {
        job.request_cancel();
        Err(JobError::LockPoisoned.into())
    })
    .err()
    .ok_or("job invariant failure was hidden by cancellation")?;
    assert_eq!(
        error.downcast_ref::<JobError>(),
        Some(&JobError::LockPoisoned)
    );

    let error = run(options, "unrelated interrupted I/O", |job| {
        job.request_cancel();
        Err(io::Error::new(io::ErrorKind::Interrupted, "unrelated interruption").into())
    })
    .err()
    .ok_or("unrelated interrupted I/O was treated as job cancellation")?;
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::Interrupted)
    );
    Ok(())
}

fn check_cancellation_results(options: &RecoveryOptions) -> Result<(), Box<dyn Error>> {
    let outcome = run(options, "typed cancellation", |job| {
        job.request_cancel();
        job.check_cancelled()?;
        Ok(true)
    })?;
    assert_eq!(outcome, RunOutcome::Interrupted);
    assert_eq!(outcome.exit_code(), std::process::ExitCode::from(130));

    let outcome = run(options, "wrapped cancellation", |_| {
        Err(io::Error::other(JobError::Cancelled).into())
    })?;
    assert_eq!(outcome, RunOutcome::Interrupted);

    let outcome = run(options, "memory cancellation", |_| {
        Err(MemoryError::Cancelled.into())
    })?;
    assert_eq!(outcome, RunOutcome::Interrupted);

    for (complete, expected) in [
        (true, RunOutcome::Completed),
        (false, RunOutcome::Incomplete),
    ] {
        let outcome = run(options, "late cancellation", |job| {
            job.request_cancel();
            Ok(complete)
        })?;
        assert_eq!(outcome, expected);
    }

    #[cfg(target_os = "linux")]
    {
        let temporary = tempfile::tempdir()?;
        let destination = temporary.path().join("published");
        let outcome = run(options, "committed before cancellation", |job| {
            let complete = crate::publish::create_directory_with_precommit(
                &destination,
                |staging| {
                    std::fs::write(staging.join("marker"), b"committed")?;
                    Ok(true)
                },
                || {
                    job.check_cancelled()
                        .map_err(|error| Box::new(error) as Box<dyn Error>)
                },
            )?;
            job.request_cancel();
            RecoveryCache::disabled().finish(Ok(complete), job)
        })?;
        assert_eq!(outcome, RunOutcome::Completed);
        assert_eq!(std::fs::read(destination.join("marker"))?, b"committed");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn unavailable_human_diagnostics_do_not_change_cancellation_exit_status()
-> Result<(), Box<dyn Error>> {
    if std::env::var_os(CHILD_ENV).is_some() {
        let summary_options = RecoveryOptions {
            quiet: false,
            ..options()
        };
        let summary_result = run(&summary_options, "closed summary", |job| {
            job.record_cache_fallback(
                l2_workbench::job::CacheStage::CaseRecovery,
                l2_workbench::job::CacheFallbackKind::LookupFailed,
                format_args!("test cache failure"),
            )?;
            Ok(true)
        });
        if !matches!(summary_result, Ok(RunOutcome::Completed)) {
            std::process::exit(1);
        }
        let outcome = run(&options(), "closed diagnostics", |job| {
            job.request_cancel();
            job.check_cancelled()?;
            Ok(true)
        });
        std::process::exit(if matches!(outcome, Ok(RunOutcome::Interrupted)) {
            130
        } else {
            1
        });
    }

    let status = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery_job::outcome_tests::unavailable_human_diagnostics_do_not_change_cancellation_exit_status",
        ])
        .env(CHILD_ENV, "1")
        .stderr(unavailable_stderr()?)
        .status()?;
    assert_eq!(status.code(), Some(130));
    Ok(())
}

#[cfg(unix)]
#[test]
fn renderer_failure_is_preserved_after_an_operation_failure() -> Result<(), Box<dyn Error>> {
    if std::env::var_os(CHILD_ENV).is_some() {
        let options = RecoveryOptions {
            progress: ProgressMode::Always,
            quiet: false,
            ..RecoveryOptions::default()
        };
        let error = run(&options, "renderer failure", |job| {
            job.request_cancel();
            Err(io::Error::other("original operation failure").into())
        })
        .err()
        .ok_or("operation and renderer failures were hidden")?;
        let message = error.to_string();
        assert!(message.contains("original operation failure"), "{message}");
        assert!(
            message.contains("could not write progress output"),
            "{message}"
        );
        assert!(crate::memory_error::any_cause(error.as_ref(), |cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.to_string() == "original operation failure")
        }));

        let error = run(&options, "renderer failure after cancellation", |job| {
            job.request_cancel();
            job.check_cancelled()?;
            Ok(true)
        })
        .err()
        .ok_or("renderer failure after cancellation was hidden")?;
        assert!(
            error
                .to_string()
                .contains("could not write progress output")
        );
        assert!(error.to_string().contains("job cancellation was requested"));

        let error = run(
            &options,
            "renderer failure after successful operation",
            |job| {
                job.request_cancel();
                Ok(true)
            },
        )
        .err()
        .ok_or("renderer failure after success was hidden")?;
        assert!(
            error
                .to_string()
                .contains("could not write progress output")
        );
        return Ok(());
    }

    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery_job::outcome_tests::renderer_failure_is_preserved_after_an_operation_failure",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stderr(unavailable_stderr()?)
        .output()?;
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}
