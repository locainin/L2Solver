//! Competing refreshes must not replace a result that already committed

use super::{
    OwnedChild,
    publish::{self, PreparedDirectoryReplacement, test_hooks},
};
use std::{
    error::Error,
    fs, io,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn Error>>;

fn write_output(staging: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    fs::write(staging.join("payload"), name)?;
    fs::write(staging.join("manifest"), name)?;
    Ok(())
}

fn refresh(prepared: &PreparedDirectoryReplacement, name: &str) -> Result<(), String> {
    publish::replace_directory_with_precommit(
        prepared,
        |staging| write_output(staging, name),
        || Ok(()),
    )
    .map_err(|error| error.to_string())
}

#[test]
fn concurrent_refresh_preserves_the_successful_winner() -> TestResult {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("result");
    publish::create_directory(&destination, |staging| write_output(staging, "original"))?;
    let delayed = publish::prepare_directory_replacement(&destination)?;
    let competing = publish::prepare_directory_replacement(&destination)?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    // Pause after the old destination was checked and the new tree was synced
    let delayed_worker = thread::spawn(move || {
        test_hooks::set_before_directory_exchange(move || {
            ready_tx.send(()).map_err(io::Error::other)?;
            release_rx
                .recv_timeout(Duration::from_secs(15))
                .map_err(io::Error::other)?;
            Ok(())
        });
        refresh(&delayed, "delayed")
    });
    ready_rx.recv_timeout(Duration::from_secs(10))?;

    // A nonblocking contender must finish while the first commit remains paused
    let (result_tx, result_rx) = mpsc::channel();
    let competing_worker = thread::spawn(move || {
        let _ = result_tx.send(refresh(&competing, "competing"));
    });
    let competing_result = result_rx.recv_timeout(Duration::from_secs(10))?;
    release_tx.send(())?;
    let delayed_result = delayed_worker
        .join()
        .map_err(|_| "delayed publisher panicked")?;
    competing_worker
        .join()
        .map_err(|_| "competing publisher panicked")?;

    let winner = match (&competing_result, &delayed_result) {
        (Ok(()), Err(_)) => "competing",
        (Err(_), Ok(())) => "delayed",
        _ => {
            return Err(format!(
                "expected one successful refresh: competing={competing_result:?}, delayed={delayed_result:?}"
            )
            .into());
        }
    };
    assert_eq!(fs::read(destination.join("payload"))?, winner.as_bytes());
    assert_eq!(fs::read(destination.join("manifest"))?, winner.as_bytes());
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn parent_lock_contention_fails_closed_and_releases_for_retry() -> TestResult {
    use rustix::fs::{FlockOperation, flock};

    let root = tempfile::tempdir()?;
    let first = root.path().join("first");
    let second = root.path().join("second");
    for destination in [&first, &second] {
        publish::create_directory(destination, |staging| write_output(staging, "original"))?;
    }
    let first_prepared = publish::prepare_directory_replacement(&first)?;
    let second_prepared = publish::prepare_directory_replacement(&second)?;
    let held_parent = fs::File::open(root.path())?;
    flock(&held_parent, FlockOperation::NonBlockingLockExclusive)?;

    // The held parent protects all replacement commits in this directory
    for (prepared, destination) in [(&first_prepared, &first), (&second_prepared, &second)] {
        let result = publish::replace_directory_with_precommit(
            prepared,
            |staging| write_output(staging, "replacement"),
            || Ok(()),
        );
        let Err(publish::DirectoryPublishError::BeforePublication(error)) = result else {
            return Err("contended lock did not fail before publication".into());
        };
        assert!(
            error.to_string().contains("cannot lock output parent"),
            "{error}"
        );
        let error = error
            .downcast_ref::<io::Error>()
            .ok_or("lock failure did not retain its I/O error")?;
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(destination.join("payload"))?, b"original");
    }
    assert_eq!(fs::read_dir(root.path())?.count(), 2);
    drop(held_parent);

    // Each refresh can retry after the lock owner releases the parent
    refresh(&first_prepared, "first-winner").map_err(io::Error::other)?;
    refresh(&second_prepared, "second-winner").map_err(io::Error::other)?;
    assert_eq!(fs::read(first.join("payload"))?, b"first-winner");
    assert_eq!(fs::read(second.join("payload"))?, b"second-winner");
    Ok(())
}

#[test]
fn paused_refresh_child() -> TestResult {
    let Some(root) = std::env::var_os("L2_TEST_REFRESH_CRASH_ROOT") else {
        return Ok(());
    };
    let root = std::path::PathBuf::from(root);
    let prepared = publish::prepare_directory_replacement(&root.join("result"))?;
    test_hooks::set_before_directory_exchange(move || {
        fs::write(root.join("ready"), b"ready")?;
        // The parent kills this process while the commit lock is still held
        thread::sleep(Duration::from_secs(20));
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "parent did not stop child",
        ))
    });
    refresh(&prepared, "interrupted").map_err(io::Error::other)?;
    Err("paused child unexpectedly published".into())
}

#[test]
fn process_contention_and_killed_lock_owner_preserve_the_previous_result() -> TestResult {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("result");
    publish::create_directory(&destination, |staging| write_output(staging, "original"))?;
    let mut child = OwnedChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "concurrent_refresh::paused_refresh_child"])
            .env("L2_TEST_REFRESH_CRASH_ROOT", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.path().join("ready").exists() && Instant::now() < deadline {
        if child.0.try_wait()?.is_some() {
            return Err("refresh child exited before the commit pause".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !root.path().join("ready").exists() {
        return Err("refresh child did not reach the commit pause".into());
    }
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let error = refresh(&prepared, "contender")
        .err()
        .ok_or("another process published while the first held the parent lock")?;
    assert!(error.contains("cannot lock output parent"), "{error}");
    assert_eq!(fs::read(destination.join("payload"))?, b"original");
    assert_eq!(fs::read(destination.join("manifest"))?, b"original");

    // Killing the lock owner releases the kernel lock without removing the old result
    child.0.kill()?;
    assert_eq!(child.0.wait()?.signal(), Some(libc::SIGKILL));
    assert_eq!(fs::read(destination.join("payload"))?, b"original");
    refresh(&prepared, "after-kill").map_err(io::Error::other)?;
    assert_eq!(fs::read(destination.join("payload"))?, b"after-kill");
    assert_eq!(fs::read(destination.join("manifest"))?, b"after-kill");
    Ok(())
}
