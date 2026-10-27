//! Check that write errors cannot replace a completed directory

use super::publish;
use std::{
    error::Error,
    fs, io,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn Error>>;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn old_output(destination: &Path) -> TestResult {
    publish::create_directory(destination, |staging| {
        fs::write(staging.join("payload"), b"previous output")?;
        Ok(())
    })?;
    Ok(())
}

fn assert_before_publication_errno(
    result: Result<(), publish::DirectoryPublishError>,
    expected: i32,
) -> TestResult {
    let Err(publish::DirectoryPublishError::BeforePublication(error)) = result else {
        return Err("failure did not retain the pre-publication status".into());
    };
    // Tempfile may preserve only the error kind after adding the staged path
    let mut cause: Option<&(dyn Error + 'static)> = Some(error.as_ref());
    let mut actual = None;
    let mut kind = None;
    while let Some(current) = cause {
        if let Some(io_error) = current.downcast_ref::<io::Error>() {
            kind = Some(io_error.kind());
            if let Some(errno) = io_error.raw_os_error() {
                actual = Some(errno);
                break;
            }
        }
        cause = current.source();
    }
    assert_eq!(kind, Some(io::Error::from_raw_os_error(expected).kind()));
    if let Some(errno) = actual {
        assert_eq!(errno, expected, "unexpected filesystem error: {error}");
    }
    Ok(())
}

#[test]
fn injected_staged_write_errors_preserve_the_previous_directory() -> TestResult {
    for errno in [libc::ENOSPC, libc::EDQUOT, libc::EROFS, libc::EACCES] {
        let root = tempfile::tempdir()?;
        let destination = root.path().join("bundle");
        old_output(&destination)?;
        let prepared = publish::prepare_directory_replacement(&destination)?;

        let result = publish::replace_directory_with_precommit(
            &prepared,
            |staging| {
                fs::write(staging.join("payload"), b"partial new output")?;
                Err::<(), Box<dyn Error>>(io::Error::from_raw_os_error(errno).into())
            },
            || Ok(()),
        );

        assert_before_publication_errno(result, errno)?;
        assert_eq!(fs::read(destination.join("payload"))?, b"previous output");
        assert_eq!(fs::read_dir(root.path())?.count(), 1);
    }
    Ok(())
}

#[test]
fn unwritable_parent_preserves_the_existing_directory() -> TestResult {
    // Root can bypass directory permissions, so only check unprivileged execution
    let status = fs::read_to_string("/proc/self/status")?;
    let uid = status.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .nth(1)?
            .parse::<u32>()
            .ok()
    });
    if uid == Some(0) {
        eprintln!("skipping permission test for effective uid 0");
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    old_output(&destination)?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o500))?;
    let probe = fs::write(root.path().join("permission-probe"), b"probe");
    let result = publish::replace_directory_with_precommit(&prepared, |_| Ok(()), || Ok(()));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;

    let Err(probe) = probe else {
        return Err("unwritable parent accepted the permission probe".into());
    };
    assert_eq!(probe.raw_os_error(), Some(libc::EACCES));
    assert_before_publication_errno(result, libc::EACCES)?;
    assert_eq!(fs::read(destination.join("payload"))?, b"previous output");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn real_full_filesystem_preserves_the_existing_directory() -> TestResult {
    let Some(base) = std::env::var_os("L2_TEST_ENOSPC_ROOT") else {
        eprintln!("real ENOSPC test needs an isolated small filesystem");
        return Ok(());
    };
    let root = tempfile::tempdir_in(base)?;
    let destination = root.path().join("bundle");
    old_output(&destination)?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let result = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            // The namespace fixture limits this filesystem to one MiB
            fs::write(staging.join("payload"), vec![0_u8; 2 * 1024 * 1024])?;
            Ok(())
        },
        || Ok(()),
    );

    assert_before_publication_errno(result, libc::ENOSPC)?;
    assert_eq!(fs::read(destination.join("payload"))?, b"previous output");
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn real_read_only_filesystem_preserves_the_existing_directory() -> TestResult {
    let Some(base) = std::env::var_os("L2_TEST_EROFS_ROOT") else {
        eprintln!("real EROFS test needs an isolated read-only filesystem");
        return Ok(());
    };
    let destination = Path::new(&base).join("bundle");
    let prepared = publish::prepare_directory_replacement(&destination)?;
    let Err(probe) = fs::write(Path::new(&base).join("readonly-probe"), b"probe") else {
        return Err("read-only filesystem accepted the write probe".into());
    };
    let result = publish::replace_directory_with_precommit(&prepared, |_| Ok(()), || Ok(()));

    assert_eq!(probe.raw_os_error(), Some(libc::EROFS));
    assert_before_publication_errno(result, libc::EROFS)?;
    assert_eq!(fs::read(destination.join("payload"))?, b"previous output");
    assert_eq!(fs::read_dir(Path::new(&base))?.count(), 1);
    Ok(())
}

#[test]
fn directory_crash_child() -> TestResult {
    let Some(base) = std::env::var_os("L2_TEST_DIRECTORY_CRASH_ROOT") else {
        return Ok(());
    };
    let base = Path::new(&base);
    let prepared = publish::prepare_directory_replacement(&base.join("bundle"))?;
    publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            fs::write(staging.join("payload"), b"staged output")?;
            Ok(())
        },
        || {
            fs::write(base.join("ready"), b"ready")?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            Err(io::Error::other("parent did not interrupt publication").into())
        },
    )?;
    Err("publication unexpectedly completed".into())
}

#[test]
fn killing_the_publisher_before_commit_preserves_the_previous_directory() -> TestResult {
    let root = tempfile::tempdir()?;
    let destination = root.path().join("bundle");
    old_output(&destination)?;
    let mut child = OwnedChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "faults::directory_crash_child", "--nocapture"])
            .env("L2_TEST_DIRECTORY_CRASH_ROOT", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    while !root.path().join("ready").exists() && Instant::now() < deadline {
        if child.0.try_wait()?.is_some() {
            return Err("publisher exited before reaching its precommit pause".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    let ready = root.path().join("ready").exists();
    child.0.kill()?;
    let status = child.0.wait()?;
    assert!(ready, "publisher did not reach its precommit pause");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(fs::read(destination.join("payload"))?, b"previous output");

    // A killed process cannot remove its staged directory, so it stays recoverable
    let staged: Vec<_> = fs::read_dir(root.path())?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".l2solver-")
        })
        .collect();
    let [staged] = staged.as_slice() else {
        return Err(format!(
            "expected one retained staging directory, got {}",
            staged.len()
        )
        .into());
    };
    assert_eq!(fs::read(staged.path().join("payload"))?, b"staged output");
    Ok(())
}
