use std::{
    cell::{Cell, RefCell},
    io,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

type BeforeDirectoryExchangeHook = Box<dyn FnOnce() -> io::Result<()>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestFault {
    UnsupportedFilesystem,
    SecurePublication,
    FileSync,
    Link,
    DirectorySync,
    UnsupportedDirectoryExchange,
}

// Only the publication harness arms faults; every caller uses the same per-thread slot
thread_local! {
    pub(crate) static TEST_FAULT: Cell<Option<TestFault>> = const { Cell::new(None) };
    static BEFORE_DIRECTORY_EXCHANGE: RefCell<Option<BeforeDirectoryExchangeHook>> =
        const { RefCell::new(None) };
}

pub fn take_fault(fault: TestFault) -> bool {
    TEST_FAULT.with(|slot| {
        if slot.get() == Some(fault) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

pub fn set_before_directory_exchange(hook: impl FnOnce() -> io::Result<()> + 'static) {
    BEFORE_DIRECTORY_EXCHANGE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

pub fn before_directory_exchange() -> io::Result<()> {
    let hook = BEFORE_DIRECTORY_EXCHANGE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook()
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PauseStage {
    BeforeLink,
    AfterLink,
}

pub fn pause_before_link() -> io::Result<()> {
    pause_at(PauseStage::BeforeLink)
}

pub fn pause_after_link() -> io::Result<()> {
    pause_at(PauseStage::AfterLink)
}

fn pause_at(stage: PauseStage) -> io::Result<()> {
    let expected = match stage {
        PauseStage::BeforeLink => "before-link",
        PauseStage::AfterLink => "after-link",
    };
    if std::env::var("L2SOLVER_PUBLISH_PAUSE_STAGE")
        .ok()
        .as_deref()
        != Some(expected)
    {
        return Ok(());
    }
    let ready = PathBuf::from(std::env::var_os("L2SOLVER_PUBLISH_READY").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing publication-ready marker",
        )
    })?);
    let release = PathBuf::from(std::env::var_os("L2SOLVER_PUBLISH_RELEASE").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing publication-release marker",
        )
    })?);
    std::fs::write(ready, b"ready")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !release.exists() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for publication release",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io, os::fd::AsRawFd, path::Path};

    use rustix::fs::{self, CWD, Mode, OFlags};

    #[test]
    fn proc_fd_validation_ordinary_directory() -> Result<(), Box<dyn std::error::Error>> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        let directory = fs::openat(CWD, Path::new("."), flags, Mode::empty())?;

        assert!(super::super::validate_proc_fd_filesystem(&directory).is_err());
        Ok(())
    }

    #[test]
    fn proc_fd_exact_held_file() -> Result<(), Box<dyn std::error::Error>> {
        let proc_fd = super::super::open_proc_fd_directory()?;
        let expected = std::fs::File::open(std::env::current_exe()?)?;
        let other = std::fs::File::open(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))?;

        assert!(
            super::super::verify_proc_fd_entry(
                &proc_fd,
                &expected,
                &expected.as_raw_fd().to_string(),
            )
            .is_ok()
        );
        assert!(super::super::verify_proc_fd_entry(
            &proc_fd,
            &expected,
            &other.as_raw_fd().to_string(),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn unsupported_tmpfile_errnos_are_classified() {
        for error_number in [
            libc::EOPNOTSUPP,
            libc::ENOSYS,
            libc::EISDIR,
            libc::ENOENT,
            libc::EINVAL,
        ] {
            assert!(super::super::is_unsupported_tmpfile(
                &io::Error::from_raw_os_error(error_number)
            ));
        }
        assert!(super::super::is_unsupported_tmpfile(&io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported",
        )));
        assert!(!super::super::is_unsupported_tmpfile(
            &io::Error::from_raw_os_error(libc::EIO)
        ));
    }

    #[test]
    fn proc_fd_without_other_io() {
        for error_number in [
            libc::EACCES,
            libc::EPERM,
            libc::ENOENT,
            libc::ENOTDIR,
            libc::ELOOP,
            libc::ENOSYS,
            libc::EOPNOTSUPP,
            libc::EINVAL,
        ] {
            assert!(super::super::is_unavailable_proc_fd_error(
                &io::Error::from_raw_os_error(error_number)
            ));
        }
        assert!(super::super::is_unavailable_proc_fd_error(&io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported",
        )));
        assert!(!super::super::is_unavailable_proc_fd_error(
            &io::Error::from_raw_os_error(libc::EIO)
        ));
        assert!(!super::super::is_unavailable_proc_fd_error(
            &io::Error::from_raw_os_error(libc::EEXIST)
        ));
    }

    #[test]
    fn sync_errnos_without_io_failures() {
        for error_number in [libc::EINVAL, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert!(super::super::is_unsupported_sync_error(
                &io::Error::from_raw_os_error(error_number)
            ));
        }
        assert!(super::super::is_unsupported_sync_error(&io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported",
        )));
        for error_number in [libc::EIO, libc::ENOSPC] {
            assert!(!super::super::is_unsupported_sync_error(
                &io::Error::from_raw_os_error(error_number)
            ));
        }
    }
}
