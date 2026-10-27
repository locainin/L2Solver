use std::{
    fs::{self, File, Metadata},
    io,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use super::{
    error::{CacheError, Result},
    manifest::{MAX_TREE_DEPTH, MAX_TREE_ITEMS},
};

const INTERNAL_LOCK_WAIT: Duration = Duration::from_secs(5);
const INTERNAL_LOCK_RETRY: Duration = Duration::from_millis(10);

/// A directory held open so later path operations can check that its name still points to it
pub(super) struct HeldDirectory {
    file: File,
    path: PathBuf,
}

/// An OS advisory lock whose file descriptor stays open for the full lease
pub(super) struct LockGuard {
    file: File,
}

impl HeldDirectory {
    pub(super) fn sync(&self) -> Result<()> {
        self.check_location()?;
        self.file.sync_all()?;
        self.check_location()
    }

    pub(super) fn sync_tree(&self) -> Result<()> {
        let mut items = 0;
        self.sync_tree_at(0, &mut items)
    }

    fn sync_tree_at(&self, depth: usize, items: &mut usize) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(CacheError::InvalidInput(
                "cache entry directory tree is too deep",
            ));
        }
        self.check_location()?;
        for item in fs::read_dir(self.path())? {
            let item = item?;
            *items = items.checked_add(1).ok_or(CacheError::SizeOverflow)?;
            if *items > MAX_TREE_ITEMS {
                return Err(CacheError::InvalidInput(
                    "cache entry contains too many files",
                ));
            }
            let name = item.file_name();
            let name = name
                .to_str()
                .ok_or(CacheError::InvalidInput("cache entry path is not UTF-8"))?;
            let metadata = fs::symlink_metadata(item.path())?;
            if metadata.file_type().is_symlink() {
                return Err(CacheError::UnsafePath("cache entry contains a symlink"));
            }
            if metadata.is_dir() {
                self.open_child_inner(name, false)?
                    .sync_tree_at(depth + 1, items)?;
            } else if metadata.is_file() {
                self.open_file(name)?.sync_all()?;
            } else {
                return Err(CacheError::UnsafePath(
                    "cache entry contains a non-regular file",
                ));
            }
        }
        self.sync()
    }

    pub(super) fn create_private_child(&self, prefix: &str) -> Result<(String, Self)> {
        self.check_location()?;
        let temporary = tempfile::Builder::new()
            .prefix(prefix)
            .make_in(self.path(), |path| {
                let name = path
                    .file_name()
                    .ok_or_else(|| io::Error::other("missing temporary name"))?;
                #[cfg(unix)]
                rustix::fs::mkdirat(&self.file, name, rustix::fs::Mode::RWXU)
                    .map_err(io::Error::from)?;
                #[cfg(not(unix))]
                fs::create_dir(path)?;
                let name = name
                    .to_str()
                    .ok_or_else(|| io::Error::other("temporary name is not UTF-8"))?;
                self.open_child(name).map_err(io::Error::other)
            })?;
        let (directory, path) = temporary.into_parts();
        let path = path.keep().map_err(|error| error.error)?;
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(CacheError::InvalidInput(
                "temporary directory name is invalid",
            ))?
            .to_owned();
        self.check_location()?;
        Ok((name, directory))
    }

    pub(super) fn create_new_file(&self, name: &str) -> Result<File> {
        self.check_location()?;
        validate_component(name)?;
        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(io::Error::from)?,
        );
        #[cfg(not(unix))]
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.path.join(name))?;
        self.check_location()?;
        Ok(file)
    }

    pub(super) fn open_file(&self, name: &str) -> Result<File> {
        self.check_location()?;
        validate_component(name)?;
        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        #[cfg(not(unix))]
        let file = File::open(self.path.join(name))?;
        let held = file.metadata()?;
        let named = fs::symlink_metadata(self.path.join(name))?;
        if !held.is_file()
            || !named.is_file()
            || named.file_type().is_symlink()
            || !same_file(&held, &named)
        {
            return Err(CacheError::UnsafePath(
                "checkpoint component is not a stable regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if held.nlink() != 1 {
                return Err(CacheError::UnsafePath(
                    "checkpoint component has an external link",
                ));
            }
        }
        self.check_location()?;
        Ok(file)
    }

    pub(super) fn rename_child_to(&self, name: &str, target: &Self) -> Result<()> {
        self.check_location()?;
        target.check_location()?;
        validate_component(name)?;
        #[cfg(target_os = "linux")]
        rustix::fs::renameat_with(
            &self.file,
            name,
            &target.file,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        #[cfg(not(target_os = "linux"))]
        return Err(CacheError::InvalidInput(
            "execution checkpoints require Linux no-replace rename",
        ));
        self.check_location()?;
        target.check_location()
    }

    pub(super) fn open_root(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(CacheError::UnsafePath(
                    "cache root must be a real directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::create_dir_all(path)?;
        let directory = Self::open(path)?;
        directory.check_location()?;
        Ok(directory)
    }

    fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        let file = File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| open_error(error, "cache root must not be a symlink"))?,
        );
        #[cfg(not(unix))]
        let file = {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CacheError::UnsafePath(
                    "cache root must be a real directory",
                ));
            }
            File::open(path)?
        };

        let canonical = fs::canonicalize(path)?;
        let held_metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(&canonical)?;
        if !path_metadata.is_dir() || !same_file(&held_metadata, &path_metadata) {
            return Err(CacheError::UnsafePath("cache root changed while opening"));
        }
        set_private_directory_mode(&file)?;
        Ok(Self {
            file,
            path: canonical,
        })
    }

    pub(super) fn open_child_or_create(&self, name: &str) -> Result<Self> {
        self.check_location()?;
        validate_component(name)?;

        #[cfg(unix)]
        match rustix::fs::mkdirat(&self.file, name, rustix::fs::Mode::RWXU) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        #[cfg(not(unix))]
        match fs::create_dir(self.path.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }

        self.open_child(name)
    }

    pub(super) fn open_child(&self, name: &str) -> Result<Self> {
        self.open_child_inner(name, true)
    }

    fn open_child_inner(&self, name: &str, restrict_mode: bool) -> Result<Self> {
        self.check_location()?;
        validate_component(name)?;
        let path = self.path.join(name);

        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| open_error(error, "cache child must not be a symlink"))?,
        );
        #[cfg(not(unix))]
        let file = {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(CacheError::UnsafePath("cache child is a symlink"));
            }
            File::open(&path)?
        };

        let held_metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(&path)?;
        if !path_metadata.is_dir() || !same_file(&held_metadata, &path_metadata) {
            return Err(CacheError::UnsafePath(
                "cache directory changed while opening",
            ));
        }
        if restrict_mode {
            set_private_directory_mode(&file)?;
        }

        Ok(Self { file, path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn check_location(&self) -> Result<()> {
        let current = fs::symlink_metadata(&self.path)
            .map_err(|_| CacheError::UnsafePath("cache directory moved or was replaced"))?;
        let held = self.file.metadata()?;
        if !current.is_dir() || !same_file(&held, &current) {
            return Err(CacheError::UnsafePath(
                "cache directory moved or was replaced",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_regular_file(&self, name: &str) -> Result<PathBuf> {
        self.check_location()?;
        validate_component(name)?;
        let path = self.path.join(name);

        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|error| open_error(error, "cache database must not be a symlink"))?,
        );
        #[cfg(not(unix))]
        let file = {
            let metadata = fs::symlink_metadata(&path);
            match metadata {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(CacheError::UnsafePath("cache database is a symlink"));
                }
                Ok(metadata) if !metadata.is_file() => {
                    return Err(CacheError::UnsafePath("cache database is not a file"));
                }
                Ok(_) => File::options().read(true).write(true).open(&path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)?,
                Err(error) => return Err(error.into()),
            }
        };

        let held_metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(&path)?;
        if !path_metadata.is_file()
            || !same_file(&held_metadata, &path_metadata)
            || path_metadata.file_type().is_symlink()
        {
            return Err(CacheError::UnsafePath(
                "cache database changed while opening",
            ));
        }
        Ok(path)
    }

    pub(super) fn lock(&self, file_name: &str, exclusive: bool) -> Result<LockGuard> {
        self.check_location()?;
        validate_component(file_name)?;

        #[cfg(unix)]
        let file = File::from(
            rustix::fs::openat(
                &self.file,
                file_name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|error| open_error(error, "cache lock must not be a symlink"))?,
        );
        #[cfg(not(unix))]
        let file = {
            let path = self.path.join(file_name);
            let metadata = fs::symlink_metadata(&path);
            match metadata {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(CacheError::UnsafePath("cache lock is a symlink"));
                }
                Ok(metadata) if !metadata.is_file() => {
                    return Err(CacheError::UnsafePath("cache lock is not a file"));
                }
                Ok(_) => File::options().read(true).write(true).open(path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)?,
                Err(error) => return Err(error.into()),
            }
        };

        let held_metadata = file.metadata()?;
        let path_metadata = fs::symlink_metadata(self.path.join(file_name))?;
        if !path_metadata.is_file()
            || path_metadata.file_type().is_symlink()
            || !same_file(&held_metadata, &path_metadata)
        {
            return Err(CacheError::UnsafePath("cache lock changed while opening"));
        }
        set_private_file_mode(&file)?;
        acquire_lock(&file, exclusive)?;
        Ok(LockGuard { file })
    }

    pub(super) fn lock_with_retry(&self, file_name: &str, exclusive: bool) -> Result<LockGuard> {
        let deadline = Instant::now() + INTERNAL_LOCK_WAIT;
        loop {
            match self.lock(file_name, exclusive) {
                Ok(lock) => return Ok(lock),
                Err(CacheError::LockBusy) if Instant::now() < deadline => {
                    thread::sleep(INTERNAL_LOCK_RETRY);
                }
                Err(CacheError::LockBusy) => return Err(CacheError::CacheBusy),
                Err(error) => return Err(error),
            }
        }
    }
}

impl LockGuard {
    pub(super) fn downgrade(&self) -> Result<()> {
        set_lock(&self.file, LockMode::Shared)
    }
}

fn validate_component(value: &str) -> Result<()> {
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\']) {
        return Err(CacheError::InvalidInput("cache path component is invalid"));
    }
    Ok(())
}

fn same_file(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev() && first.ino() == second.ino()
    }
    #[cfg(not(unix))]
    {
        first.file_type() == second.file_type() && first.len() == second.len()
    }
}

fn open_error(error: rustix::io::Errno, symlink_message: &'static str) -> CacheError {
    if error == rustix::io::Errno::LOOP {
        CacheError::UnsafePath(symlink_message)
    } else {
        io::Error::from(error).into()
    }
}

#[cfg(unix)]
fn set_private_directory_mode(file: &File) -> Result<()> {
    rustix::fs::fchmod(file, rustix::fs::Mode::RWXU).map_err(io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_mode(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(file: &File) -> Result<()> {
    rustix::fs::fchmod(file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
        .map_err(io::Error::from)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_mode(_file: &File) -> Result<()> {
    Ok(())
}

#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

fn acquire_lock(file: &File, exclusive: bool) -> Result<()> {
    let mode = if exclusive {
        LockMode::Exclusive
    } else {
        LockMode::Shared
    };
    set_nonblocking_lock(file, mode)
}

#[cfg(not(any(
    target_os = "espidf",
    target_os = "horizon",
    target_os = "solaris",
    target_os = "vita",
    target_os = "wasi"
)))]
fn set_nonblocking_lock(file: &File, mode: LockMode) -> Result<()> {
    let operation = match mode {
        LockMode::Shared => rustix::fs::FlockOperation::NonBlockingLockShared,
        LockMode::Exclusive => rustix::fs::FlockOperation::NonBlockingLockExclusive,
    };
    match rustix::fs::flock(file, operation) {
        Ok(()) => Ok(()),
        Err(error)
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN =>
        {
            Err(CacheError::LockBusy)
        }
        Err(error) => Err(io::Error::from(error).into()),
    }
}

#[cfg(any(
    target_os = "espidf",
    target_os = "horizon",
    target_os = "solaris",
    target_os = "vita",
    target_os = "wasi"
))]
fn set_nonblocking_lock(_file: &File, _mode: LockMode) -> Result<()> {
    Err(CacheError::InvalidInput(
        "OS advisory file locks are unavailable",
    ))
}

fn set_lock(file: &File, mode: LockMode) -> Result<()> {
    #[cfg(not(any(
        target_os = "espidf",
        target_os = "horizon",
        target_os = "solaris",
        target_os = "vita",
        target_os = "wasi"
    )))]
    {
        let operation = match mode {
            LockMode::Shared => rustix::fs::FlockOperation::LockShared,
            LockMode::Exclusive => rustix::fs::FlockOperation::LockExclusive,
        };
        rustix::fs::flock(file, operation).map_err(io::Error::from)?;
        Ok(())
    }
    #[cfg(any(
        target_os = "espidf",
        target_os = "horizon",
        target_os = "solaris",
        target_os = "vita",
        target_os = "wasi"
    ))]
    {
        let _ = (file, mode);
        Err(CacheError::InvalidInput(
            "OS advisory file locks are unavailable",
        ))
    }
}
