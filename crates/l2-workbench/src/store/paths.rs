use super::{Result, invalid};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

/// Source reads use a held directory so path renames cannot redirect packet bytes
pub struct Directory {
    file: File,
    original: PathBuf,
}

impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        let file = File::from(rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        #[cfg(not(unix))]
        let file = File::open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(invalid("index directory must be a real directory"));
        }
        Ok(Self {
            file,
            original: std::fs::canonicalize(path)?,
        })
    }

    pub fn path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.original.clone()
        }
    }

    pub fn check_location(&self) -> Result<()> {
        let current = std::fs::symlink_metadata(&self.original)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = self.file.metadata()?;
            if current.dev() != held.dev() || current.ino() != held.ino() {
                return Err(invalid(
                    "index directory moved; reopen it before importing another source",
                ));
            }
        }
        if !current.is_dir() {
            return Err(invalid("index directory changed"));
        }
        Ok(())
    }

    pub fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

pub fn regular(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let file = File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    #[cfg(not(unix))]
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("index evidence must be a regular file"));
    }
    Ok(file)
}
