use std::{error::Error, io, path::Path};

/// Publish a complete directory with no replacement, using the same checked parent as files
///
/// # Errors
/// Returns [`DirectoryPublishError::BeforePublication`] when this call did not
/// commit the destination. Returns
/// [`DirectoryPublishError::PublishedDurabilityUncertain`] when rename succeeded
/// but syncing the parent directory failed
pub fn create_directory<T>(
    path: &Path,
    write: impl FnOnce(&Path) -> Result<T, Box<dyn Error>>,
) -> Result<T, super::DirectoryPublishError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{RenameFlags, renameat_with};
        use std::{os::fd::AsRawFd, path::PathBuf};
        let (parent, name) = super::parent_and_name(path)?;
        let parent_fd = super::open_parent(parent)?;
        // The held descriptor keeps staging inside the checked parent during path changes
        let stable_parent = PathBuf::from(format!("/proc/self/fd/{}", parent_fd.as_raw_fd()));
        let staging = tempfile::Builder::new()
            .prefix(".l2solver-")
            .tempdir_in(stable_parent)?;
        let result = write(staging.path())?;
        let staging_name = staging
            .path()
            .file_name()
            .ok_or_else(|| io::Error::other("missing staging directory name"))?;
        renameat_with(
            &parent_fd,
            staging_name,
            &parent_fd,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        // Publication owns the directory now; cleanup must not follow its former temporary name
        let _former_name = staging.keep();
        super::sync_parent_directory(&parent_fd, path)
            .map_err(super::DirectoryPublishError::PublishedDurabilityUncertain)?;
        Ok(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, write);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory publication requires Linux",
        )
        .into())
    }
}
